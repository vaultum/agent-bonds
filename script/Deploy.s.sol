// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AgentBondManager} from "../src/AgentBondManager.sol";
import {ReputationScorer} from "../src/ReputationScorer.sol";

/// @title Deploy
/// @author Vaultum
/// @notice Deploys ReputationScorer and AgentBondManager behind ERC-1967 proxies.
contract Deploy is Script {
    uint256 private constant MIN_DISPUTE_PERIOD = 1 hours;
    bytes32 private constant ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    address private constant DETERMINISTIC_DEPLOYMENT_PROXY =
        0x4e59b44847b379578588920cA78FbF26c0B4956C;

    bytes32 private constant BASE_SCORER_IMPL_SALT = keccak256("agent-bonds.scorer.impl");
    bytes32 private constant BASE_SCORER_PROXY_SALT = keccak256("agent-bonds.scorer.proxy");
    bytes32 private constant BASE_MANAGER_IMPL_SALT = keccak256("agent-bonds.manager.impl");
    bytes32 private constant BASE_MANAGER_PROXY_SALT = keccak256("agent-bonds.manager.proxy");

    struct DeployConfig {
        address deployer;
        address ownerAddress;
        address identityRegistry;
        address validationRegistry;
        address settlementToken;
        uint256 scorerPriorValue;
        uint256 scorerSlashMultiplierBps;
        uint256 disputePeriod;
        uint8 minPassingScore;
        uint256 slashBps;
        uint8 validationFinalityPolicy;
        uint8 statusLookupFailurePolicy;
    }

    struct Deployment {
        address scorerImpl;
        address scorerProxy;
        address managerImpl;
        address managerProxy;
    }

    function run() external {
        _requireExpectedChainId();
        DeployConfig memory config = _loadConfig();
        _validateConfig(config);
        bytes32 saltSecret = _loadSaltSecret();

        console2.log("===========================================");
        console2.log("  Agent Bonds Deployment");
        console2.log("===========================================");
        _logConfig(config);
        _logSaltInfo();

        string memory outDir = string.concat(vm.projectRoot(), "/deployments");
        string memory outputPath = _deploymentArtifactsPath();
        vm.createDir(outDir, true);

        bytes32 scorerImplSalt = _deriveSalt(BASE_SCORER_IMPL_SALT, saltSecret);
        bytes32 scorerProxySalt = _deriveSalt(BASE_SCORER_PROXY_SALT, saltSecret);
        bytes32 managerImplSalt = _deriveSalt(BASE_MANAGER_IMPL_SALT, saltSecret);
        bytes32 managerProxySalt = _deriveSalt(BASE_MANAGER_PROXY_SALT, saltSecret);

        address predictedScorerImpl = _predictCreate2Address(type(ReputationScorer).creationCode, scorerImplSalt);
        address predictedScorerProxy =
            _predictCreate2Address(_scorerProxyCreationCode(predictedScorerImpl), scorerProxySalt);
        address predictedManagerImpl = _predictCreate2Address(type(AgentBondManager).creationCode, managerImplSalt);
        address predictedManagerProxy =
            _predictCreate2Address(_managerProxyCreationCode(predictedManagerImpl), managerProxySalt);

        _assertExistingArtifactCompatibility(outputPath, predictedScorerProxy, predictedManagerProxy);

        vm.startBroadcast(config.deployer);

        Deployment memory d;

        d.scorerImpl = _deployDeterministic(
            type(ReputationScorer).creationCode,
            scorerImplSalt,
            bytes32(0),
            "ReputationScorer impl"
        );
        _assertScorerImplementation(d.scorerImpl);
        console2.log("ReputationScorer impl:", d.scorerImpl);

        d.scorerProxy = _deployDeterministic(
            _scorerProxyCreationCode(d.scorerImpl),
            scorerProxySalt,
            keccak256(type(ERC1967Proxy).runtimeCode),
            "ReputationScorer proxy"
        );
        _assertProxyImplementation(d.scorerProxy, d.scorerImpl, "ReputationScorer proxy implementation mismatch");
        console2.log("ReputationScorer proxy:", d.scorerProxy);

        d.managerImpl = _deployDeterministic(
            type(AgentBondManager).creationCode,
            managerImplSalt,
            bytes32(0),
            "AgentBondManager impl"
        );
        _assertManagerImplementation(d.managerImpl);
        console2.log("AgentBondManager impl:", d.managerImpl);

        d.managerProxy = _deployDeterministic(
            _managerProxyCreationCode(d.managerImpl),
            managerProxySalt,
            keccak256(type(ERC1967Proxy).runtimeCode),
            "AgentBondManager proxy"
        );
        _assertProxyImplementation(d.managerProxy, d.managerImpl, "AgentBondManager proxy implementation mismatch");
        console2.log("AgentBondManager proxy:", d.managerProxy);

        ReputationScorer scorer = ReputationScorer(d.scorerProxy);
        if (scorer.priorValue() == 0) {
            scorer.initialize(config.scorerPriorValue, config.scorerSlashMultiplierBps);
        }
        if (scorer.priorValue() != config.scorerPriorValue) {
            revert("Scorer prior value mismatch");
        }
        if (scorer.slashMultiplierBps() != config.scorerSlashMultiplierBps) {
            revert("Scorer slash multiplier mismatch");
        }
        if (address(scorer.BOND_MANAGER()) == address(0)) {
            scorer.setBondManager(d.managerProxy);
        } else if (address(scorer.BOND_MANAGER()) != d.managerProxy) {
            revert("Scorer BOND_MANAGER mismatch");
        }

        AgentBondManager manager = AgentBondManager(d.managerProxy);
        if (manager.owner() == address(0)) {
            manager.initialize(
                config.identityRegistry,
                config.validationRegistry,
                d.scorerProxy,
                config.settlementToken,
                config.disputePeriod,
                config.minPassingScore,
                config.slashBps
            );
        }
        if (address(manager.IDENTITY_REGISTRY()) != config.identityRegistry) {
            revert("Manager identity registry mismatch");
        }
        if (address(manager.VALIDATION_REGISTRY()) != config.validationRegistry) {
            revert("Manager validation registry mismatch");
        }
        if (address(manager.SCORER()) != d.scorerProxy) {
            revert("Manager scorer mismatch");
        }
        if (address(manager.settlementToken()) != config.settlementToken) {
            revert("Manager settlement token mismatch");
        }
        if (uint8(manager.validationFinalityPolicy()) != config.validationFinalityPolicy) {
            manager.setValidationFinalityPolicy(config.validationFinalityPolicy);
        }
        if (uint8(manager.statusLookupFailurePolicy()) != config.statusLookupFailurePolicy) {
            manager.setStatusLookupFailurePolicy(config.statusLookupFailurePolicy);
        }

        if (config.ownerAddress != config.deployer) {
            if (scorer.owner() == config.deployer && scorer.pendingOwner() == address(0)) {
                scorer.transferOwnership(config.ownerAddress);
            }
            if (manager.owner() == config.deployer && manager.pendingOwner() == address(0)) {
                manager.transferOwnership(config.ownerAddress);
            }
            if (scorer.owner() != config.ownerAddress && scorer.pendingOwner() != config.ownerAddress) {
                revert("Scorer ownership state mismatch");
            }
            if (manager.owner() != config.ownerAddress && manager.pendingOwner() != config.ownerAddress) {
                revert("Manager ownership state mismatch");
            }
            if (scorer.pendingOwner() != address(0) && scorer.pendingOwner() != config.ownerAddress) {
                revert("Scorer pending owner mismatch");
            }
            if (manager.pendingOwner() != address(0) && manager.pendingOwner() != config.ownerAddress) {
                revert("Manager pending owner mismatch");
            }
            console2.log("Ownership transfer initiated to:", config.ownerAddress);
        } else {
            console2.log("OWNER_ADDRESS matches DEPLOYER_ADDRESS; skipping ownership transfer");
        }

        vm.stopBroadcast();

        _writeArtifacts(outputPath, d, config);
        _logDeployment(d);
    }

    function predictAddresses() external view {
        bytes32 saltSecret = _loadSaltSecret();
        bytes32 scorerImplSalt = _deriveSalt(BASE_SCORER_IMPL_SALT, saltSecret);
        bytes32 scorerProxySalt = _deriveSalt(BASE_SCORER_PROXY_SALT, saltSecret);
        bytes32 managerImplSalt = _deriveSalt(BASE_MANAGER_IMPL_SALT, saltSecret);
        bytes32 managerProxySalt = _deriveSalt(BASE_MANAGER_PROXY_SALT, saltSecret);

        console2.log("===========================================");
        console2.log("  Agent Bonds Deterministic Address Prediction");
        console2.log("===========================================");
        console2.log(
            "ReputationScorer impl:",
            _predictCreate2Address(type(ReputationScorer).creationCode, scorerImplSalt)
        );
        console2.log("ReputationScorer proxy:", _predictProxyAddressForScorer(scorerImplSalt, scorerProxySalt));
        console2.log(
            "AgentBondManager impl:",
            _predictCreate2Address(type(AgentBondManager).creationCode, managerImplSalt)
        );
        console2.log(
            "AgentBondManager proxy:",
            _predictProxyAddressForManager(managerImplSalt, managerProxySalt)
        );
        console2.log("===========================================");
    }

    function _loadConfig() private view returns (DeployConfig memory c) {
        c.deployer = vm.envAddress("DEPLOYER_ADDRESS");
        c.ownerAddress = vm.envAddress("OWNER_ADDRESS");
        c.identityRegistry = vm.envAddress("IDENTITY_REGISTRY");
        c.validationRegistry = vm.envAddress("VALIDATION_REGISTRY");
        c.settlementToken = vm.envAddress("SETTLEMENT_TOKEN");
        c.scorerPriorValue = _envUintOrDefault("SCORER_PRIOR_VALUE", 0);
        if (c.scorerPriorValue == 0) {
            c.scorerPriorValue = vm.envUint("SCORER_PRIOR_VALUE_WEI");
        }
        c.scorerSlashMultiplierBps = vm.envUint("SCORER_SLASH_MULTIPLIER_BPS");
        c.disputePeriod = vm.envUint("DISPUTE_PERIOD");
        uint256 rawValidationFinalityPolicy = _envUintOrDefault(
            "VALIDATION_FINALITY_POLICY",
            uint256(uint8(AgentBondManager.ValidationFinalityPolicy.ResponseHashRequired))
        );
        if (rawValidationFinalityPolicy > uint8(AgentBondManager.ValidationFinalityPolicy.AnyStatusRecord)) {
            revert("VALIDATION_FINALITY_POLICY out of range");
        }
        c.validationFinalityPolicy = uint8(rawValidationFinalityPolicy);

        uint256 rawStatusLookupFailurePolicy = _envUintOrDefault(
            "STATUS_LOOKUP_FAILURE_POLICY",
            uint256(uint8(AgentBondManager.StatusLookupFailurePolicy.CanonicalUnknownAsMissing))
        );
        if (rawStatusLookupFailurePolicy > uint8(AgentBondManager.StatusLookupFailurePolicy.AlwaysUnavailable)) {
            revert("STATUS_LOOKUP_FAILURE_POLICY out of range");
        }
        c.statusLookupFailurePolicy = uint8(rawStatusLookupFailurePolicy);

        uint256 rawScore = vm.envUint("MIN_PASSING_SCORE");
        if (rawScore > 100) revert("MIN_PASSING_SCORE exceeds 100");
        c.minPassingScore = uint8(rawScore);

        c.slashBps = vm.envUint("SLASH_BPS");
    }

    function _validateConfig(DeployConfig memory c) private view {
        if (c.deployer == address(0)) revert("DEPLOYER_ADDRESS is zero");
        if (c.ownerAddress == address(0)) revert("OWNER_ADDRESS is zero");
        if (c.identityRegistry == address(0)) revert("IDENTITY_REGISTRY is zero");
        if (c.validationRegistry == address(0)) revert("VALIDATION_REGISTRY is zero");
        if (c.settlementToken == address(0)) revert("SETTLEMENT_TOKEN is zero");
        if (c.scorerPriorValue == 0) revert("SCORER_PRIOR_VALUE is zero");
        if (c.scorerSlashMultiplierBps < 10_000 || c.scorerSlashMultiplierBps > 100_000) {
            revert("SCORER_SLASH_MULTIPLIER_BPS out of range [10000,100000]");
        }
        if (c.minPassingScore == 0 || c.minPassingScore > 100) revert("MIN_PASSING_SCORE out of range [1,100]");
        if (c.slashBps > 10_000) revert("SLASH_BPS exceeds 10000");
        if (c.disputePeriod < MIN_DISPUTE_PERIOD) revert("DISPUTE_PERIOD below minimum");
        if (c.disputePeriod > 90 days) revert("DISPUTE_PERIOD exceeds 90 days");
        if (c.validationFinalityPolicy > uint8(AgentBondManager.ValidationFinalityPolicy.AnyStatusRecord)) {
            revert("VALIDATION_FINALITY_POLICY out of range");
        }
        if (c.statusLookupFailurePolicy > uint8(AgentBondManager.StatusLookupFailurePolicy.AlwaysUnavailable)) {
            revert("STATUS_LOOKUP_FAILURE_POLICY out of range");
        }

        if (c.identityRegistry.code.length == 0) revert("IDENTITY_REGISTRY has no code");
        if (c.validationRegistry.code.length == 0) revert("VALIDATION_REGISTRY has no code");
        if (c.settlementToken.code.length == 0) revert("SETTLEMENT_TOKEN has no code");
        if (DETERMINISTIC_DEPLOYMENT_PROXY.code.length == 0) {
            revert("Deterministic deployment proxy missing at 0x4e59b4...");
        }
    }

    function _writeArtifacts(string memory path, Deployment memory d, DeployConfig memory c) private {
        string memory key = "deployment";
        string memory json;

        json = vm.serializeUint(key, "chainId", block.chainid);
        json = vm.serializeAddress(key, "scorerImplementation", d.scorerImpl);
        json = vm.serializeAddress(key, "scorerProxy", d.scorerProxy);
        json = vm.serializeAddress(key, "managerImplementation", d.managerImpl);
        json = vm.serializeAddress(key, "managerProxy", d.managerProxy);
        json = vm.serializeAddress(key, "identityRegistry", c.identityRegistry);
        json = vm.serializeAddress(key, "validationRegistry", c.validationRegistry);
        json = vm.serializeAddress(key, "settlementToken", c.settlementToken);
        json = vm.serializeAddress(key, "ownerAddress", c.ownerAddress);
        json = vm.serializeUint(key, "scorerPriorValue", c.scorerPriorValue);
        json = vm.serializeUint(key, "scorerSlashMultiplierBps", c.scorerSlashMultiplierBps);
        json = vm.serializeUint(key, "disputePeriod", c.disputePeriod);
        json = vm.serializeUint(key, "minPassingScore", uint256(c.minPassingScore));
        json = vm.serializeUint(key, "slashBps", c.slashBps);
        json = vm.serializeUint(key, "validationFinalityPolicy", uint256(c.validationFinalityPolicy));
        json = vm.serializeUint(key, "statusLookupFailurePolicy", uint256(c.statusLookupFailurePolicy));
        json = vm.serializeUint(key, "timestamp", block.timestamp);

        try vm.envString("SALT_TAG") returns (string memory tag) {
            if (bytes(tag).length > 0) {
                json = vm.serializeString(key, "saltTag", tag);
            }
        } catch {}

        vm.writeJson(json, path);
        console2.log("Deployment saved to:", path);
    }

    function _logConfig(DeployConfig memory c) private pure {
        console2.log("Deployer:", c.deployer);
        console2.log("Owner Address:", c.ownerAddress);
        console2.log("Identity Registry:", c.identityRegistry);
        console2.log("Validation Registry:", c.validationRegistry);
        console2.log("Settlement Token:", c.settlementToken);
        console2.log("Scorer prior value:", c.scorerPriorValue);
        console2.log("Scorer slash multiplier (bps):", c.scorerSlashMultiplierBps);
        console2.log("Dispute Period:", c.disputePeriod);
        console2.log("Min Passing Score:", uint256(c.minPassingScore));
        console2.log("Slash BPS:", c.slashBps);
        console2.log("Validation finality policy:", uint256(c.validationFinalityPolicy));
        console2.log("Status lookup failure policy:", uint256(c.statusLookupFailurePolicy));
        console2.log("");
    }

    function _envUintOrDefault(string memory key, uint256 defaultValue) private view returns (uint256 value) {
        try vm.envString(key) returns (string memory raw) {
            try vm.parseUint(raw) returns (uint256 parsed) {
                return parsed;
            } catch {
                revert(string.concat(key, " must be a valid uint256"));
            }
        } catch {
            return defaultValue;
        }
    }

    function _logSaltInfo() private view {
        console2.log("Deterministic salt secret: configured");
        try vm.envString("SALT_TAG") returns (string memory tag) {
            if (bytes(tag).length > 0) {
                console2.log("SALT_TAG:", tag);
            }
        } catch {}
        console2.log("");
    }

    function _loadSaltSecret() private view returns (bytes32 secret) {
        try vm.envBytes32("DEPLOYMENT_SALT_SECRET") returns (bytes32 s) {
            if (s == bytes32(0)) revert("DEPLOYMENT_SALT_SECRET must be non-zero");
            secret = s;
        } catch {
            revert("DEPLOYMENT_SALT_SECRET env var required");
        }

        try vm.envString("SALT_TAG") returns (string memory tag) {
            if (bytes(tag).length > 0) {
                secret = keccak256(abi.encodePacked(secret, tag));
            }
        } catch {}
    }

    function _deriveSalt(bytes32 baseSalt, bytes32 secret) private pure returns (bytes32) {
        return keccak256(abi.encode(baseSalt, secret));
    }

    function _deploymentArtifactsPath() private view returns (string memory) {
        string memory basePath =
            string.concat(vm.projectRoot(), "/deployments/", vm.toString(block.chainid));
        string memory tag = _saltTag();
        if (bytes(tag).length == 0) {
            return string.concat(basePath, ".json");
        }

        return string.concat(basePath, "-", vm.toString(keccak256(bytes(tag))), ".json");
    }

    function _saltTag() private view returns (string memory tag) {
        try vm.envString("SALT_TAG") returns (string memory configuredTag) {
            return configuredTag;
        } catch {
            return "";
        }
    }

    function _deployDeterministic(
        bytes memory creationCode,
        bytes32 salt,
        bytes32 expectedRuntimeHash,
        string memory label
    ) private returns (address deployed) {
        deployed = _predictCreate2Address(creationCode, salt);
        if (deployed.code.length > 0) {
            if (expectedRuntimeHash != bytes32(0) && keccak256(deployed.code) != expectedRuntimeHash) {
                revert(string.concat(label, " runtime hash mismatch at predicted address"));
            }
            console2.log(label, "already deployed at:", deployed);
            return deployed;
        }

        (bool success, bytes memory returnData) = DETERMINISTIC_DEPLOYMENT_PROXY.call(
            abi.encodePacked(salt, creationCode)
        );
        if (!success) {
            assembly ("memory-safe") {
                revert(add(returnData, 0x20), mload(returnData))
            }
        }

        if (deployed.code.length == 0) {
            revert(string.concat(label, " deployment failed"));
        }
        if (expectedRuntimeHash != bytes32(0) && keccak256(deployed.code) != expectedRuntimeHash) {
            revert(string.concat(label, " runtime hash mismatch after deployment"));
        }
    }

    function _predictCreate2Address(bytes memory creationCode, bytes32 salt) private pure returns (address) {
        bytes32 initCodeHash = keccak256(creationCode);
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(bytes1(0xff), DETERMINISTIC_DEPLOYMENT_PROXY, salt, initCodeHash)
                    )
                )
            )
        );
    }

    function _assertProxyImplementation(address proxy, address expectedImplementation, string memory errorMessage)
        private
        view
    {
        address implementation = address(uint160(uint256(vm.load(proxy, ERC1967_IMPLEMENTATION_SLOT))));
        if (implementation != expectedImplementation) {
            revert(errorMessage);
        }
    }

    function _assertScorerImplementation(address implementation) private view {
        if (_proxiableUuid(implementation) != ERC1967_IMPLEMENTATION_SLOT) {
            revert("Scorer implementation proxiableUUID mismatch");
        }
        _requireProbeSuccess(implementation, abi.encodeWithSignature("priorValue()"), "Scorer probe failed");
        _requireProbeSuccess(
            implementation,
            abi.encodeWithSignature("slashMultiplierBps()"),
            "Scorer probe failed"
        );
    }

    function _assertManagerImplementation(address implementation) private view {
        if (_proxiableUuid(implementation) != ERC1967_IMPLEMENTATION_SLOT) {
            revert("Manager implementation proxiableUUID mismatch");
        }
        _requireProbeSuccess(
            implementation,
            abi.encodeWithSignature("validationFinalityPolicy()"),
            "Manager probe failed"
        );
        _requireProbeSuccess(
            implementation,
            abi.encodeWithSignature("statusLookupFailurePolicy()"),
            "Manager probe failed"
        );
    }

    function _proxiableUuid(address implementation) private view returns (bytes32 uuid) {
        (bool ok, bytes memory data) = implementation.staticcall(abi.encodeWithSignature("proxiableUUID()"));
        if (!ok || data.length < 32) revert("Implementation missing proxiableUUID");
        uuid = abi.decode(data, (bytes32));
    }

    function _requireProbeSuccess(address implementation, bytes memory payload, string memory err) private view {
        (bool ok,) = implementation.staticcall(payload);
        if (!ok) revert(err);
    }

    function _predictProxyAddressForScorer(bytes32 scorerImplSalt, bytes32 scorerProxySalt)
        private
        pure
        returns (address)
    {
        address scorerImpl = _predictCreate2Address(type(ReputationScorer).creationCode, scorerImplSalt);
        return _predictCreate2Address(_scorerProxyCreationCode(scorerImpl), scorerProxySalt);
    }

    function _predictProxyAddressForManager(bytes32 managerImplSalt, bytes32 managerProxySalt)
        private
        pure
        returns (address)
    {
        address managerImpl = _predictCreate2Address(type(AgentBondManager).creationCode, managerImplSalt);
        return _predictCreate2Address(_managerProxyCreationCode(managerImpl), managerProxySalt);
    }

    function _scorerProxyCreationCode(address scorerImpl) private pure returns (bytes memory) {
        return abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(scorerImpl, bytes("")));
    }

    function _managerProxyCreationCode(address managerImpl) private pure returns (bytes memory) {
        return abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(managerImpl, bytes("")));
    }

    function _assertExistingArtifactCompatibility(
        string memory path,
        address predictedScorerProxy,
        address predictedManagerProxy
    ) private view {
        try vm.readFile(path) returns (string memory raw) {
            address existingScorerProxy = _parseAddress(raw, ".scorerProxy");
            address existingManagerProxy = _parseAddress(raw, ".managerProxy");
            bool scorerLive = existingScorerProxy != address(0) && existingScorerProxy.code.length > 0;
            bool managerLive = existingManagerProxy != address(0) && existingManagerProxy.code.length > 0;

            if (scorerLive != managerLive) {
                revert("Existing deployment artifact is partial");
            }
            if (!scorerLive) {
                return;
            }
            if (existingScorerProxy != predictedScorerProxy || existingManagerProxy != predictedManagerProxy) {
                revert("Existing deployment differs from deterministic prediction; use upgrade or SALT_TAG");
            }
        } catch {}
    }

    function _parseAddress(string memory json, string memory key) private pure returns (address) {
        try vm.parseJsonAddress(json, key) returns (address parsed) {
            return parsed;
        } catch {
            return address(0);
        }
    }

    function _requireExpectedChainId() private view {
        uint256 expectedChainId = vm.envUint("EXPECTED_CHAIN_ID");
        if (block.chainid != expectedChainId) {
            revert("EXPECTED_CHAIN_ID mismatch");
        }
    }

    function _logDeployment(Deployment memory d) private pure {
        console2.log("");
        console2.log("===========================================");
        console2.log("  Deployment Complete");
        console2.log("===========================================");
        console2.log("ReputationScorer impl:", d.scorerImpl);
        console2.log("ReputationScorer proxy:", d.scorerProxy);
        console2.log("AgentBondManager impl:", d.managerImpl);
        console2.log("AgentBondManager proxy:", d.managerProxy);
        console2.log("===========================================");
    }
}
