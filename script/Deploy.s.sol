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
    struct DeployConfig {
        address deployer;
        address identityRegistry;
        address reputationRegistry;
        address validationRegistry;
        string reputationTag;
        uint256 maxExpectedValue;
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
        DeployConfig memory config = _loadConfig();
        _validateConfig(config);

        console2.log("===========================================");
        console2.log("  Agent Bonds Deployment");
        console2.log("===========================================");
        _logConfig(config);

        string memory outDir = string.concat(vm.projectRoot(), "/deployments");
        string memory outputPath = string.concat(outDir, "/", vm.toString(block.chainid), ".json");
        vm.createDir(outDir, true);

        vm.startBroadcast(config.deployer);

        Deployment memory d;

        d.scorerImpl = address(new ReputationScorer());
        console2.log("ReputationScorer impl:", d.scorerImpl);

        d.scorerProxy = address(
            new ERC1967Proxy(
                d.scorerImpl,
                abi.encodeCall(
                    ReputationScorer.initialize,
                    (
                        config.reputationRegistry,
                        config.validationRegistry,
                        config.reputationTag,
                        config.maxExpectedValue
                    )
                )
            )
        );
        console2.log("ReputationScorer proxy:", d.scorerProxy);

        d.managerImpl = address(new AgentBondManager());
        console2.log("AgentBondManager impl:", d.managerImpl);

        d.managerProxy = address(
            new ERC1967Proxy(
                d.managerImpl,
                abi.encodeCall(
                    AgentBondManager.initialize,
                    (
                        config.identityRegistry,
                        config.validationRegistry,
                        d.scorerProxy,
                        config.disputePeriod,
                        config.minPassingScore,
                        config.slashBps
                    )
                )
            )
        );
        console2.log("AgentBondManager proxy:", d.managerProxy);

        AgentBondManager manager = AgentBondManager(payable(d.managerProxy));
        manager.setValidationFinalityPolicy(config.validationFinalityPolicy);
        manager.setStatusLookupFailurePolicy(config.statusLookupFailurePolicy);

        vm.stopBroadcast();

        _writeArtifacts(outputPath, d, config);
        _logDeployment(d);
    }

    function _loadConfig() private view returns (DeployConfig memory c) {
        c.deployer = vm.envAddress("DEPLOYER_ADDRESS");
        c.identityRegistry = vm.envAddress("IDENTITY_REGISTRY");
        c.reputationRegistry = vm.envAddress("REPUTATION_REGISTRY");
        c.validationRegistry = vm.envAddress("VALIDATION_REGISTRY");
        c.reputationTag = vm.envString("REPUTATION_TAG");
        c.maxExpectedValue = vm.envUint("MAX_EXPECTED_VALUE");
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
        if (c.identityRegistry == address(0)) revert("IDENTITY_REGISTRY is zero");
        if (c.reputationRegistry == address(0)) revert("REPUTATION_REGISTRY is zero");
        if (c.validationRegistry == address(0)) revert("VALIDATION_REGISTRY is zero");
        if (bytes(c.reputationTag).length == 0) revert("REPUTATION_TAG is empty");
        if (c.maxExpectedValue == 0) revert("MAX_EXPECTED_VALUE is zero");
        if (c.minPassingScore == 0 || c.minPassingScore > 100) revert("MIN_PASSING_SCORE out of range [1,100]");
        if (c.slashBps > 10_000) revert("SLASH_BPS exceeds 10000");
        if (c.disputePeriod > 90 days) revert("DISPUTE_PERIOD exceeds 90 days");
        if (c.validationFinalityPolicy > uint8(AgentBondManager.ValidationFinalityPolicy.AnyStatusRecord)) {
            revert("VALIDATION_FINALITY_POLICY out of range");
        }
        if (c.statusLookupFailurePolicy > uint8(AgentBondManager.StatusLookupFailurePolicy.AlwaysUnavailable)) {
            revert("STATUS_LOOKUP_FAILURE_POLICY out of range");
        }

        if (c.identityRegistry.code.length == 0) revert("IDENTITY_REGISTRY has no code");
        if (c.reputationRegistry.code.length == 0) revert("REPUTATION_REGISTRY has no code");
        if (c.validationRegistry.code.length == 0) revert("VALIDATION_REGISTRY has no code");
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
        json = vm.serializeAddress(key, "reputationRegistry", c.reputationRegistry);
        json = vm.serializeAddress(key, "validationRegistry", c.validationRegistry);
        json = vm.serializeString(key, "reputationTag", c.reputationTag);
        json = vm.serializeUint(key, "maxExpectedValue", c.maxExpectedValue);
        json = vm.serializeUint(key, "disputePeriod", c.disputePeriod);
        json = vm.serializeUint(key, "minPassingScore", uint256(c.minPassingScore));
        json = vm.serializeUint(key, "slashBps", c.slashBps);
        json = vm.serializeUint(key, "validationFinalityPolicy", uint256(c.validationFinalityPolicy));
        json = vm.serializeUint(key, "statusLookupFailurePolicy", uint256(c.statusLookupFailurePolicy));
        json = vm.serializeUint(key, "timestamp", block.timestamp);

        vm.writeJson(json, path);
        console2.log("Deployment saved to:", path);
    }

    function _logConfig(DeployConfig memory c) private pure {
        console2.log("Deployer:", c.deployer);
        console2.log("Identity Registry:", c.identityRegistry);
        console2.log("Reputation Registry:", c.reputationRegistry);
        console2.log("Validation Registry:", c.validationRegistry);
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
