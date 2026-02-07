// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {AgentBondManager} from "../src/AgentBondManager.sol";
import {ReputationScorer} from "../src/ReputationScorer.sol";

/// @title PostDeploymentSmokeTest
/// @author Vaultum
/// @notice Verifies Agent Bonds deployment is correctly initialized on-chain.
/// @dev Run: forge script script/PostDeploymentSmokeTest.s.sol --rpc-url $RPC_URL
contract PostDeploymentSmokeTest is Script {
    bytes32 private constant ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    uint256 private totalTests;
    uint256 private failCount;

    function run() external {
        console2.log("===========================================");
        console2.log("  Agent Bonds Smoke Test");
        console2.log("===========================================");
        console2.log("");

        (address managerProxy, address scorerProxy) = _loadAddresses();
        if (managerProxy == address(0) || scorerProxy == address(0)) {
            revert("Deployment addresses not found");
        }

        console2.log("Manager proxy:", managerProxy);
        console2.log("Scorer proxy:", scorerProxy);
        console2.log("");

        _testScorerProxy(scorerProxy);
        _testManagerProxy(managerProxy, scorerProxy);

        console2.log("");
        console2.log("===========================================");
        uint256 passed = totalTests - failCount;
        if (failCount == 0) {
            console2.log("  All", passed, "tests passed.");
        } else {
            console2.log("  FAILED:", failCount, "of", totalTests);
            revert("Smoke tests failed");
        }
        console2.log("===========================================");
    }

    function _testScorerProxy(address proxy) private {
        console2.log("--- ReputationScorer ---");

        _check("Scorer: has code", "OK", proxy.code.length > 0);

        address impl = _getImplementation(proxy);
        _check("Scorer: impl has code", vm.toString(impl), impl != address(0) && impl.code.length > 0);

        ReputationScorer scorer = ReputationScorer(proxy);

        address owner = scorer.owner();
        _check("Scorer: owner set", vm.toString(owner), owner != address(0));

        address repRegistry = address(scorer.REPUTATION_REGISTRY());
        _check("Scorer: reputation registry", vm.toString(repRegistry), repRegistry != address(0));

        address valRegistry = address(scorer.VALIDATION_REGISTRY());
        _check("Scorer: validation registry", vm.toString(valRegistry), valRegistry != address(0));

        uint256 maxVal = scorer.maxExpectedValue();
        _check("Scorer: maxExpectedValue", vm.toString(maxVal), maxVal > 0);

        uint256 repW = scorer.reputationWeight();
        uint256 valW = scorer.validationWeight();
        _check(
            "Scorer: weights each <= 10000",
            string.concat(vm.toString(repW), " + ", vm.toString(valW)),
            repW <= 10_000 && valW <= 10_000
        );

        console2.log("");
    }

    function _testManagerProxy(address proxy, address expectedScorer) private {
        console2.log("--- AgentBondManager ---");

        _check("Manager: has code", "OK", proxy.code.length > 0);

        address impl = _getImplementation(proxy);
        _check("Manager: impl has code", vm.toString(impl), impl != address(0) && impl.code.length > 0);

        AgentBondManager manager = AgentBondManager(payable(proxy));

        address owner = manager.owner();
        _check("Manager: owner set", vm.toString(owner), owner != address(0));

        address identity = address(manager.IDENTITY_REGISTRY());
        _check("Manager: identity registry", vm.toString(identity), identity != address(0));

        address validation = address(manager.VALIDATION_REGISTRY());
        _check("Manager: validation registry", vm.toString(validation), validation != address(0));

        address scorer = address(manager.SCORER());
        _check("Manager: scorer matches", vm.toString(scorer), scorer == expectedScorer);

        uint256 dp = manager.disputePeriod();
        _check("Manager: disputePeriod", string.concat(vm.toString(dp), "s"), dp > 0 && dp <= 90 days);

        uint8 mps = manager.minPassingScore();
        _check("Manager: minPassingScore", vm.toString(uint256(mps)), mps > 0 && mps <= 100);

        uint256 bps = manager.slashBps();
        _check("Manager: slashBps", vm.toString(bps), bps <= 10_000);

        uint256 rgp = manager.registryFailureGracePeriod();
        _check("Manager: registryFailureGracePeriod", string.concat(vm.toString(rgp), "s"), rgp <= 90 days);

        console2.log("");
    }

    function _getImplementation(address proxy) private view returns (address impl) {
        impl = address(uint160(uint256(vm.load(proxy, ERC1967_IMPLEMENTATION_SLOT))));
    }

    function _check(string memory name, string memory detail, bool passed) private {
        totalTests++;
        if (passed) {
            console2.log("[PASS]", name, "-", detail);
        } else {
            failCount++;
            console2.log("[FAIL]", name, "-", detail);
        }
    }

    function _loadAddresses() private view returns (address manager, address scorer) {
        manager = _envAddress("MANAGER_PROXY");
        scorer = _envAddress("SCORER_PROXY");

        if (manager != address(0) && scorer != address(0)) return (manager, scorer);

        string memory path = string.concat(vm.projectRoot(), "/deployments/", vm.toString(block.chainid), ".json");
        try vm.readFile(path) returns (string memory raw) {
            if (manager == address(0)) manager = _parseAddress(raw, ".managerProxy");
            if (scorer == address(0)) scorer = _parseAddress(raw, ".scorerProxy");
        } catch {}
    }

    function _envAddress(string memory key) private view returns (address) {
        try vm.envAddress(key) returns (address v) { return v; } catch { return address(0); }
    }

    function _parseAddress(string memory json, string memory key) private pure returns (address) {
        try vm.parseJsonAddress(json, key) returns (address v) { return v; } catch { return address(0); }
    }
}
