// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";

/// @title PreFlightCheck
/// @author Vaultum
/// @notice Validates environment configuration before Agent Bonds deployment.
/// @dev Run: forge script script/PreFlightCheck.s.sol --rpc-url $RPC_URL
contract PreFlightCheck is Script {
    uint256 private constant MIN_DEPLOYER_BALANCE = 0.05 ether;
    uint256 private constant MIN_DISPUTE_PERIOD = 1 hours;

    struct CheckResult {
        bool passed;
        string message;
    }

    CheckResult[] private results;
    uint256 private failCount;

    function run() external {
        console2.log("===========================================");
        console2.log("  Agent Bonds Pre-Flight Check");
        console2.log("===========================================");
        console2.log("");

        _checkDeployer();
        _checkRegistries();
        _checkSettlementToken();
        _checkScorerParams();
        _checkManagerParams();
        _checkPolicyParams();
        _checkExistingDeployment();

        _printSummary();

        if (failCount > 0) revert("Pre-flight checks failed");
    }

    function _checkDeployer() private {
        console2.log("Checking deployer...");

        address deployer = _envAddress("DEPLOYER_ADDRESS");
        if (deployer == address(0)) {
            _record(false, "DEPLOYER_ADDRESS: MISSING");
            console2.log("");
            return;
        }

        _record(true, string.concat("DEPLOYER_ADDRESS: ", vm.toString(deployer)));

        uint256 balance = deployer.balance;
        if (balance < MIN_DEPLOYER_BALANCE) {
            _record(
                false,
                string.concat(
                    "Balance: ",
                    vm.toString(balance / 1e15),
                    " finney (need ",
                    vm.toString(MIN_DEPLOYER_BALANCE / 1e15),
                    " finney)"
                )
            );
        } else {
            _record(true, string.concat("Balance: ", vm.toString(balance / 1e15), " finney"));
        }

        console2.log("");
    }

    function _checkRegistries() private {
        console2.log("Checking ERC-8004 registries...");

        _checkAddressWithCode("IDENTITY_REGISTRY");
        _checkAddressWithCode("VALIDATION_REGISTRY");

        console2.log("");
    }

    function _checkSettlementToken() private {
        console2.log("Checking settlement token...");
        _checkAddressWithCode("SETTLEMENT_TOKEN");
        console2.log("");
    }

    function _checkScorerParams() private {
        console2.log("Checking ReputationScorer params...");

        uint256 priorValue = _envUint("SCORER_PRIOR_VALUE");
        if (priorValue == 0) {
            priorValue = _envUint("SCORER_PRIOR_VALUE_WEI");
        }
        if (priorValue == 0) {
            _record(false, "SCORER_PRIOR_VALUE: MISSING or zero");
        } else {
            _record(true, string.concat("SCORER_PRIOR_VALUE: ", vm.toString(priorValue)));
        }

        uint256 slashMultiplierBps = _envUint("SCORER_SLASH_MULTIPLIER_BPS");
        if (slashMultiplierBps < 10_000 || slashMultiplierBps > 100_000) {
            _record(
                false,
                string.concat(
                    "SCORER_SLASH_MULTIPLIER_BPS: ",
                    vm.toString(slashMultiplierBps),
                    " (must be 10000-100000)"
                )
            );
        } else {
            _record(true, string.concat("SCORER_SLASH_MULTIPLIER_BPS: ", vm.toString(slashMultiplierBps)));
        }

        console2.log("");
    }

    function _checkManagerParams() private {
        console2.log("Checking AgentBondManager params...");

        uint256 dp = _envUint("DISPUTE_PERIOD");
        if (dp == 0) {
            _record(false, "DISPUTE_PERIOD: MISSING");
        } else if (dp < MIN_DISPUTE_PERIOD) {
            _record(
                false,
                string.concat(
                    "DISPUTE_PERIOD: ", vm.toString(dp), " below minimum ", vm.toString(MIN_DISPUTE_PERIOD)
                )
            );
        } else if (dp > 90 days) {
            _record(false, string.concat("DISPUTE_PERIOD: ", vm.toString(dp), " exceeds 90 days"));
        } else {
            _record(true, string.concat("DISPUTE_PERIOD: ", vm.toString(dp), " seconds"));
        }

        uint256 mps = _envUint("MIN_PASSING_SCORE");
        if (mps == 0 || mps > 100) {
            _record(false, string.concat("MIN_PASSING_SCORE: ", vm.toString(mps), " (must be 1-100)"));
        } else {
            _record(true, string.concat("MIN_PASSING_SCORE: ", vm.toString(mps)));
        }

        uint256 bps = _envUint("SLASH_BPS");
        if (bps > 10_000) {
            _record(false, string.concat("SLASH_BPS: ", vm.toString(bps), " exceeds 10000"));
        } else {
            _record(true, string.concat("SLASH_BPS: ", vm.toString(bps)));
        }

        console2.log("");
    }

    function _checkPolicyParams() private {
        console2.log("Checking AgentBondManager policy params...");

        (bool hasValidityPolicy, bool validityPolicyValid, uint256 validityPolicy) =
            _envOptionalUint("VALIDATION_FINALITY_POLICY");
        if (!hasValidityPolicy) {
            _record(true, "VALIDATION_FINALITY_POLICY: not set (defaulting to 0)");
        } else if (!validityPolicyValid) {
            _record(false, "VALIDATION_FINALITY_POLICY: invalid uint256");
        } else if (validityPolicy > 1) {
            _record(false, string.concat("VALIDATION_FINALITY_POLICY: ", vm.toString(validityPolicy), " out of range [0-1]"));
        } else {
            _record(true, string.concat("VALIDATION_FINALITY_POLICY: ", vm.toString(validityPolicy)));
        }

        (bool hasFailurePolicy, bool failurePolicyValid, uint256 failurePolicy) =
            _envOptionalUint("STATUS_LOOKUP_FAILURE_POLICY");
        if (!hasFailurePolicy) {
            _record(true, "STATUS_LOOKUP_FAILURE_POLICY: not set (defaulting to 0)");
        } else if (!failurePolicyValid) {
            _record(false, "STATUS_LOOKUP_FAILURE_POLICY: invalid uint256");
        } else if (failurePolicy > 2) {
            _record(false, string.concat("STATUS_LOOKUP_FAILURE_POLICY: ", vm.toString(failurePolicy), " out of range [0-2]"));
        } else {
            _record(true, string.concat("STATUS_LOOKUP_FAILURE_POLICY: ", vm.toString(failurePolicy)));
        }

        console2.log("");
    }

    function _checkExistingDeployment() private {
        console2.log("Checking existing deployments...");

        string memory path = string.concat(vm.projectRoot(), "/deployments/", vm.toString(block.chainid), ".json");
        try vm.readFile(path) returns (string memory raw) {
            if (bytes(raw).length > 2) {
                address managerProxy = _parseAddress(raw, ".managerProxy");
                address scorerProxy = _parseAddress(raw, ".scorerProxy");

                if (managerProxy != address(0) && managerProxy.code.length > 0) {
                    _record(false, string.concat("AgentBondManager already deployed at ", vm.toString(managerProxy)));
                } else {
                    _record(true, "No live AgentBondManager found");
                }

                if (scorerProxy != address(0) && scorerProxy.code.length > 0) {
                    _record(false, string.concat("ReputationScorer already deployed at ", vm.toString(scorerProxy)));
                } else {
                    _record(true, "No live ReputationScorer found");
                }
            } else {
                _record(true, "No existing deployment found");
            }
        } catch {
            _record(true, "No deployments file found (fresh deployment)");
        }

        console2.log("");
    }

    function _checkAddressWithCode(string memory key) private {
        address addr = _envAddress(key);
        if (addr == address(0)) {
            _record(false, string.concat(key, ": MISSING"));
        } else if (addr.code.length == 0) {
            _record(false, string.concat(key, ": ", vm.toString(addr), " (no code)"));
        } else {
            _record(true, string.concat(key, ": ", vm.toString(addr)));
        }
    }

    function _envAddress(string memory key) private view returns (address) {
        try vm.envAddress(key) returns (address v) {
            return v;
        } catch {
            return address(0);
        }
    }

    function _envUint(string memory key) private view returns (uint256) {
        try vm.envUint(key) returns (uint256 v) {
            return v;
        } catch {
            return 0;
        }
    }

    function _envOptionalUint(string memory key) private view returns (bool exists, bool valid, uint256 value) {
        try vm.envString(key) returns (string memory raw) {
            try vm.parseUint(raw) returns (uint256 parsed) {
                return (true, true, parsed);
            } catch {
                return (true, false, 0);
            }
        } catch {
            return (false, true, 0);
        }
    }

    function _parseAddress(string memory json, string memory key) private pure returns (address) {
        try vm.parseJsonAddress(json, key) returns (address v) {
            return v;
        } catch {
            return address(0);
        }
    }

    function _record(bool passed, string memory message) private {
        results.push(CheckResult({passed: passed, message: message}));
        if (passed) {
            console2.log(unicode"  ✓", message);
        } else {
            console2.log(unicode"  ✗", message);
            failCount++;
        }
    }

    function _printSummary() private view {
        console2.log("===========================================");
        uint256 passCount = results.length - failCount;
        if (failCount == 0) {
            console2.log(unicode"✓ All", passCount, "checks passed. Ready to deploy.");
        } else {
            console2.log(unicode"✗", failCount, "checks failed.");
            console2.log(unicode"✓", passCount, "checks passed.");
            console2.log("Fix the issues above before deploying.");
        }
        console2.log("===========================================");
    }
}
