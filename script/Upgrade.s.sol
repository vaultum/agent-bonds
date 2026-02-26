// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {AgentBondManager} from "../src/AgentBondManager.sol";
import {ReputationScorer} from "../src/ReputationScorer.sol";

/// @title Upgrade
/// @author Vaultum
/// @notice Upgrades AgentBondManager or ReputationScorer UUPS proxies.
/// @dev Set TARGET=manager|scorer and optionally NEW_IMPLEMENTATION to skip redeployment.
///      Run: forge script script/Upgrade.s.sol --rpc-url $RPC_URL --broadcast
contract Upgrade is Script {
    bytes32 private constant ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function run() external {
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        string memory target = vm.envString("TARGET");
        address proxy = _resolveProxy(target);

        if (proxy == address(0)) revert("Proxy address not found");
        if (proxy.code.length == 0) revert("No code at proxy address");

        address currentImpl = _getImplementation(proxy);
        console2.log("===========================================");
        console2.log("  Agent Bonds UUPS Upgrade");
        console2.log("===========================================");
        console2.log("Target:", target);
        console2.log("Proxy:", proxy);
        console2.log("Current impl:", currentImpl);

        vm.startBroadcast(deployer);

        address newImpl = _resolveOrDeploy(target);
        if (newImpl == currentImpl) revert("Already on this implementation");

        console2.log("New impl:", newImpl);

        _upgradeProxy(target, proxy, newImpl);

        vm.stopBroadcast();

        address verifyImpl = _getImplementation(proxy);
        if (verifyImpl != newImpl) revert("Implementation mismatch after upgrade");

        console2.log("");
        console2.log("Upgrade verified. Implementation:", verifyImpl);
        console2.log("===========================================");
    }

    function validateOnly() external view {
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        string memory target = vm.envString("TARGET");
        address proxy = _resolveProxy(target);

        if (proxy == address(0)) revert("Proxy address not found");
        if (proxy.code.length == 0) revert("No code at proxy address");

        address currentImpl = _getImplementation(proxy);
        if (currentImpl == address(0) || currentImpl.code.length == 0) {
            revert("Current implementation invalid");
        }

        address owner = _ownerOf(proxy);
        if (owner != deployer) {
            revert("DEPLOYER_ADDRESS is not proxy owner");
        }

        address provided = _envAddress("NEW_IMPLEMENTATION");
        console2.log("===========================================");
        console2.log("  Agent Bonds Upgrade Preflight");
        console2.log("===========================================");
        console2.log("Target:", target);
        console2.log("Proxy:", proxy);
        console2.log("Proxy owner:", owner);
        console2.log("Current impl:", currentImpl);

        if (provided != address(0)) {
            if (provided.code.length == 0) revert("NEW_IMPLEMENTATION has no code");
            if (provided == currentImpl) revert("Already on this implementation");
            console2.log("New impl override:", provided);
        } else {
            console2.log("NEW_IMPLEMENTATION not set (script will deploy a fresh implementation)");
        }

        console2.log("Preflight complete.");
        console2.log("===========================================");
    }

    function _resolveProxy(string memory target) private view returns (address) {
        bytes32 t = keccak256(bytes(target));

        if (t == keccak256("manager")) {
            address addr = _envAddress("MANAGER_PROXY");
            if (addr != address(0)) return addr;
            return _loadFromArtifacts(".managerProxy");
        }

        if (t == keccak256("scorer")) {
            address addr = _envAddress("SCORER_PROXY");
            if (addr != address(0)) return addr;
            return _loadFromArtifacts(".scorerProxy");
        }

        revert("TARGET must be 'manager' or 'scorer'");
    }

    function _resolveOrDeploy(string memory target) private returns (address) {
        address provided = _envAddress("NEW_IMPLEMENTATION");
        if (provided != address(0)) {
            if (provided.code.length == 0) revert("NEW_IMPLEMENTATION has no code");
            return provided;
        }

        bytes32 t = keccak256(bytes(target));
        if (t == keccak256("manager")) {
            return address(new AgentBondManager());
        }
        if (t == keccak256("scorer")) {
            return address(new ReputationScorer());
        }

        revert("TARGET must be 'manager' or 'scorer'");
    }

    function _upgradeProxy(string memory target, address proxy, address newImpl) private {
        bytes32 t = keccak256(bytes(target));
        if (t == keccak256("manager")) {
            AgentBondManager(payable(proxy)).upgradeToAndCall(newImpl, "");
        } else {
            ReputationScorer(proxy).upgradeToAndCall(newImpl, "");
        }
    }

    function _getImplementation(address proxy) private view returns (address impl) {
        impl = address(uint160(uint256(vm.load(proxy, ERC1967_IMPLEMENTATION_SLOT))));
    }

    function _ownerOf(address target) private view returns (address owner) {
        (bool ok, bytes memory data) = target.staticcall(abi.encodeWithSignature("owner()"));
        if (!ok || data.length < 32) revert("owner() probe failed");
        owner = abi.decode(data, (address));
    }

    function _loadFromArtifacts(string memory key) private view returns (address) {
        string memory path = string.concat(vm.projectRoot(), "/deployments/", vm.toString(block.chainid), ".json");
        try vm.readFile(path) returns (string memory raw) {
            return _parseAddress(raw, key);
        } catch {
            return address(0);
        }
    }

    function _envAddress(string memory key) private view returns (address) {
        try vm.envAddress(key) returns (address v) {
            return v;
        } catch {
            return address(0);
        }
    }

    function _parseAddress(string memory json, string memory key) private pure returns (address) {
        try vm.parseJsonAddress(json, key) returns (address v) {
            return v;
        } catch {
            return address(0);
        }
    }
}
