// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {MinimalValidationRegistry} from "../src/MinimalValidationRegistry.sol";

/// @title DeployValidationRegistry
/// @author Vaultum
/// @notice Deploys MinimalValidationRegistry for testnet dispute flows.
contract DeployValidationRegistry is Script {
    function run() external returns (address deployedRegistry) {
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        if (deployer == address(0)) revert("DEPLOYER_ADDRESS is zero");

        vm.startBroadcast(deployer);
        deployedRegistry = address(new MinimalValidationRegistry());
        vm.stopBroadcast();

        console2.log("MinimalValidationRegistry:", deployedRegistry);

        string memory outDir = string.concat(vm.projectRoot(), "/deployments");
        string memory outputPath = string.concat(outDir, "/validation_", vm.toString(block.chainid), ".json");
        vm.createDir(outDir, true);

        string memory key = "validation";
        string memory json = vm.serializeUint(key, "chainId", block.chainid);
        json = vm.serializeAddress(key, "validationRegistry", deployedRegistry);
        json = vm.serializeUint(key, "timestamp", block.timestamp);
        vm.writeJson(json, outputPath);

        console2.log("Validation registry deployment saved to:", outputPath);
    }
}
