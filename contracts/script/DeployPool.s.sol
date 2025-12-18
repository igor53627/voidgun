// SPDX-License-Identifier: MIT
pragma solidity ^0.8.31;

import {Script, console} from "forge-std/Script.sol";
import {VoidgunPool} from "../src/VoidgunPool.sol";
import {Poseidon2Yul} from "../src/Poseidon2.sol";

/// @notice Deploy VoidgunPool with a pre-deployed verifier
contract DeployPoolScript is Script {
    function run(address verifier) external {
        vm.startBroadcast();
        
        // Deploy Poseidon2
        Poseidon2Yul poseidon2 = new Poseidon2Yul();
        console.log("Poseidon2 deployed at:", address(poseidon2));
        
        // Deploy VoidgunPool
        VoidgunPool pool = new VoidgunPool(verifier, address(poseidon2));
        console.log("VoidgunPool deployed at:", address(pool));
        console.log("Pool ID:", pool.poolId());
        
        vm.stopBroadcast();
    }
}
