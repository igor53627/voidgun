// SPDX-License-Identifier: MIT
pragma solidity ^0.8.31;

import {Script, console} from "forge-std/Script.sol";
import {VoidgunPool} from "../src/VoidgunPool.sol";
import {Poseidon2Yul} from "../src/Poseidon2.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);
        
        // 1. Deploy Poseidon2
        Poseidon2Yul poseidon2 = new Poseidon2Yul();
        console.log("Poseidon2 deployed at:", address(poseidon2));
        
        // 2. Deploy ZKTranscriptLib (required by HonkVerifier)
        bytes memory libBytecode = vm.parseBytes(vm.readFile("verifier/compiled/ZKTranscriptLib.bin"));
        address zkTranscriptLib;
        assembly {
            zkTranscriptLib := create(0, add(libBytecode, 0x20), mload(libBytecode))
        }
        require(zkTranscriptLib != address(0), "ZKTranscriptLib deployment failed");
        console.log("ZKTranscriptLib deployed at:", zkTranscriptLib);
        
        // 3. Deploy HonkVerifier
        // Read pre-linked bytecode (generated with library address embedded)
        // Run: ./scripts/link-verifier.sh <lib_address> to generate linked bytecode
        bytes memory verifierBytecode = vm.parseBytes(vm.readFile("verifier/compiled/HonkVerifier.linked.bin"));
        address verifier;
        assembly {
            verifier := create(0, add(verifierBytecode, 0x20), mload(verifierBytecode))
        }
        require(verifier != address(0), "HonkVerifier deployment failed");
        console.log("HonkVerifier deployed at:", verifier);
        
        // 4. Deploy VoidgunPool
        VoidgunPool pool = new VoidgunPool(verifier, address(poseidon2));
        console.log("VoidgunPool deployed at:", address(pool));
        console.log("Pool ID:", pool.poolId());
        
        vm.stopBroadcast();
    }
}
