// SPDX-License-Identifier: MIT
pragma solidity ^0.8.31;

import {Script, console} from "forge-std/Script.sol";
import {VoidgunPoolV2} from "../src/VoidgunPoolV2.sol";
import {Poseidon2Yul} from "../src/Poseidon2.sol";

contract DeployV2Script is Script {
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
        
        // 3. Deploy Transfer Verifier
        bytes memory transferVerifierBytecode = vm.parseBytes(vm.readFile("verifier/compiled/TransferVerifier.linked.bin"));
        address transferVerifier;
        assembly {
            transferVerifier := create(0, add(transferVerifierBytecode, 0x20), mload(transferVerifierBytecode))
        }
        require(transferVerifier != address(0), "TransferVerifier deployment failed");
        console.log("TransferVerifier deployed at:", transferVerifier);
        
        // 4. Deploy Withdrawal Verifier
        bytes memory withdrawalVerifierBytecode = vm.parseBytes(vm.readFile("verifier/compiled/WithdrawalVerifier.linked.bin"));
        address withdrawalVerifier;
        assembly {
            withdrawalVerifier := create(0, add(withdrawalVerifierBytecode, 0x20), mload(withdrawalVerifierBytecode))
        }
        require(withdrawalVerifier != address(0), "WithdrawalVerifier deployment failed");
        console.log("WithdrawalVerifier deployed at:", withdrawalVerifier);
        
        // 5. Deploy VoidgunPoolV2
        VoidgunPoolV2 pool = new VoidgunPoolV2(transferVerifier, withdrawalVerifier, address(poseidon2));
        console.log("VoidgunPoolV2 deployed at:", address(pool));
        console.log("Pool ID:", pool.poolId());
        
        vm.stopBroadcast();
    }
}
