// SPDX-License-Identifier: MIT
pragma solidity ^0.8.31;

import "forge-std/Test.sol";

/// @title Poseidon2 Cross-Language Test Vectors
/// @notice These test vectors are generated from the Rust implementation
/// @dev Run with: forge test -vvv
contract Poseidon2Test is Test {
    address poseidon2;

    function setUp() public {
        bytes memory bytecode = vm.getCode("Poseidon2.sol:Poseidon2Yul");
        address deployed;
        assembly {
            deployed := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        require(deployed != address(0), "Poseidon2Yul deployment failed");
        poseidon2 = deployed;
    }

    /// @notice Call Poseidon2 with 3 inputs (for Merkle node: domain=2, left, right)
    function hash3(uint256 a, uint256 b, uint256 c) internal view returns (uint256 result) {
        bytes memory input = abi.encodePacked(a, b, c);
        (bool success, bytes memory output) = poseidon2.staticcall(input);
        require(success, "Poseidon2 call failed");
        result = abi.decode(output, (uint256));
    }

    /// @notice Call Poseidon2 with 4 inputs
    function hash4(uint256 a, uint256 b, uint256 c, uint256 d) internal view returns (uint256 result) {
        bytes memory input = abi.encodePacked(a, b, c, d);
        (bool success, bytes memory output) = poseidon2.staticcall(input);
        require(success, "Poseidon2 call failed");
        result = abi.decode(output, (uint256));
    }

    /// @notice Test Merkle node hash(0, 0)
    /// @dev All implementations (Noir, Rust, Solidity) now use sponge: IV = num_inputs << 64
    function test_MerkleNodeZeros() public view {
        uint256 result = hash3(2, 0, 0);
        // Poseidon2Yul sponge output for hash(2, 0, 0)
        assertTrue(result != 0, "Hash should produce non-zero output");
    }

    /// @notice Test Merkle node hash(123, 456)
    /// @dev Solidity uses yolo's Poseidon2Yul sponge construction
    function test_MerkleNodeSimple() public view {
        uint256 result = hash3(2, 123, 456);
        assertTrue(result != 0, "Hash should produce non-zero output");
    }

    /// @notice Test 4-input hash (used for nullifiers and key derivation)
    function test_Hash4Inputs() public view {
        uint256 result = hash4(2, 100, 200, 300);
        assertTrue(result != 0, "Hash4 should produce non-zero output");
    }

    /// @notice Test that unaligned input (not 32-byte aligned) reverts
    function test_RejectsUnalignedInput() public {
        bytes memory unaligned = new bytes(33);
        (bool success,) = poseidon2.staticcall(unaligned);
        assertFalse(success, "Should reject unaligned input");
    }

    /// @notice Test single 32-byte input
    function test_SingleInput() public view {
        bytes memory input = abi.encodePacked(uint256(42));
        (bool success, bytes memory output) = poseidon2.staticcall(input);
        assertTrue(success, "Single input should succeed");
        uint256 result = abi.decode(output, (uint256));
        assertTrue(result != 0, "Single input hash should be non-zero");
    }

    /// @notice Test empty input handling - returns zero (identity element)
    function test_EmptyInput() public view {
        bytes memory empty = new bytes(0);
        (bool success, bytes memory output) = poseidon2.staticcall(empty);
        assertTrue(success, "Empty input should succeed");
        uint256 result = abi.decode(output, (uint256));
        assertEq(result, 0, "Empty input should return zero");
    }

    /// @notice Cross-language test vectors - must match Rust and Noir implementations
    /// @dev These vectors are generated from the Rust poseidon2.rs implementation
    function test_CrossLanguageVectors() public view {
        uint256 merkle_00 = hash3(2, 0, 0);
        assertEq(
            merkle_00,
            0x1218536453df604871fd18460a1d5c2abf9d9cfcda586312bfc3b78d75e29cf0,
            "merkle_node(0,0) must match Rust/Noir"
        );

        uint256 merkle_123_456 = hash3(2, 123, 456);
        assertEq(
            merkle_123_456,
            0x24cbf5ece05503c37381b5d7dfcaf96fe2aca3749cb1a5d4d2f5264e40872fa2,
            "merkle_node(123,456) must match Rust/Noir"
        );

        bytes memory input = abi.encodePacked(uint256(1), uint256(2), uint256(3));
        (bool success, bytes memory output) = poseidon2.staticcall(input);
        assertTrue(success, "hash([1,2,3]) call failed");
        uint256 hash_1_2_3 = abi.decode(output, (uint256));
        assertEq(
            hash_1_2_3,
            0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8,
            "sponge_hash([1,2,3]) must match Rust/Noir"
        );
    }
}
