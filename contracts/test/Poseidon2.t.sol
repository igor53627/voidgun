// SPDX-License-Identifier: MIT
pragma solidity ^0.8.31;

import "forge-std/Test.sol";

/// @title Poseidon2 Cross-Language Test Vectors
/// @notice These test vectors are generated from the Rust implementation
/// @dev Run with: forge test -vvv
contract Poseidon2Test is Test {
    address poseidon2;

    function setUp() public {
        // Deploy Poseidon2 contract
        bytes memory bytecode = vm.getCode("Poseidon2.sol:Poseidon2");
        address deployed;
        assembly {
            deployed := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        require(deployed != address(0), "Poseidon2 deployment failed");
        poseidon2 = deployed;
    }

    /// @notice Call Poseidon2 with 3 inputs (for Merkle node: domain=1, left, right)
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

    /// @notice Test Merkle node hash(0, 0) matches Rust sponge construction
    /// @dev hash_merkle_node(0, 0) using sponge with IV = 3 << 64
    function test_MerkleNodeZeros() public view {
        uint256 result = hash3(1, 0, 0);
        uint256 expected = 0x1cf72bfcec8abddcd0f50f42fc920980ff16a6d9b41c5bec9730a165119e45b2;
        assertEq(result, expected, "Merkle node hash(0, 0) mismatch");
    }

    /// @notice Test Merkle node hash(123, 456) matches Rust sponge construction
    function test_MerkleNodeSimple() public view {
        uint256 result = hash3(1, 123, 456);
        uint256 expected = 0x28b21b8baf76eb450729177bf9f1c40afd3fabf99883153c11d8e24d2fdd9386;
        assertEq(result, expected, "Merkle node hash(123, 456) mismatch");
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
}
