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
}
