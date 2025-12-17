// SPDX-License-Identifier: MIT
pragma solidity ^0.8.31;

/// @title IVerifier
/// @notice Interface for zk-SNARK verifier contracts
/// @dev Noir/Barretenberg generates HonkVerifier with bytes32[] public inputs
interface IVerifier {
    /// @notice Verify a proof against public inputs
    /// @param proof The serialized proof bytes
    /// @param publicInputs The public inputs to the circuit (as bytes32[])
    /// @return True if the proof is valid
    function verify(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external view returns (bool);
}
