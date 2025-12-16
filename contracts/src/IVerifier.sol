// SPDX-License-Identifier: MIT
pragma solidity ^0.8.31;

/// @title IVerifier
/// @notice Interface for zk-SNARK verifier contracts
/// @dev Noir/Barretenberg will generate a concrete implementation
interface IVerifier {
    /// @notice Verify a proof against public inputs
    /// @param proof The serialized proof bytes
    /// @param publicInputs The public inputs to the circuit
    /// @return True if the proof is valid
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool);
}
