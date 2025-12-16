// SPDX-License-Identifier: MIT
pragma solidity ^0.8.31;

import "./IVerifier.sol";

/// @title VoidgunPool
/// @notice Privacy pool for shielded transfers using zk-SNARKs
/// @dev Implements "proxy without spending authority" model from Nullmask paper
contract VoidgunPool {
    // ============================================
    // Constants
    // ============================================
    
    uint256 public constant TREE_DEPTH = 20;
    uint256 public constant ROOT_HISTORY_SIZE = 100;
    
    /// @notice Domain separation tag for Merkle node hashing
    /// Must match Noir circuit: DOMAIN_MERKLE_NODE = 2
    uint256 private constant DOMAIN_MERKLE_NODE = 2;
    
    // ============================================
    // State
    // ============================================
    
    /// @notice The verifier contract for zk proofs
    IVerifier public immutable verifier;
    
    /// @notice The Poseidon2 hasher contract
    address public immutable poseidon2;
    
    /// @notice Current Merkle root
    uint256 public currentRoot;
    
    /// @notice Next leaf index in the Merkle tree
    uint256 public nextIndex;
    
    /// @notice Mapping of known roots (for proof validity window)
    mapping(uint256 => bool) public isKnownRoot;
    
    /// @notice Set of used note nullifiers
    mapping(uint256 => bool) public nullifiedNotes;
    
    /// @notice Set of used transaction nullifiers
    mapping(uint256 => bool) public nullifiedTxs;
    
    /// @notice Filled subtrees at each level (for incremental tree)
    uint256[TREE_DEPTH] public filledSubtrees;
    
    /// @notice Zero values at each level
    uint256[TREE_DEPTH + 1] public zeros;
    
    // ============================================
    // Events
    // ============================================
    
    event Deposit(
        uint256 indexed commitment,
        uint256 value,
        address indexed token,
        bytes ciphertext,
        uint256 leafIndex,
        uint256 newRoot
    );
    
    event Transfer(
        uint256 indexed nfNote,
        uint256 indexed nfTx,
        uint256 cmOut,
        uint256 cmChange,
        uint256 newRoot,
        bytes ciphertextOut,
        bytes ciphertextChange
    );
    
    event Withdrawal(
        uint256 indexed nfNote,
        uint256 indexed nfTx,
        address indexed to,
        uint256 value,
        address token
    );
    
    // ============================================
    // Constructor
    // ============================================
    
    constructor(address _verifier, address _poseidon2) {
        require(_verifier != address(0), "Invalid verifier address");
        require(_poseidon2 != address(0), "Invalid Poseidon2 address");
        verifier = IVerifier(_verifier);
        poseidon2 = _poseidon2;
        
        // Initialize zero values for empty tree
        zeros[0] = 0;
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            zeros[i + 1] = hashPair(zeros[i], zeros[i]);
            filledSubtrees[i] = zeros[i];
        }
        
        currentRoot = zeros[TREE_DEPTH];
        isKnownRoot[currentRoot] = true;
    }
    
    // ============================================
    // External Functions
    // ============================================
    
    /// @notice Deposit tokens into the shielded pool
    /// @param commitment Note commitment
    /// @param token Token address (address(0) for ETH)
    /// @param ciphertext Encrypted note data
    function deposit(
        uint256 commitment,
        address token,
        bytes calldata ciphertext
    ) external payable {
        uint256 value;
        
        if (token == address(0)) {
            // ETH deposit
            value = msg.value;
        } else {
            // ERC20 deposit
            // TODO: Implement ERC20 transfer
            revert("ERC20 not yet implemented");
        }
        
        require(value > 0, "Zero value deposit");
        
        // Insert commitment into Merkle tree
        uint256 leafIndex = _insert(commitment);
        
        emit Deposit(
            commitment,
            value,
            token,
            ciphertext,
            leafIndex,
            currentRoot
        );
    }
    
    /// @notice Execute a shielded transfer
    /// @param publicInputs Array of public inputs for the circuit
    ///        [root, cmOut, cmChange, nfNote, nfTx, gasTip, gasFeeCap, tokenType]
    /// @param proof The zk proof bytes
    /// @param ciphertextOut Encrypted output note
    /// @param ciphertextChange Encrypted change note
    function shieldedTransfer(
        uint256[] calldata publicInputs,
        bytes calldata proof,
        bytes calldata ciphertextOut,
        bytes calldata ciphertextChange
    ) external {
        require(publicInputs.length == 8, "Invalid public inputs length");
        
        uint256 root = publicInputs[0];
        uint256 cmOut = publicInputs[1];
        uint256 cmChange = publicInputs[2];
        uint256 nfNote = publicInputs[3];
        uint256 nfTx = publicInputs[4];
        // gasTip = publicInputs[5];
        // gasFeeCap = publicInputs[6];
        // tokenType = publicInputs[7];
        
        // Verify the root is known
        require(isKnownRoot[root], "Unknown root");
        
        // Verify nullifiers haven't been used
        require(!nullifiedNotes[nfNote], "Note already spent");
        require(!nullifiedTxs[nfTx], "Transaction already used");
        
        // Verify the proof
        require(verifier.verify(proof, publicInputs), "Invalid proof");
        
        // Mark nullifiers as used
        nullifiedNotes[nfNote] = true;
        nullifiedTxs[nfTx] = true;
        
        // Insert new commitments
        _insert(cmOut);
        _insert(cmChange);
        
        emit Transfer(
            nfNote,
            nfTx,
            cmOut,
            cmChange,
            currentRoot,
            ciphertextOut,
            ciphertextChange
        );
    }
    
    /// @notice Withdraw tokens from the shielded pool
    /// @param publicInputs Array of public inputs for withdrawal circuit
    /// @param proof The zk proof bytes
    /// @param to Recipient address
    /// @param token Token address
    /// @param value Amount to withdraw
    function withdraw(
        uint256[] calldata publicInputs,
        bytes calldata proof,
        address to,
        address token,
        uint256 value
    ) external {
        require(publicInputs.length >= 5, "Invalid public inputs");
        
        uint256 root = publicInputs[0];
        uint256 nfNote = publicInputs[1];
        uint256 nfTx = publicInputs[2];
        
        // Verify root and nullifiers
        require(isKnownRoot[root], "Unknown root");
        require(!nullifiedNotes[nfNote], "Note already spent");
        require(!nullifiedTxs[nfTx], "Transaction already used");
        
        // Verify the proof
        require(verifier.verify(proof, publicInputs), "Invalid proof");
        
        // Mark nullifiers as used
        nullifiedNotes[nfNote] = true;
        nullifiedTxs[nfTx] = true;
        
        // Transfer funds
        if (token == address(0)) {
            (bool success, ) = to.call{value: value}("");
            require(success, "ETH transfer failed");
        } else {
            // TODO: Implement ERC20 transfer
            revert("ERC20 not yet implemented");
        }
        
        emit Withdrawal(nfNote, nfTx, to, value, token);
    }
    
    // ============================================
    // Internal Functions
    // ============================================
    
    /// @notice Insert a leaf into the Merkle tree
    function _insert(uint256 leaf) internal returns (uint256 index) {
        index = nextIndex;
        uint256 currentIndex = index;
        uint256 currentHash = leaf;
        
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            if (currentIndex % 2 == 0) {
                filledSubtrees[i] = currentHash;
                currentHash = hashPair(currentHash, zeros[i]);
            } else {
                currentHash = hashPair(filledSubtrees[i], currentHash);
            }
            currentIndex /= 2;
        }
        
        currentRoot = currentHash;
        isKnownRoot[currentRoot] = true;
        nextIndex = index + 1;
    }
    
    /// @notice Hash two values together using Poseidon2 with domain separation
    /// @dev Uses Poseidon2Yul sponge: IV = (3 << 64), absorbs [DOMAIN_MERKLE_NODE, left, right]
    /// This matches Noir circuit: Poseidon2::hash([DOMAIN_MERKLE_NODE, left, right], 3)
    /// and Rust: sponge_hash(&[DOMAIN_MERKLE_NODE, left, right])
    function hashPair(uint256 left, uint256 right) internal view returns (uint256 result) {
        address hasher = poseidon2;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, DOMAIN_MERKLE_NODE)
            mstore(add(ptr, 0x20), left)
            mstore(add(ptr, 0x40), right)
            
            let success := staticcall(gas(), hasher, ptr, 0x60, ptr, 0x20)
            if iszero(success) { revert(0, 0) }
            
            result := mload(ptr)
        }
    }
}
