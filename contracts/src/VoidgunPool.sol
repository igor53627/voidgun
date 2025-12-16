// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./IVerifier.sol";

/// @title VoidgunPool
/// @notice Privacy pool for shielded transfers using zk-SNARKs
/// @dev Implements "proxy without spending authority" model from Nullmask paper
contract VoidgunPool is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ============================================
    // Constants
    // ============================================
    
    uint256 public constant TREE_DEPTH = 20;
    uint256 public constant TREE_CAPACITY = 1 << TREE_DEPTH;
    uint256 public constant ROOT_HISTORY_SIZE = 100;
    
    /// @notice Domain separation tag for Merkle node hashing
    /// Must match Noir circuit: DOMAIN_MERKLE_NODE = 2
    uint256 private constant DOMAIN_MERKLE_NODE = 2;
    
    /// @notice Expected public inputs length for shielded transfer
    /// [root, cmOut, cmChange, nfNote, nfTx, gasTip, gasFeeCap, tokenType, poolId]
    uint256 private constant TRANSFER_PUBLIC_INPUTS_LENGTH = 9;
    
    /// @notice Expected public inputs length for withdrawal
    /// [root, nfNote, nfTx, value, tokenType, recipient, poolId]
    uint256 private constant WITHDRAW_PUBLIC_INPUTS_LENGTH = 7;
    
    // ============================================
    // Errors
    // ============================================
    
    error InvalidVerifierAddress();
    error InvalidPoseidon2Address();
    error ZeroValueDeposit();
    error ETHNotAllowedForERC20();
    error IncorrectETHValue();
    error MerkleTreeFull();
    error UnknownRoot();
    error NoteAlreadySpent();
    error TransactionAlreadyUsed();
    error InvalidProof();
    error InvalidPublicInputsLength();
    error InvalidPoolId();
    error ValueMismatch();
    error TokenMismatch();
    error RecipientMismatch();
    error InvalidRecipient();
    error ETHTransferFailed();
    error Poseidon2CallFailed();
    
    // ============================================
    // State
    // ============================================
    
    /// @notice The verifier contract for zk proofs
    IVerifier public immutable verifier;
    
    /// @notice The Poseidon2 hasher contract
    address public immutable poseidon2;
    
    /// @notice Pool identifier for cross-pool replay protection
    /// Derived from contract address
    uint256 public immutable poolId;
    
    /// @notice Current Merkle root
    uint256 public currentRoot;
    
    /// @notice Next leaf index in the Merkle tree
    uint256 public nextIndex;
    
    /// @notice Ring buffer of recent roots for proof validity window
    uint256[ROOT_HISTORY_SIZE] public rootHistory;
    
    /// @notice Current index in root history ring buffer
    uint256 public rootHistoryIndex;
    
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
        uint256 leafIndexOut,
        uint256 leafIndexChange,
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
        if (_verifier == address(0)) revert InvalidVerifierAddress();
        if (_poseidon2 == address(0)) revert InvalidPoseidon2Address();
        
        verifier = IVerifier(_verifier);
        poseidon2 = _poseidon2;
        poolId = uint256(uint160(address(this)));
        
        // Initialize zero values for empty tree
        zeros[0] = 0;
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            zeros[i + 1] = hashPair(zeros[i], zeros[i]);
            filledSubtrees[i] = zeros[i];
        }
        
        currentRoot = zeros[TREE_DEPTH];
        isKnownRoot[currentRoot] = true;
        
        // Initialize root history with empty root
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            rootHistory[i] = currentRoot;
        }
    }
    
    // ============================================
    // External Functions
    // ============================================
    
    /// @notice Deposit tokens into the shielded pool
    /// @param commitment Note commitment
    /// @param value Amount to deposit
    /// @param token Token address (address(0) for ETH)
    /// @param ciphertext Encrypted note data
    function deposit(
        uint256 commitment,
        uint256 value,
        address token,
        bytes calldata ciphertext
    ) external payable nonReentrant {
        if (value == 0) revert ZeroValueDeposit();
        
        if (token == address(0)) {
            // ETH deposit
            if (msg.value != value) revert IncorrectETHValue();
        } else {
            // ERC20 deposit
            if (msg.value != 0) revert ETHNotAllowedForERC20();
            IERC20(token).safeTransferFrom(msg.sender, address(this), value);
        }
        
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
    ///        [root, cmOut, cmChange, nfNote, nfTx, gasTip, gasFeeCap, tokenType, poolId]
    /// @param proof The zk proof bytes
    /// @param ciphertextOut Encrypted output note
    /// @param ciphertextChange Encrypted change note
    function shieldedTransfer(
        uint256[] calldata publicInputs,
        bytes calldata proof,
        bytes calldata ciphertextOut,
        bytes calldata ciphertextChange
    ) external nonReentrant {
        if (publicInputs.length != TRANSFER_PUBLIC_INPUTS_LENGTH) revert InvalidPublicInputsLength();
        
        uint256 root = publicInputs[0];
        uint256 cmOut = publicInputs[1];
        uint256 cmChange = publicInputs[2];
        uint256 nfNote = publicInputs[3];
        uint256 nfTx = publicInputs[4];
        // gasTip = publicInputs[5];
        // gasFeeCap = publicInputs[6];
        // tokenType = publicInputs[7];
        uint256 proofPoolId = publicInputs[8];
        
        // Verify pool binding
        if (proofPoolId != poolId) revert InvalidPoolId();
        
        // Verify the root is known
        if (!isKnownRoot[root]) revert UnknownRoot();
        
        // Verify nullifiers haven't been used
        if (nullifiedNotes[nfNote]) revert NoteAlreadySpent();
        if (nullifiedTxs[nfTx]) revert TransactionAlreadyUsed();
        
        // Verify the proof
        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();
        
        // Mark nullifiers as used
        nullifiedNotes[nfNote] = true;
        nullifiedTxs[nfTx] = true;
        
        // Insert new commitments
        uint256 leafIndexOut = _insert(cmOut);
        uint256 leafIndexChange = _insert(cmChange);
        
        emit Transfer(
            nfNote,
            nfTx,
            cmOut,
            cmChange,
            leafIndexOut,
            leafIndexChange,
            currentRoot,
            ciphertextOut,
            ciphertextChange
        );
    }
    
    /// @notice Withdraw tokens from the shielded pool
    /// @param publicInputs Array of public inputs for withdrawal circuit
    ///        [root, nfNote, nfTx, value, tokenType, recipient, poolId]
    /// @param proof The zk proof bytes
    /// @param to Recipient address (must match proof)
    /// @param token Token address
    /// @param value Amount to withdraw
    function withdraw(
        uint256[] calldata publicInputs,
        bytes calldata proof,
        address to,
        address token,
        uint256 value
    ) external nonReentrant {
        if (publicInputs.length != WITHDRAW_PUBLIC_INPUTS_LENGTH) revert InvalidPublicInputsLength();
        if (to == address(0)) revert InvalidRecipient();
        
        uint256 root = publicInputs[0];
        uint256 nfNote = publicInputs[1];
        uint256 nfTx = publicInputs[2];
        uint256 proofValue = publicInputs[3];
        uint256 proofTokenType = publicInputs[4];
        uint256 proofRecipient = publicInputs[5];
        uint256 proofPoolId = publicInputs[6];
        
        // Verify pool binding
        if (proofPoolId != poolId) revert InvalidPoolId();
        
        // Verify recipient matches proof (prevents relayer from redirecting funds)
        if (proofRecipient != uint256(uint160(to))) revert RecipientMismatch();
        
        // Verify value matches proof
        if (proofValue != value) revert ValueMismatch();
        
        // Verify token matches proof (token type is address as uint256)
        if (proofTokenType != uint256(uint160(token))) revert TokenMismatch();
        
        // Verify root and nullifiers
        if (!isKnownRoot[root]) revert UnknownRoot();
        if (nullifiedNotes[nfNote]) revert NoteAlreadySpent();
        if (nullifiedTxs[nfTx]) revert TransactionAlreadyUsed();
        
        // Verify the proof
        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();
        
        // Mark nullifiers as used
        nullifiedNotes[nfNote] = true;
        nullifiedTxs[nfTx] = true;
        
        // Transfer funds
        if (token == address(0)) {
            (bool success, ) = to.call{value: value}("");
            if (!success) revert ETHTransferFailed();
        } else {
            IERC20(token).safeTransfer(to, value);
        }
        
        emit Withdrawal(nfNote, nfTx, to, value, token);
    }
    
    // ============================================
    // View Functions
    // ============================================
    
    /// @notice Get the current number of leaves in the tree
    function getLeafCount() external view returns (uint256) {
        return nextIndex;
    }
    
    /// @notice Check if the tree has capacity for more deposits
    function hasCapacity() external view returns (bool) {
        return nextIndex < TREE_CAPACITY;
    }
    
    // ============================================
    // Internal Functions
    // ============================================
    
    /// @notice Insert a leaf into the Merkle tree
    function _insert(uint256 leaf) internal returns (uint256 index) {
        if (nextIndex >= TREE_CAPACITY) revert MerkleTreeFull();
        
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
        
        // Evict old root from validity set
        uint256 evictedRoot = rootHistory[rootHistoryIndex];
        if (evictedRoot != currentRoot && evictedRoot != 0) {
            isKnownRoot[evictedRoot] = false;
        }
        
        // Update current root
        currentRoot = currentHash;
        isKnownRoot[currentRoot] = true;
        
        // Add to ring buffer
        rootHistory[rootHistoryIndex] = currentRoot;
        rootHistoryIndex = (rootHistoryIndex + 1) % ROOT_HISTORY_SIZE;
        
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
            if iszero(success) {
                mstore(0x00, 0x8e4a23d6) // Poseidon2CallFailed()
                revert(0x1c, 0x04)
            }
            
            result := mload(ptr)
        }
    }
}
