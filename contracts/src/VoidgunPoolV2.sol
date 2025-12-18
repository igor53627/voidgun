// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./IVerifier.sol";

/// @title VoidgunPoolV2
/// @notice Privacy pool with separate verifiers for transfer and withdrawal circuits
/// @dev V2 adds support for separate transfer and withdrawal verifiers
contract VoidgunPoolV2 is ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint256 public constant TREE_DEPTH = 20;
    uint256 public constant TREE_CAPACITY = 1 << TREE_DEPTH;
    uint256 public constant ROOT_HISTORY_SIZE = 100;
    
    uint256 private constant DOMAIN_MERKLE_NODE = 2;
    uint256 private constant TRANSFER_PUBLIC_INPUTS_LENGTH = 9;
    uint256 private constant WITHDRAW_PUBLIC_INPUTS_LENGTH = 7;
    
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
    
    /// @notice The verifier contract for transfer proofs
    IVerifier public immutable transferVerifier;
    
    /// @notice The verifier contract for withdrawal proofs
    IVerifier public immutable withdrawalVerifier;
    
    /// @notice The Poseidon2 hasher contract
    address public immutable poseidon2;
    
    /// @notice Pool identifier for cross-pool replay protection
    uint256 public immutable poolId;
    
    uint256 public currentRoot;
    uint256 public nextIndex;
    uint256[ROOT_HISTORY_SIZE] public rootHistory;
    uint256 public rootHistoryIndex;
    mapping(uint256 => bool) public isKnownRoot;
    mapping(uint256 => bool) public nullifiedNotes;
    mapping(uint256 => bool) public nullifiedTxs;
    uint256[TREE_DEPTH] public filledSubtrees;
    uint256[TREE_DEPTH + 1] public zeros;
    
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
    
    constructor(address _transferVerifier, address _withdrawalVerifier, address _poseidon2) {
        if (_transferVerifier == address(0)) revert InvalidVerifierAddress();
        if (_withdrawalVerifier == address(0)) revert InvalidVerifierAddress();
        if (_poseidon2 == address(0)) revert InvalidPoseidon2Address();
        
        transferVerifier = IVerifier(_transferVerifier);
        withdrawalVerifier = IVerifier(_withdrawalVerifier);
        poseidon2 = _poseidon2;
        poolId = uint256(uint160(address(this)));
        
        zeros[0] = 0;
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            zeros[i + 1] = hashPair(zeros[i], zeros[i]);
            filledSubtrees[i] = zeros[i];
        }
        
        currentRoot = zeros[TREE_DEPTH];
        isKnownRoot[currentRoot] = true;
    }
    
    function deposit(
        uint256 commitment,
        uint256 value,
        address token,
        bytes calldata ciphertext
    ) external payable nonReentrant {
        if (value == 0) revert ZeroValueDeposit();
        
        if (token == address(0)) {
            if (msg.value != value) revert IncorrectETHValue();
        } else {
            if (msg.value != 0) revert ETHNotAllowedForERC20();
            IERC20(token).safeTransferFrom(msg.sender, address(this), value);
        }
        
        uint256 leafIndex = _insert(commitment);
        
        emit Deposit(commitment, value, token, ciphertext, leafIndex, currentRoot);
    }
    
    function shieldedTransfer(
        bytes32[] calldata publicInputs,
        bytes calldata proof,
        bytes calldata ciphertextOut,
        bytes calldata ciphertextChange
    ) external nonReentrant {
        if (publicInputs.length != TRANSFER_PUBLIC_INPUTS_LENGTH) revert InvalidPublicInputsLength();
        
        uint256 root = uint256(publicInputs[0]);
        uint256 cmOut = uint256(publicInputs[1]);
        uint256 cmChange = uint256(publicInputs[2]);
        uint256 nfNote = uint256(publicInputs[3]);
        uint256 nfTx = uint256(publicInputs[4]);
        uint256 proofPoolId = uint256(publicInputs[8]);
        
        if (proofPoolId != poolId) revert InvalidPoolId();
        if (!isKnownRoot[root]) revert UnknownRoot();
        if (nullifiedNotes[nfNote]) revert NoteAlreadySpent();
        if (nullifiedTxs[nfTx]) revert TransactionAlreadyUsed();
        
        if (!transferVerifier.verify(proof, publicInputs)) revert InvalidProof();
        
        nullifiedNotes[nfNote] = true;
        nullifiedTxs[nfTx] = true;
        
        uint256 leafIndexOut = _insert(cmOut);
        uint256 leafIndexChange = _insert(cmChange);
        
        emit Transfer(nfNote, nfTx, cmOut, cmChange, leafIndexOut, leafIndexChange, currentRoot, ciphertextOut, ciphertextChange);
    }
    
    function withdraw(
        bytes32[] calldata publicInputs,
        bytes calldata proof,
        address to,
        address token,
        uint256 value
    ) external nonReentrant {
        if (publicInputs.length != WITHDRAW_PUBLIC_INPUTS_LENGTH) revert InvalidPublicInputsLength();
        if (to == address(0)) revert InvalidRecipient();
        
        uint256 root = uint256(publicInputs[0]);
        uint256 nfNote = uint256(publicInputs[1]);
        uint256 nfTx = uint256(publicInputs[2]);
        uint256 proofValue = uint256(publicInputs[3]);
        uint256 proofTokenType = uint256(publicInputs[4]);
        uint256 proofRecipient = uint256(publicInputs[5]);
        uint256 proofPoolId = uint256(publicInputs[6]);
        
        if (proofPoolId != poolId) revert InvalidPoolId();
        if (proofRecipient != uint256(uint160(to))) revert RecipientMismatch();
        if (proofValue != value) revert ValueMismatch();
        if (proofTokenType != uint256(uint160(token))) revert TokenMismatch();
        if (!isKnownRoot[root]) revert UnknownRoot();
        if (nullifiedNotes[nfNote]) revert NoteAlreadySpent();
        if (nullifiedTxs[nfTx]) revert TransactionAlreadyUsed();
        
        if (!withdrawalVerifier.verify(proof, publicInputs)) revert InvalidProof();
        
        nullifiedNotes[nfNote] = true;
        nullifiedTxs[nfTx] = true;
        
        if (token == address(0)) {
            (bool success, ) = to.call{value: value}("");
            if (!success) revert ETHTransferFailed();
        } else {
            IERC20(token).safeTransfer(to, value);
        }
        
        emit Withdrawal(nfNote, nfTx, to, value, token);
    }
    
    function getLeafCount() external view returns (uint256) {
        return nextIndex;
    }
    
    function hasCapacity() external view returns (bool) {
        return nextIndex < TREE_CAPACITY;
    }
    
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
        
        uint256 evictedRoot = rootHistory[rootHistoryIndex];
        if (evictedRoot != currentRoot && evictedRoot != 0) {
            isKnownRoot[evictedRoot] = false;
        }
        
        currentRoot = currentHash;
        isKnownRoot[currentRoot] = true;
        rootHistory[rootHistoryIndex] = currentRoot;
        rootHistoryIndex = (rootHistoryIndex + 1) % ROOT_HISTORY_SIZE;
        nextIndex = index + 1;
    }
    
    function hashPair(uint256 left, uint256 right) internal view returns (uint256 result) {
        address hasher = poseidon2;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, DOMAIN_MERKLE_NODE)
            mstore(add(ptr, 0x20), left)
            mstore(add(ptr, 0x40), right)
            
            let success := staticcall(gas(), hasher, ptr, 0x60, ptr, 0x20)
            if iszero(success) {
                mstore(0x00, 0x5845ba0b)
                revert(0x1c, 0x04)
            }
            
            result := mload(ptr)
        }
    }
}
