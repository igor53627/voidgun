use alloy_sol_types::sol;

// TODO: Generate actual bindings from compiled Solidity
// For now, define the interface manually

sol! {
    /// VoidgunPool interface
    #[derive(Debug)]
    interface IVoidgunPool {
        /// Deposit tokens into the shielded pool
        function deposit(
            uint256 commitment,
            uint256 value,
            address token,
            bytes calldata ciphertext
        ) external payable;
        
        /// Execute a shielded transfer
        function shieldedTransfer(
            uint256[] calldata publicInputs,
            bytes calldata proof,
            bytes calldata ciphertextOut,
            bytes calldata ciphertextChange
        ) external;
        
        /// Withdraw tokens from the shielded pool
        function withdraw(
            uint256[] calldata publicInputs,
            bytes calldata proof,
            address to,
            address token,
            uint256 value
        ) external;
        
        /// Check if a root is known
        function isKnownRoot(uint256 root) external view returns (bool);
        
        /// Check if a note nullifier has been used
        function isNullifiedNote(uint256 nullifier) external view returns (bool);
        
        /// Check if a tx nullifier has been used
        function isNullifiedTx(uint256 nullifier) external view returns (bool);
        
        /// Get current merkle root
        function currentRoot() external view returns (uint256);
        
        /// Events
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
    }
}
