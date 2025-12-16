use alloy_primitives::{Address, U256};

/// Configuration for VoidgunPool contract
#[derive(Clone, Debug)]
pub struct VoidgunPoolConfig {
    /// Deployed pool contract address
    pub pool_address: Address,
    /// Deployed verifier contract address  
    pub verifier_address: Address,
    /// Chain ID
    pub chain_id: u64,
    /// Merkle tree depth
    pub tree_depth: u32,
}

/// Deposit event data
#[derive(Clone, Debug)]
pub struct DepositEvent {
    pub commitment: U256,
    pub value: U256,
    pub token: Address,
    pub ciphertext: Vec<u8>,
    pub leaf_index: u64,
    pub new_root: U256,
}

/// Transfer event data
#[derive(Clone, Debug)]
pub struct TransferEvent {
    pub nf_note: U256,
    pub nf_tx: U256,
    pub cm_out: U256,
    pub cm_change: U256,
    pub new_root: U256,
    pub ciphertext_out: Vec<u8>,
    pub ciphertext_change: Vec<u8>,
}

/// Withdrawal event data
#[derive(Clone, Debug)]
pub struct WithdrawalEvent {
    pub nf_note: U256,
    pub nf_tx: U256,
    pub to: Address,
    pub value: U256,
    pub token: Address,
}
