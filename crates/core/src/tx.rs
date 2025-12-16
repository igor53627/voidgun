use alloy_primitives::{Address, Bytes, U256, keccak256};

/// Parsed EIP-1559 transaction
#[derive(Clone, Debug)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
}

/// Signed EIP-1559 transaction
#[derive(Clone, Debug)]
pub struct SignedEip1559Tx {
    pub tx: Eip1559Tx,
    pub v: u8,
    pub r: U256,
    pub s: U256,
    /// Raw transaction bytes
    pub raw: Bytes,
}

impl SignedEip1559Tx {
    /// Parse a signed transaction from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TxError> {
        // First byte should be 0x02 for EIP-1559
        if bytes.is_empty() || bytes[0] != 0x02 {
            return Err(TxError::InvalidTxType);
        }
        
        // TODO: Implement full RLP decoding with alloy-consensus
        Err(TxError::DecodingNotImplemented)
    }
    
    /// Get the transaction hash
    pub fn tx_hash(&self) -> [u8; 32] {
        keccak256(&self.raw).0
    }
}

/// Convert a secp256k1 public key bytes to an Ethereum address
pub fn pubkey_to_address(pubkey_bytes: &[u8]) -> Address {
    // Skip the 0x04 prefix if present (uncompressed format)
    let bytes = if pubkey_bytes.len() == 65 && pubkey_bytes[0] == 0x04 {
        &pubkey_bytes[1..]
    } else {
        pubkey_bytes
    };
    
    let hash = keccak256(bytes);
    Address::from_slice(&hash[12..])
}

#[derive(Debug, thiserror::Error)]
pub enum TxError {
    #[error("Invalid transaction type")]
    InvalidTxType,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("RLP decoding not yet implemented")]
    DecodingNotImplemented,
}
