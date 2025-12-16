use alloy_primitives::{Address, Bytes, U256};
use std::sync::Arc;
use thiserror::Error;

use crate::config::VoidgunConfig;
use crate::storage::VoidgunStorage;
use voidgun_core::NoteInfo;

/// Voidgun RPC API implementation
pub struct VoidgunRpc {
    config: VoidgunConfig,
    storage: Arc<VoidgunStorage>,
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Not implemented")]
    NotImplemented,
    
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    
    #[error("Insufficient balance")]
    InsufficientBalance,
    
    #[error("Proof generation failed: {0}")]
    ProofFailed(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
}

impl VoidgunRpc {
    pub fn new(config: VoidgunConfig, storage: Arc<VoidgunStorage>) -> Self {
        Self { config, storage }
    }
    
    /// Send a shielded transaction
    /// 
    /// Takes a wallet-signed EIP-1559 transaction and:
    /// 1. Parses and validates it
    /// 2. Looks up recipient's receiving key
    /// 3. Selects funding notes
    /// 4. Generates zk proof
    /// 5. Submits VoidgunPool.shieldedTransfer
    pub async fn send_transaction(&self, _raw_tx: Bytes) -> Result<Bytes, RpcError> {
        tracing::info!("void_sendTransaction called");
        
        // TODO: Implement full flow
        // 1. Parse the signed tx
        // 2. Recover signer
        // 3. Look up sender's viewing key and notes
        // 4. Look up recipient's receiving key
        // 5. Build witness
        // 6. Generate proof
        // 7. Build and submit pool tx
        
        Err(RpcError::NotImplemented)
    }
    
    /// Get shielded balance for an address
    pub async fn get_balance(
        &self,
        addr: Address,
        token: Option<Address>,
    ) -> Result<U256, RpcError> {
        let notes = self.storage.get_unspent_notes(addr)
            .map_err(|e| RpcError::StorageError(e.to_string()))?;
        
        let token_filter = token.unwrap_or(Address::ZERO);
        let total: U256 = notes
            .iter()
            .filter(|n| n.token_type == token_filter)
            .map(|n| n.value)
            .fold(U256::ZERO, |acc, v| acc + v);
        
        Ok(total)
    }
    
    /// List all unspent notes for an address
    pub async fn list_notes(&self, addr: Address) -> Result<Vec<NoteInfo>, RpcError> {
        self.storage.get_unspent_notes(addr)
            .map_err(|e| RpcError::StorageError(e.to_string()))
    }
    
    /// Initialize a new voidgun account
    /// 
    /// Takes the EXPORT_VK_MESSAGE signature and derives viewing/receiving keys
    pub async fn init_account(
        &self,
        _addr: Address,
        _signature: Bytes,
    ) -> Result<(), RpcError> {
        tracing::info!("void_initAccount called");
        
        // TODO: Implement key derivation and storage
        // 1. Recover public key from signature
        // 2. Derive viewing key
        // 3. Derive receiving key
        // 4. Store viewing key locally
        // 5. Optionally publish receiving key to key server
        
        Err(RpcError::NotImplemented)
    }
}
