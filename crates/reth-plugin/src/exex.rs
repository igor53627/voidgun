use alloy_primitives::Address;
use ark_bn254::Fr as Field;
use ark_ff::PrimeField;
use std::sync::Arc;

use crate::config::VoidgunConfig;
use crate::storage::VoidgunStorage;
use voidgun_contracts::{DepositEvent, TransferEvent, WithdrawalEvent};
use voidgun_core::MerkleTree;

/// ExEx (Execution Extension) for scanning VoidgunPool events
/// 
/// This component:
/// 1. Subscribes to new blocks
/// 2. Filters logs for VoidgunPool events
/// 3. Updates local Merkle tree and nullifier sets
/// 4. Trial-decrypts notes for managed viewing keys
pub struct VoidgunExEx {
    config: VoidgunConfig,
    storage: Arc<VoidgunStorage>,
    merkle_tree: MerkleTree,
}

impl VoidgunExEx {
    pub fn new(config: VoidgunConfig, storage: Arc<VoidgunStorage>) -> Self {
        Self {
            config,
            storage,
            merkle_tree: MerkleTree::new(),
        }
    }
    
    /// Process a new block
    pub async fn process_block(
        &mut self,
        _block_number: u64,
        logs: Vec<RawLog>,
    ) -> eyre::Result<()> {
        for log in logs {
            if log.address != self.config.pool_address {
                continue;
            }
            
            // TODO: Decode and process events
            // - Deposit: add commitment to tree, try decrypt note
            // - Transfer: add commitments, mark nullifiers, try decrypt
            // - Withdrawal: mark nullifiers
        }
        
        Ok(())
    }
    
    /// Handle a Deposit event
    pub fn handle_deposit(&mut self, event: DepositEvent) -> eyre::Result<()> {
        // Add commitment to Merkle tree
        let cm = Field::from_be_bytes_mod_order(&event.commitment.to_be_bytes::<32>());
        let index = self.merkle_tree.insert(cm);
        
        // Store new root
        self.storage.add_known_root(self.merkle_tree.root())?;
        
        // Try to decrypt the note for all known viewing keys
        self.try_decrypt_note(&event.ciphertext, index)?;
        
        tracing::info!(
            "Processed deposit: cm={:?}, index={}, new_root={:?}",
            event.commitment,
            index,
            self.merkle_tree.root()
        );
        
        Ok(())
    }
    
    /// Handle a Transfer event
    pub fn handle_transfer(&mut self, event: TransferEvent) -> eyre::Result<()> {
        // Mark nullifiers as used
        let nf_note = Field::from_be_bytes_mod_order(&event.nf_note.to_be_bytes::<32>());
        let nf_tx = Field::from_be_bytes_mod_order(&event.nf_tx.to_be_bytes::<32>());
        self.storage.add_note_nullifier(nf_note)?;
        self.storage.add_tx_nullifier(nf_tx)?;
        
        // Add new commitments to tree
        let cm_out = Field::from_be_bytes_mod_order(&event.cm_out.to_be_bytes::<32>());
        let cm_change = Field::from_be_bytes_mod_order(&event.cm_change.to_be_bytes::<32>());
        let index_out = self.merkle_tree.insert(cm_out);
        let index_change = self.merkle_tree.insert(cm_change);
        
        // Store new root
        self.storage.add_known_root(self.merkle_tree.root())?;
        
        // Try to decrypt notes
        self.try_decrypt_note(&event.ciphertext_out, index_out)?;
        self.try_decrypt_note(&event.ciphertext_change, index_change)?;
        
        tracing::info!(
            "Processed transfer: nf_note={:?}, cm_out index={}, cm_change index={}",
            event.nf_note,
            index_out,
            index_change
        );
        
        Ok(())
    }
    
    /// Handle a Withdrawal event  
    pub fn handle_withdrawal(&mut self, event: WithdrawalEvent) -> eyre::Result<()> {
        // Mark nullifiers as used
        let nf_note = Field::from_be_bytes_mod_order(&event.nf_note.to_be_bytes::<32>());
        let nf_tx = Field::from_be_bytes_mod_order(&event.nf_tx.to_be_bytes::<32>());
        self.storage.add_note_nullifier(nf_note)?;
        self.storage.add_tx_nullifier(nf_tx)?;
        
        tracing::info!(
            "Processed withdrawal: {} {} to {}",
            event.value,
            event.token,
            event.to
        );
        
        Ok(())
    }
    
    /// Try to decrypt a note ciphertext for all known viewing keys
    fn try_decrypt_note(&self, _ciphertext: &[u8], _merkle_index: u64) -> eyre::Result<()> {
        // TODO: Iterate through all viewing keys and attempt decryption
        // For each successful decryption, store the note
        Ok(())
    }
}

/// Raw log data (placeholder until reth integration)
pub struct RawLog {
    pub address: Address,
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}
