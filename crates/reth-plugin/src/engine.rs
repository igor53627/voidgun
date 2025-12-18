//! VoidgunEngine - Reth-agnostic core for processing pool events
//!
//! This module provides a clean, synchronous API for:
//! - Processing Deposit/Transfer/Withdrawal events
//! - Maintaining Merkle tree state
//! - Tracking nullifiers and roots
//! - Trial decrypting notes for viewing keys
//! - Handling chain reorgs
//!
//! The engine is designed to be wrapped by async adapters (ExEx, RPC) using
//! tokio::sync::Mutex or RwLock at the boundary.

use alloy_primitives::{Address, U256};
use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField};
use std::sync::Arc;

use crate::config::VoidgunConfig;
use crate::storage::{RevertOperation, VoidgunStorage};
use voidgun_contracts::{DepositEvent, TransferEvent, WithdrawalEvent};
use voidgun_core::{
    encrypted_note_from_bytes,
    poseidon2::{hash_commitment, hash_key_derivation},
    try_decrypt_note, MerkleTree, NoteInfo,
};

/// VoidgunEngine - Core state machine for processing pool events
///
/// This struct owns the Merkle tree and provides a sync API for event processing.
/// It should be wrapped in `Arc<tokio::sync::Mutex<_>>` for use in async contexts.
#[derive(Debug)]
pub struct VoidgunEngine {
    config: VoidgunConfig,
    storage: Arc<VoidgunStorage>,
    merkle_tree: MerkleTree,
    current_block_revert_ops: Vec<RevertOperation>,
    current_block: Option<u64>,
}

impl VoidgunEngine {
    /// Create a new engine with given config and storage
    pub fn new(config: VoidgunConfig, storage: Arc<VoidgunStorage>) -> Self {
        Self {
            config,
            storage,
            merkle_tree: MerkleTree::new(),
            current_block_revert_ops: Vec::new(),
            current_block: None,
        }
    }

    /// Get the pool address being monitored
    pub fn pool_address(&self) -> Address {
        self.config.pool_address
    }

    /// Get current Merkle root
    pub fn current_root(&self) -> Field {
        self.merkle_tree.root()
    }

    /// Get current leaf count
    pub fn leaf_count(&self) -> u64 {
        self.merkle_tree.next_index
    }

    /// Check if a root is known (valid for proofs)
    pub fn is_known_root(&self, root: Field) -> eyre::Result<bool> {
        self.storage.is_known_root(root).map_err(Into::into)
    }

    /// Get Merkle path for a leaf index
    pub fn merkle_path(&self, index: u64) -> eyre::Result<Vec<Field>> {
        Ok(self.merkle_tree.proof(index, Field::from(0u64)).path)
    }

    /// Begin processing a new block
    pub fn begin_block(&mut self, block_number: u64) {
        self.current_block_revert_ops.clear();
        self.current_block = Some(block_number);
    }

    /// Finalize block processing and store revert operations
    pub fn end_block(&mut self, block_number: u64) -> eyre::Result<()> {
        if !self.current_block_revert_ops.is_empty() {
            self.storage
                .store_block_revert_ops(block_number, &self.current_block_revert_ops)?;
        }
        self.storage.set_last_block(block_number)?;
        self.current_block_revert_ops.clear();
        self.current_block = None;
        Ok(())
    }

    /// Revert a single block (undo all operations from that block)
    pub fn revert_block(&mut self, block_number: u64) -> eyre::Result<()> {
        if let Some(ops) = self.storage.get_block_revert_ops(block_number)? {
            self.storage.execute_revert(&ops)?;
            self.storage.remove_block_revert_ops(block_number)?;
            tracing::info!("Reverted block {} ({} operations)", block_number, ops.len());
        }
        Ok(())
    }

    /// Revert to a specific block (revert all blocks after target)
    pub fn revert_to_block(&mut self, target_block: u64) -> eyre::Result<()> {
        let current = self.storage.get_last_block()?.unwrap_or(0);
        for block in (target_block + 1..=current).rev() {
            self.revert_block(block)?;
        }
        self.storage.set_last_block(target_block)?;
        tracing::info!("Reverted from block {} to block {}", current, target_block);
        Ok(())
    }

    /// Get the last processed block number
    pub fn last_block(&self) -> eyre::Result<Option<u64>> {
        self.storage.get_last_block().map_err(Into::into)
    }

    /// Handle a Deposit event
    pub fn handle_deposit(&mut self, event: DepositEvent) -> eyre::Result<()> {
        let cm = Field::from_be_bytes_mod_order(&event.commitment.to_be_bytes::<32>());
        let index = self.merkle_tree.insert(cm);

        let root = self.merkle_tree.root();
        let root_key = format!("root:{}", hex::encode(root.into_bigint().to_bytes_be()));
        self.storage.add_known_root(root)?;
        self.current_block_revert_ops
            .push(RevertOperation::RemoveRoot { root_key });

        self.trial_decrypt_and_store(&event.ciphertext, index, cm)?;

        tracing::info!(
            "Processed deposit: cm={:?}, index={}, new_root={:?}",
            event.commitment,
            index,
            root
        );

        Ok(())
    }

    /// Handle a Transfer event
    pub fn handle_transfer(&mut self, event: TransferEvent) -> eyre::Result<()> {
        let nf_note = Field::from_be_bytes_mod_order(&event.nf_note.to_be_bytes::<32>());
        let nf_tx = Field::from_be_bytes_mod_order(&event.nf_tx.to_be_bytes::<32>());

        let nf_note_key = format!(
            "nf_note:{}",
            hex::encode(nf_note.into_bigint().to_bytes_be())
        );
        let nf_tx_key = format!("nf_tx:{}", hex::encode(nf_tx.into_bigint().to_bytes_be()));

        self.storage.add_note_nullifier(nf_note)?;
        self.storage.add_tx_nullifier(nf_tx)?;

        self.current_block_revert_ops
            .push(RevertOperation::UnmarkNullifier {
                nullifier_key: nf_note_key,
            });
        self.current_block_revert_ops
            .push(RevertOperation::UnmarkNullifier {
                nullifier_key: nf_tx_key,
            });

        let cm_out = Field::from_be_bytes_mod_order(&event.cm_out.to_be_bytes::<32>());
        let cm_change = Field::from_be_bytes_mod_order(&event.cm_change.to_be_bytes::<32>());
        let index_out = self.merkle_tree.insert(cm_out);
        let index_change = self.merkle_tree.insert(cm_change);

        let root = self.merkle_tree.root();
        let root_key = format!("root:{}", hex::encode(root.into_bigint().to_bytes_be()));
        self.storage.add_known_root(root)?;
        self.current_block_revert_ops
            .push(RevertOperation::RemoveRoot { root_key });

        self.trial_decrypt_and_store(&event.ciphertext_out, index_out, cm_out)?;
        self.trial_decrypt_and_store(&event.ciphertext_change, index_change, cm_change)?;

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
        let nf_note = Field::from_be_bytes_mod_order(&event.nf_note.to_be_bytes::<32>());
        let nf_tx = Field::from_be_bytes_mod_order(&event.nf_tx.to_be_bytes::<32>());

        let nf_note_key = format!(
            "nf_note:{}",
            hex::encode(nf_note.into_bigint().to_bytes_be())
        );
        let nf_tx_key = format!("nf_tx:{}", hex::encode(nf_tx.into_bigint().to_bytes_be()));

        self.storage.add_note_nullifier(nf_note)?;
        self.storage.add_tx_nullifier(nf_tx)?;

        self.current_block_revert_ops
            .push(RevertOperation::UnmarkNullifier {
                nullifier_key: nf_note_key,
            });
        self.current_block_revert_ops
            .push(RevertOperation::UnmarkNullifier {
                nullifier_key: nf_tx_key,
            });

        tracing::info!(
            "Processed withdrawal: {} {} to {}",
            event.value,
            event.token,
            event.to
        );

        Ok(())
    }

    /// Try to decrypt a note ciphertext for all known viewing keys
    fn trial_decrypt_and_store(
        &mut self,
        ciphertext: &[u8],
        merkle_index: u64,
        expected_commitment: Field,
    ) -> eyre::Result<()> {
        let encrypted = match encrypted_note_from_bytes(ciphertext) {
            Some(enc) => enc,
            None => {
                tracing::warn!("Failed to parse encrypted note ciphertext");
                return Ok(());
            }
        };

        let viewing_keys = self.storage.get_all_viewing_keys()?;

        for (addr, vk) in viewing_keys {
            let ek_x = hash_key_derivation(&[vk.nk, Field::from(1u64)]);

            if let Some((rk_hash, value_field, token_field, r)) = try_decrypt_note(&encrypted, ek_x)
            {
                let computed_cm = hash_commitment(rk_hash, value_field, token_field, r);

                if computed_cm == expected_commitment {
                    let value_bytes = value_field.into_bigint().to_bytes_be();
                    let value = U256::from_be_slice(&value_bytes);

                    let token_bytes = token_field.into_bigint().to_bytes_be();
                    let token_type = Address::from_slice(&token_bytes[12..32]);

                    let note_info = NoteInfo {
                        commitment: expected_commitment,
                        rk_hash,
                        value,
                        token_type,
                        r,
                        merkle_index,
                        spent: false,
                    };

                    self.storage.add_note(addr, &note_info)?;

                    self.current_block_revert_ops
                        .push(RevertOperation::RemoveNote { addr, merkle_index });

                    tracing::info!(
                        "Decrypted note for {}: value={}, token={}, index={}",
                        addr,
                        value,
                        token_type,
                        merkle_index
                    );

                    break;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_config() -> VoidgunConfig {
        VoidgunConfig::default()
    }

    fn test_storage() -> Arc<VoidgunStorage> {
        let dir = tempdir().unwrap();
        Arc::new(VoidgunStorage::open(dir.path()).unwrap())
    }

    #[test]
    fn test_engine_new() {
        let engine = VoidgunEngine::new(test_config(), test_storage());
        assert_eq!(engine.leaf_count(), 0);
    }

    #[test]
    fn test_begin_end_block() {
        let mut engine = VoidgunEngine::new(test_config(), test_storage());
        engine.begin_block(100);
        assert!(engine.end_block(100).is_ok());
        assert_eq!(engine.last_block().unwrap(), Some(100));
    }

    #[test]
    fn test_handle_deposit() {
        let mut engine = VoidgunEngine::new(test_config(), test_storage());
        engine.begin_block(1);

        let event = DepositEvent {
            commitment: U256::from(12345u64),
            value: U256::from(1000u64),
            token: Address::ZERO,
            ciphertext: vec![],
            leaf_index: 0,
            new_root: U256::ZERO,
        };

        assert!(engine.handle_deposit(event).is_ok());
        assert_eq!(engine.leaf_count(), 1);
        engine.end_block(1).unwrap();
    }
}
