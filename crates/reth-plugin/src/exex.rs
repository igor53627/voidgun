//! VoidgunExEx - Execution Extension wrapper for reth integration
//!
//! This module provides the async ExEx adapter that:
//! - Wraps VoidgunEngine with tokio::sync::Mutex
//! - Provides an async API for reth ExEx notification processing
//! - Decodes raw logs into typed events
//!
//! For use with reth's ExExContext, the reth fork crate should:
//! 1. Create a VoidgunExEx instance
//! 2. Call engine() to get the shared engine handle
//! 3. In the ExEx notification loop, lock the engine and call handle_* methods

use alloy_primitives::{Address, FixedBytes, U256};
use alloy_sol_types::SolEvent;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config::VoidgunConfig;
use crate::engine::VoidgunEngine;
use crate::storage::VoidgunStorage;
use voidgun_contracts::bindings::IVoidgunPool;
use voidgun_contracts::{DepositEvent, TransferEvent, WithdrawalEvent};

/// VoidgunExEx - Async wrapper for VoidgunEngine
///
/// This provides the async interface expected by reth's ExEx framework.
/// The engine is wrapped in tokio::sync::Mutex for safe async access.
pub struct VoidgunExEx {
    config: VoidgunConfig,
    engine: Arc<Mutex<VoidgunEngine>>,
}

impl VoidgunExEx {
    /// Create a new ExEx with the given config and storage
    pub fn new(config: VoidgunConfig, storage: Arc<VoidgunStorage>) -> Self {
        let engine = VoidgunEngine::new(config.clone(), storage);
        Self {
            config,
            engine: Arc::new(Mutex::new(engine)),
        }
    }

    /// Create with an existing engine (for sharing between ExEx and RPC)
    pub fn with_engine(config: VoidgunConfig, engine: Arc<Mutex<VoidgunEngine>>) -> Self {
        Self { config, engine }
    }

    /// Get shared engine handle for RPC
    pub fn engine(&self) -> Arc<Mutex<VoidgunEngine>> {
        self.engine.clone()
    }

    /// Get the pool address being monitored
    pub fn pool_address(&self) -> Address {
        self.config.pool_address
    }

    /// Process a block of logs
    ///
    /// This is the main entry point for ExEx notification processing.
    /// Call this for each block in ChainCommitted notifications.
    pub async fn process_block(&self, block_number: u64, logs: Vec<RawLog>) -> eyre::Result<()> {
        let mut engine = self.engine.lock().await;
        engine.begin_block(block_number);

        for log in logs {
            if log.address != self.config.pool_address {
                continue;
            }

            if log.topics.is_empty() {
                continue;
            }

            let topic0 = FixedBytes::from_slice(&log.topics[0]);

            if topic0 == IVoidgunPool::Deposit::SIGNATURE_HASH {
                if let Ok(event) = decode_deposit_event(&log) {
                    engine.handle_deposit(event)?;
                }
            } else if topic0 == IVoidgunPool::Transfer::SIGNATURE_HASH {
                if let Ok(event) = decode_transfer_event(&log) {
                    engine.handle_transfer(event)?;
                }
            } else if topic0 == IVoidgunPool::Withdrawal::SIGNATURE_HASH {
                if let Ok(event) = decode_withdrawal_event(&log) {
                    engine.handle_withdrawal(event)?;
                }
            }
        }

        engine.end_block(block_number)?;
        Ok(())
    }

    /// Revert a single block
    pub async fn revert_block(&self, block_number: u64) -> eyre::Result<()> {
        let mut engine = self.engine.lock().await;
        engine.revert_block(block_number)
    }

    /// Revert to a specific block (revert all blocks after target)
    pub async fn revert_to_block(&self, target_block: u64) -> eyre::Result<()> {
        let mut engine = self.engine.lock().await;
        engine.revert_to_block(target_block)
    }

    /// Get the last processed block number
    pub async fn last_block(&self) -> eyre::Result<Option<u64>> {
        let engine = self.engine.lock().await;
        engine.last_block()
    }
}

/// Raw log data (adapter for reth's Log type)
pub struct RawLog {
    pub address: Address,
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

impl RawLog {
    /// Create from reth's Log type (or any similar type)
    pub fn new(address: Address, topics: Vec<[u8; 32]>, data: Vec<u8>) -> Self {
        Self {
            address,
            topics,
            data,
        }
    }
}

/// Decode a Deposit event from raw log
pub fn decode_deposit_event(log: &RawLog) -> Result<DepositEvent, String> {
    if log.topics.len() < 3 {
        return Err("Deposit: not enough topics".into());
    }

    let commitment = U256::from_be_bytes(log.topics[1]);
    let token = Address::from_slice(&log.topics[2][12..32]);

    if log.data.len() < 128 {
        return Err("Deposit: data too short".into());
    }

    let value = U256::from_be_slice(&log.data[0..32]);
    let _ciphertext_offset = U256::from_be_slice(&log.data[32..64]);
    let leaf_index = U256::from_be_slice(&log.data[64..96]);
    let new_root = U256::from_be_slice(&log.data[96..128]);

    let ciphertext = if log.data.len() > 128 {
        let ct_len = U256::from_be_slice(&log.data[128..160]).saturating_to::<usize>();
        let ct_start = 160;
        let ct_end = (ct_start + ct_len).min(log.data.len());
        log.data[ct_start..ct_end].to_vec()
    } else {
        vec![]
    };

    Ok(DepositEvent {
        commitment,
        value,
        token,
        ciphertext,
        leaf_index: leaf_index.saturating_to::<u64>(),
        new_root,
    })
}

/// Decode a Transfer event from raw log
pub fn decode_transfer_event(log: &RawLog) -> Result<TransferEvent, String> {
    if log.topics.len() < 3 {
        return Err("Transfer: not enough topics".into());
    }

    let nf_note = U256::from_be_bytes(log.topics[1]);
    let nf_tx = U256::from_be_bytes(log.topics[2]);

    if log.data.len() < 160 {
        return Err("Transfer: data too short".into());
    }

    let cm_out = U256::from_be_slice(&log.data[0..32]);
    let cm_change = U256::from_be_slice(&log.data[32..64]);
    let new_root = U256::from_be_slice(&log.data[64..96]);

    let (ciphertext_out, ciphertext_change) = extract_two_dynamic_bytes(&log.data[96..]);

    Ok(TransferEvent {
        nf_note,
        nf_tx,
        cm_out,
        cm_change,
        new_root,
        ciphertext_out,
        ciphertext_change,
    })
}

/// Decode a Withdrawal event from raw log
pub fn decode_withdrawal_event(log: &RawLog) -> Result<WithdrawalEvent, String> {
    if log.topics.len() < 4 {
        return Err("Withdrawal: not enough topics".into());
    }

    let nf_note = U256::from_be_bytes(log.topics[1]);
    let nf_tx = U256::from_be_bytes(log.topics[2]);
    let to = Address::from_slice(&log.topics[3][12..32]);

    if log.data.len() < 64 {
        return Err("Withdrawal: data too short".into());
    }

    let value = U256::from_be_slice(&log.data[0..32]);
    let token = Address::from_slice(&log.data[44..64]);

    Ok(WithdrawalEvent {
        nf_note,
        nf_tx,
        to,
        value,
        token,
    })
}

fn extract_two_dynamic_bytes(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if data.len() < 64 {
        return (vec![], vec![]);
    }

    let offset1 = U256::from_be_slice(&data[0..32]).saturating_to::<usize>();
    let offset2 = U256::from_be_slice(&data[32..64]).saturating_to::<usize>();

    let bytes1 = extract_dynamic_bytes(data, offset1);
    let bytes2 = extract_dynamic_bytes(data, offset2);

    (bytes1, bytes2)
}

fn extract_dynamic_bytes(data: &[u8], offset: usize) -> Vec<u8> {
    if offset + 32 > data.len() {
        return vec![];
    }

    let len = U256::from_be_slice(&data[offset..offset + 32]).saturating_to::<usize>();
    let start = offset + 32;
    let end = (start + len).min(data.len());

    if start > data.len() {
        return vec![];
    }

    data[start..end].to_vec()
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

    #[tokio::test]
    async fn test_exex_new() {
        let exex = VoidgunExEx::new(test_config(), test_storage());
        assert!(exex.last_block().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_process_empty_block() {
        let exex = VoidgunExEx::new(test_config(), test_storage());
        assert!(exex.process_block(1, vec![]).await.is_ok());
        assert_eq!(exex.last_block().await.unwrap(), Some(1));
    }
}
