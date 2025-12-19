//! RPC client for fetching Railgun events
//!
//! This module provides async event fetching from Ethereum nodes.

use alloy_primitives::{Address, B256};
use alloy_rpc_types::Log;
use alloy_sol_types::SolEvent;
use ark_bn254::Fr as Field;
use ark_ff::PrimeField;
use thiserror::Error;

use crate::contracts::{
    Nullifiers, ParsedNullifierEvent, ParsedShieldCiphertext, ParsedShieldEvent,
    ParsedShieldPreimage, ParsedTransactEvent, RailgunAddresses, Shield, Transact,
};

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Event parsing failed: {0}")]
    ParseFailed(String),

    #[error("No provider configured")]
    NoProvider,

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Railgun event types
#[derive(Clone, Debug)]
pub enum RailgunEvent {
    Shield(ParsedShieldEvent),
    Transact(ParsedTransactEvent),
    Nullifier(ParsedNullifierEvent),
}

/// RPC client for Railgun event fetching
pub struct RailgunRpcClient {
    /// RPC endpoint URL
    pub rpc_url: String,
    /// Contract addresses
    pub addresses: RailgunAddresses,
    /// Chain ID
    pub chain_id: u64,
}

impl RailgunRpcClient {
    /// Create new RPC client
    pub fn new(rpc_url: impl Into<String>, chain_id: u64) -> Result<Self, RpcError> {
        let addresses = RailgunAddresses::for_chain(chain_id).ok_or(RpcError::NoProvider)?;
        Ok(Self {
            rpc_url: rpc_url.into(),
            addresses,
            chain_id,
        })
    }

    /// Get current block number via eth_blockNumber
    pub async fn get_block_number(&self) -> Result<u64, RpcError> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1,
        });

        let client = reqwest::Client::new();
        let response = client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(RpcError::Transport(error.to_string()));
        }

        let result = json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::Transport("No result in response".into()))?;

        // Parse hex string (e.g., "0x1234abc")
        let block_num = u64::from_str_radix(result.trim_start_matches("0x"), 16)
            .map_err(|e| RpcError::ParseFailed(format!("Invalid block number: {}", e)))?;

        Ok(block_num)
    }

    /// Fetch Shield events in a block range
    ///
    /// Note: Shield events are emitted by the Relay contract, not SmartWallet
    pub async fn fetch_shield_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<ParsedShieldEvent>, RpcError> {
        let logs = self
            .fetch_logs(
                Shield::SIGNATURE_HASH,
                self.addresses.relay,
                from_block,
                to_block,
            )
            .await?;

        logs.into_iter()
            .map(|log| self.parse_shield_log(&log))
            .collect()
    }

    /// Fetch Transact events in a block range
    ///
    /// Note: Transact events are emitted by the Relay contract, not SmartWallet
    pub async fn fetch_transact_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<ParsedTransactEvent>, RpcError> {
        let logs = self
            .fetch_logs(
                Transact::SIGNATURE_HASH,
                self.addresses.relay,
                from_block,
                to_block,
            )
            .await?;

        logs.into_iter()
            .map(|log| self.parse_transact_log(&log))
            .collect()
    }

    /// Fetch Nullifier events in a block range
    pub async fn fetch_nullifier_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<ParsedNullifierEvent>, RpcError> {
        let logs = self
            .fetch_logs(
                Nullifiers::SIGNATURE_HASH,
                self.addresses.smart_wallet,
                from_block,
                to_block,
            )
            .await?;

        logs.into_iter()
            .map(|log| self.parse_nullifier_log(&log))
            .collect()
    }

    /// Fetch all Railgun events in a block range
    pub async fn fetch_all_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<RailgunEvent>, RpcError> {
        let (shields, transacts, nullifiers) = tokio::try_join!(
            self.fetch_shield_events(from_block, to_block),
            self.fetch_transact_events(from_block, to_block),
            self.fetch_nullifier_events(from_block, to_block),
        )?;

        let mut events: Vec<RailgunEvent> =
            Vec::with_capacity(shields.len() + transacts.len() + nullifiers.len());

        events.extend(shields.into_iter().map(RailgunEvent::Shield));
        events.extend(transacts.into_iter().map(RailgunEvent::Transact));
        events.extend(nullifiers.into_iter().map(RailgunEvent::Nullifier));

        // Sort by block number
        events.sort_by_key(|e| match e {
            RailgunEvent::Shield(s) => s.block_number,
            RailgunEvent::Transact(t) => t.block_number,
            RailgunEvent::Nullifier(n) => n.block_number,
        });

        Ok(events)
    }

    /// Internal: fetch logs via HTTP RPC
    async fn fetch_logs(
        &self,
        event_signature: B256,
        contract: Address,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Log>, RpcError> {
        let filter = serde_json::json!({
            "address": format!("{:?}", contract),
            "topics": [format!("{:?}", event_signature)],
            "fromBlock": format!("0x{:x}", from_block),
            "toBlock": format!("0x{:x}", to_block),
        });

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getLogs",
            "params": [filter],
            "id": 1,
        });

        let client = reqwest::Client::new();
        let response = client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(RpcError::Transport(error.to_string()));
        }

        let result = json
            .get("result")
            .ok_or_else(|| RpcError::Transport("No result in response".into()))?;

        let logs: Vec<Log> = serde_json::from_value(result.clone())
            .map_err(|e| RpcError::ParseFailed(e.to_string()))?;

        Ok(logs)
    }

    /// Parse Shield log to event
    ///
    /// The Shield event includes preimages (npk, token, value), not the commitments directly.
    /// We compute commitment = Poseidon(npk, tokenField, value) from each preimage.
    fn parse_shield_log(&self, log: &Log) -> Result<ParsedShieldEvent, RpcError> {
        let decoded = Shield::decode_log_data(&log.data())
            .map_err(|e| RpcError::ParseFailed(e.to_string()))?;

        let mut commitments = Vec::with_capacity(decoded.preimages.len());
        let mut preimages = Vec::with_capacity(decoded.preimages.len());

        for preimage in &decoded.preimages {
            let npk = Field::from_be_bytes_mod_order(preimage.npk.as_slice());

            let token_field = if preimage.token.tokenType == 0 {
                let mut bytes = [0u8; 32];
                bytes[12..32].copy_from_slice(preimage.token.tokenAddress.as_slice());
                Field::from_be_bytes_mod_order(&bytes)
            } else {
                use sha3::{Digest, Keccak256};
                let mut data = [0u8; 96];
                data[31] = preimage.token.tokenType;
                data[44..64].copy_from_slice(preimage.token.tokenAddress.as_slice());
                data[64..96].copy_from_slice(&preimage.token.tokenSubID.to_be_bytes::<32>());
                let hash = Keccak256::digest(&data);
                Field::from_be_bytes_mod_order(&hash)
            };

            let value = preimage.value.to::<u128>();
            let commitment = crate::poseidon::poseidon3(npk, token_field, Field::from(value));

            commitments.push(commitment);
            preimages.push(ParsedShieldPreimage {
                npk,
                token: token_field,
                token_address: preimage.token.tokenAddress,
                value,
            });
        }

        let ciphertexts: Vec<ParsedShieldCiphertext> = decoded
            .ciphertexts
            .iter()
            .map(|c| {
                let mut encrypted_bundle = [[0u8; 32]; 3];
                for (i, chunk) in c.encryptedBundle.iter().take(3).enumerate() {
                    encrypted_bundle[i].copy_from_slice(chunk.as_slice());
                }
                let mut shield_key = [0u8; 32];
                shield_key.copy_from_slice(c.shieldKey.as_slice());

                ParsedShieldCiphertext {
                    encrypted_bundle,
                    shield_key,
                }
            })
            .collect();

        Ok(ParsedShieldEvent {
            tree_number: decoded.treeNumber.try_into().unwrap_or(0),
            start_position: decoded.startPosition.try_into().unwrap_or(0),
            commitments,
            ciphertexts,
            preimages,
            block_number: log.block_number.unwrap_or(0),
            tx_hash: log.transaction_hash.unwrap_or_default(),
        })
    }

    /// Parse Transact log to event
    fn parse_transact_log(&self, log: &Log) -> Result<ParsedTransactEvent, RpcError> {
        let decoded = Transact::decode_log_data(&log.data())
            .map_err(|e| RpcError::ParseFailed(e.to_string()))?;

        let commitment_hashes: Vec<Field> = decoded
            .hash
            .iter()
            .map(|h| Field::from_be_bytes_mod_order(h.as_slice()))
            .collect();

        let ciphertexts: Vec<Vec<u8>> = decoded
            .ciphertext
            .iter()
            .map(|c| {
                let mut bytes = Vec::new();
                for chunk in &c.ciphertext {
                    bytes.extend_from_slice(chunk.as_slice());
                }
                bytes.extend_from_slice(c.ephemeralKey.as_slice());
                bytes.extend_from_slice(c.blindedSenderViewingKey.as_slice());
                bytes.extend_from_slice(&c.annotationData);
                bytes.extend_from_slice(&c.memo);
                bytes
            })
            .collect();

        Ok(ParsedTransactEvent {
            tree_number: decoded.treeNumber.try_into().unwrap_or(0),
            start_position: decoded.startPosition.try_into().unwrap_or(0),
            commitment_hashes,
            ciphertexts,
            block_number: log.block_number.unwrap_or(0),
            tx_hash: log.transaction_hash.unwrap_or_default(),
        })
    }

    /// Parse Nullifier log to event
    fn parse_nullifier_log(&self, log: &Log) -> Result<ParsedNullifierEvent, RpcError> {
        let decoded = Nullifiers::decode_log_data(&log.data())
            .map_err(|e| RpcError::ParseFailed(e.to_string()))?;

        let nullifiers: Vec<Field> = decoded
            .nullifiers
            .iter()
            .map(|n| Field::from_be_bytes_mod_order(n.as_slice()))
            .collect();

        Ok(ParsedNullifierEvent {
            tree_number: decoded.treeNumber.try_into().unwrap_or(0),
            nullifiers,
            block_number: log.block_number.unwrap_or(0),
            tx_hash: log.transaction_hash.unwrap_or_default(),
        })
    }
}

/// Sync state from on-chain events
pub struct EventSyncer {
    /// RPC client
    pub client: RailgunRpcClient,
    /// Last synced block
    pub last_block: u64,
    /// Batch size for fetching
    pub batch_size: u64,
}

impl EventSyncer {
    pub fn new(client: RailgunRpcClient, start_block: u64) -> Self {
        Self {
            client,
            last_block: start_block,
            batch_size: 10_000,
        }
    }

    /// Sync events up to the specified block
    pub async fn sync_to(&mut self, target_block: u64) -> Result<Vec<RailgunEvent>, RpcError> {
        let mut all_events = Vec::new();
        let mut current = self.last_block;

        while current < target_block {
            let end = (current + self.batch_size).min(target_block);
            tracing::info!("Syncing blocks {} to {}", current, end);

            let events = self.client.fetch_all_events(current, end).await?;
            all_events.extend(events);
            current = end + 1;
        }

        self.last_block = target_block;
        Ok(all_events)
    }

    /// Get current synced block
    pub fn synced_block(&self) -> u64 {
        self.last_block
    }

    /// Sync to the latest block
    pub async fn sync_to_latest(&mut self) -> Result<Vec<RailgunEvent>, RpcError> {
        let latest_block = self.client.get_block_number().await?;
        self.sync_to(latest_block).await
    }

    /// Sync events and build merkle tree for a specific tree number
    ///
    /// Returns the merkle tree with all commitments inserted in order.
    /// The tree can be used to generate proofs that will verify on-chain.
    pub async fn sync_merkle_tree(
        &mut self,
        target_block: u64,
        tree_number: u64,
        tree_depth: usize,
    ) -> Result<crate::notes::NoteMerkleTree, RpcError> {
        let events = self.sync_to(target_block).await?;

        let mut tree = crate::notes::NoteMerkleTree::new(tree_depth)
            .map_err(|e| RpcError::ParseError(e.to_string()))?;

        // Collect all commitments with their positions
        let mut commitments_with_pos: Vec<(u64, Field)> = Vec::new();

        for event in events {
            match event {
                RailgunEvent::Shield(shield) => {
                    if shield.tree_number == tree_number {
                        for (i, commitment) in shield.commitments.iter().enumerate() {
                            let pos = shield.start_position + i as u64;
                            commitments_with_pos.push((pos, *commitment));
                        }
                    }
                }
                RailgunEvent::Transact(transact) => {
                    if transact.tree_number == tree_number {
                        for (i, commitment) in transact.commitment_hashes.iter().enumerate() {
                            let pos = transact.start_position + i as u64;
                            commitments_with_pos.push((pos, *commitment));
                        }
                    }
                }
                RailgunEvent::Nullifier(_) => {
                    // Nullifiers don't add to the tree
                }
            }
        }

        // Sort by position (should already be sorted by block, but positions might interleave)
        commitments_with_pos.sort_by_key(|(pos, _)| *pos);

        // Verify positions are contiguous and insert
        for (expected_idx, (pos, commitment)) in commitments_with_pos.iter().enumerate() {
            if *pos != expected_idx as u64 {
                tracing::warn!(
                    "Gap in commitments: expected index {}, got position {}",
                    expected_idx,
                    pos
                );
            }
            tree.insert(*commitment)
                .map_err(|e| RpcError::ParseError(e.to_string()))?;
        }

        tracing::info!("Built merkle tree with {} leaves", tree.leaves.len());

        Ok(tree)
    }
}

#[allow(dead_code)]
fn field_to_bytes(f: &Field) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    let be_bytes = f.into_bigint().to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_client_creation() {
        let client = RailgunRpcClient::new("https://eth.llamarpc.com", 1);
        assert!(client.is_ok());

        let client = RailgunRpcClient::new("https://example.com", 99999);
        assert!(client.is_err());
    }

    #[test]
    fn test_event_syncer_creation() {
        let client = RailgunRpcClient::new("https://eth.llamarpc.com", 1).unwrap();
        let syncer = EventSyncer::new(client, 18_000_000);
        assert_eq!(syncer.synced_block(), 18_000_000);
    }
}
