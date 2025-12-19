//! Pool lane abstraction for multi-pool proxy
//!
//! This module defines the `PoolLane` trait that enables Voidgun to route
//! transactions to different privacy pools (Voidgun native, Railgun, etc.)

use alloy_primitives::{hex, Address, U256};
use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField};
use async_trait::async_trait;
use thiserror::Error;

use crate::keys::RailgunWallet;
use crate::notes::RailgunNote;
use crate::prover::RailgunProver;

#[derive(Debug, Error)]
pub enum LaneError {
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Insufficient balance")]
    InsufficientBalance,

    #[error("Note not found")]
    NoteNotFound,

    #[error("Pool not supported on this chain")]
    UnsupportedChain,
}

/// Pool identification
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PoolType {
    /// Voidgun native pool (ECDSA + UltraHonk)
    Voidgun,
    /// Railgun pool (Baby Jubjub + Groth16)
    Railgun,
    /// 0xbow Privacy Pools
    PrivacyPools,
}

impl PoolType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Voidgun => "voidgun",
            Self::Railgun => "railgun",
            Self::PrivacyPools => "privacy-pools",
        }
    }
}

/// Balance in a specific pool
#[derive(Clone, Debug)]
pub struct PoolBalance {
    /// Token address (zero for ETH)
    pub token: Address,
    /// Total balance
    pub balance: U256,
    /// Number of notes making up this balance
    pub note_count: usize,
}

/// Transaction request (unified across pools)
#[derive(Clone, Debug)]
pub struct TransferRequest {
    /// Recipient address (0x for public, 0zk for private)
    pub to: String,
    /// Token address
    pub token: Address,
    /// Amount to transfer
    pub amount: U256,
    /// Optional: target pool for recipient
    pub target_pool: Option<PoolType>,
}

/// Transaction result
#[derive(Clone, Debug)]
pub struct TransferResult {
    /// Transaction hash (if submitted)
    pub tx_hash: Option<[u8; 32]>,
    /// Proof (if generated)
    pub proof: Option<Vec<u8>>,
    /// New note commitment (if created)
    pub commitment: Option<Field>,
}

/// Abstract pool lane interface
///
/// Each privacy pool implements this trait to provide a unified interface
/// for the multi-pool proxy.
#[async_trait]
pub trait PoolLane: Send + Sync {
    /// Get pool type
    fn pool_type(&self) -> PoolType;

    /// Initialize lane with wallet signature
    async fn init(&mut self, signature: &[u8]) -> Result<(), LaneError>;

    /// Check if lane is initialized
    fn is_initialized(&self) -> bool;

    /// Get shielded address for receiving
    fn receiving_address(&self) -> Option<String>;

    /// Get balance for a token
    async fn get_balance(&self, token: Address) -> Result<PoolBalance, LaneError>;

    /// Get all balances
    async fn get_all_balances(&self) -> Result<Vec<PoolBalance>, LaneError>;

    /// Shield (deposit) tokens into the pool
    async fn shield(
        &mut self,
        token: Address,
        amount: U256,
        ciphertext: Vec<u8>,
    ) -> Result<TransferResult, LaneError>;

    /// Transfer within the pool
    async fn transfer(&mut self, request: TransferRequest) -> Result<TransferResult, LaneError>;

    /// Unshield (withdraw) tokens from the pool
    async fn unshield(
        &mut self,
        token: Address,
        amount: U256,
        recipient: Address,
    ) -> Result<TransferResult, LaneError>;

    /// Sync state from on-chain events
    async fn sync(&mut self, from_block: u64) -> Result<u64, LaneError>;

    /// Sync to the latest block (fetches current block number automatically)
    async fn sync_to_latest(&mut self) -> Result<u64, LaneError>;
}

/// Railgun lane implementation
#[allow(dead_code)]
pub struct RailgunLane {
    /// Wallet (derived from signature)
    wallet: Option<RailgunWallet>,

    /// Prover instance
    prover: RailgunProver,

    /// Chain ID
    chain_id: u64,

    /// Railgun contract address
    contract: Address,

    /// RPC URL for event fetching
    rpc_url: Option<String>,

    /// Owned notes (unspent)
    notes: Vec<(RailgunNote, u64)>, // (note, merkle_index)

    /// Spent nullifiers (to track which notes are spent)
    spent_nullifiers: std::collections::HashSet<Field>,

    /// Merkle tree for note commitments
    merkle_tree: crate::notes::NoteMerkleTree,

    /// Last synced block
    last_synced_block: u64,
}

impl RailgunLane {
    /// Create a new RailgunLane
    pub fn new(
        chain_id: u64,
        contract: Address,
        circuits_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        let artifact_store =
            std::sync::Arc::new(crate::artifacts::ArtifactStore::new(circuits_path, false));
        Self {
            wallet: None,
            prover: RailgunProver::new(artifact_store),
            chain_id,
            contract,
            rpc_url: None,
            notes: Vec::new(),
            spent_nullifiers: std::collections::HashSet::new(),
            merkle_tree: crate::notes::NoteMerkleTree::new(16), // Railgun uses depth 16
            last_synced_block: 0,
        }
    }

    /// Create with RPC URL for event syncing
    pub fn with_rpc(
        chain_id: u64,
        contract: Address,
        circuits_path: impl Into<std::path::PathBuf>,
        rpc_url: impl Into<String>,
    ) -> Self {
        let mut lane = Self::new(chain_id, contract, circuits_path);
        lane.rpc_url = Some(rpc_url.into());
        lane
    }

    /// Get wallet reference
    pub fn wallet(&self) -> Option<&RailgunWallet> {
        self.wallet.as_ref()
    }

    /// Find notes that sum to at least the requested amount
    fn select_notes(&self, token: Address, amount: U256) -> Result<Vec<usize>, LaneError> {
        let token_field = address_to_field(token);

        let mut selected = Vec::new();
        let mut total = U256::ZERO;

        for (i, (note, _)) in self.notes.iter().enumerate() {
            if note.token == token_field {
                selected.push(i);
                total += U256::from(note.value);

                if total >= amount {
                    return Ok(selected);
                }
            }
        }

        Err(LaneError::InsufficientBalance)
    }
}

#[async_trait]
impl PoolLane for RailgunLane {
    fn pool_type(&self) -> PoolType {
        PoolType::Railgun
    }

    async fn init(&mut self, signature: &[u8]) -> Result<(), LaneError> {
        let wallet = RailgunWallet::from_wallet_signature(signature)
            .map_err(|e| LaneError::KeyDerivation(e.to_string()))?;

        self.wallet = Some(wallet);
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.wallet.is_some()
    }

    fn receiving_address(&self) -> Option<String> {
        self.wallet
            .as_ref()
            .map(|w| w.to_0zk_address(self.chain_id))
    }

    async fn get_balance(&self, token: Address) -> Result<PoolBalance, LaneError> {
        let token_field = address_to_field(token);

        let mut balance = U256::ZERO;
        let mut count = 0;

        for (note, _) in &self.notes {
            if note.token == token_field {
                balance += U256::from(note.value);
                count += 1;
            }
        }

        Ok(PoolBalance {
            token,
            balance,
            note_count: count,
        })
    }

    async fn get_all_balances(&self) -> Result<Vec<PoolBalance>, LaneError> {
        use std::collections::HashMap;

        let mut balances: HashMap<Field, (U256, usize)> = HashMap::new();

        for (note, _) in &self.notes {
            let entry = balances.entry(note.token).or_insert((U256::ZERO, 0));
            entry.0 += U256::from(note.value);
            entry.1 += 1;
        }

        Ok(balances
            .into_iter()
            .map(|(token_field, (balance, count))| PoolBalance {
                token: field_to_address(token_field),
                balance,
                note_count: count,
            })
            .collect())
    }

    async fn shield(
        &mut self,
        token: Address,
        amount: U256,
        _ciphertext: Vec<u8>,
    ) -> Result<TransferResult, LaneError> {
        use crate::contracts::TransactionBuilder;
        use crate::notes::EncryptedNote;
        use crate::prover::ShieldWitness;

        let wallet = self
            .wallet
            .as_ref()
            .ok_or(LaneError::KeyDerivation("Not initialized".into()))?;

        // Convert amount
        let amount_u128: u128 = amount
            .try_into()
            .map_err(|_| LaneError::TransactionFailed("Amount too large".into()))?;

        // Create note for self
        let random = Field::from(rand::random::<u64>());
        let token_field = address_to_field(token);
        let note = RailgunNote::new(wallet.master_public_key, amount_u128, token_field, random);

        let commitment = note.commitment();

        // Build shield witness
        let witness = ShieldWitness {
            commitment,
            value: amount_u128,
            token: token_field,
            recipient_mpk: wallet.master_public_key,
            random,
        };

        // Generate shield proof
        let proof = self
            .prover
            .prove_shield(witness)
            .await
            .map_err(|e| LaneError::ProofGeneration(e.to_string()))?;

        // Encrypt note for self (so we can decrypt it during sync)
        let viewing_pub = wallet.viewing.public.as_bytes();
        let encrypted = EncryptedNote::encrypt(&note, viewing_pub)
            .map_err(|e| LaneError::TransactionFailed(e.to_string()))?;

        // Build shield calldata
        let builder = TransactionBuilder::new(self.chain_id).ok_or(LaneError::UnsupportedChain)?;

        // NPK for the shield request
        let npk = note.npk;

        // Build ciphertext components for ShieldCiphertext (encryptedBundle[3], shieldKey)
        let ciphertext_bytes = encrypted.to_bytes();
        let encrypted_bundle = {
            let mut bundle = [[0u8; 32]; 3];
            for (i, chunk) in ciphertext_bytes.chunks(32).take(3).enumerate() {
                bundle[i][..chunk.len()].copy_from_slice(chunk);
            }
            bundle
        };
        let shield_key = {
            let mut key = [0u8; 32];
            if ciphertext_bytes.len() > 96 {
                let start = 96;
                let end = (start + 32).min(ciphertext_bytes.len());
                key[..end - start].copy_from_slice(&ciphertext_bytes[start..end]);
            }
            key
        };

        let _calldata = builder
            .build_shield_calldata(token, amount, npk, encrypted_bundle, shield_key)
            .map_err(|e| LaneError::TransactionFailed(e.to_string()))?;

        Ok(TransferResult {
            tx_hash: None, // Would be set after on-chain submission
            proof: Some(proof.proof_bytes),
            commitment: Some(commitment),
        })
    }

    async fn transfer(&mut self, request: TransferRequest) -> Result<TransferResult, LaneError> {
        use crate::notes::EncryptedNote;
        use crate::prover::{RailgunProver, TransactWitness};

        let wallet = self
            .wallet
            .as_ref()
            .ok_or(LaneError::KeyDerivation("Not initialized".into()))?
            .clone();

        // Select input notes
        let note_indices = self.select_notes(request.token, request.amount)?;

        // Gather input notes and their merkle data
        let mut input_notes = Vec::new();
        let mut input_merkle_proofs = Vec::new();
        let mut input_merkle_indices = Vec::new();
        let mut total_input = 0u128;

        for &idx in &note_indices {
            let (note, merkle_idx) = &self.notes[idx];
            input_notes.push(note.clone());
            input_merkle_proofs.push(self.merkle_tree.proof(*merkle_idx));
            input_merkle_indices.push(*merkle_idx);
            total_input += note.value;
        }

        // Parse recipient address to get their NPK
        // For now, assume request.to is a hex-encoded master public key
        // TODO: Parse 0zk address format properly
        let recipient_mpk = if request.to.starts_with("0x") {
            let bytes = hex::decode(request.to.trim_start_matches("0x"))
                .map_err(|e| LaneError::TransactionFailed(format!("Invalid recipient: {}", e)))?;
            let mut padded = [0u8; 32];
            let start = 32usize.saturating_sub(bytes.len());
            padded[start..].copy_from_slice(&bytes);
            Field::from_be_bytes_mod_order(&padded)
        } else {
            return Err(LaneError::TransactionFailed(
                "Recipient must be 0x hex address or 0zk address".into(),
            ));
        };

        // Create output notes
        let token_field = address_to_field(request.token);
        let amount_u128: u128 = request
            .amount
            .try_into()
            .map_err(|_| LaneError::TransactionFailed("Amount too large".into()))?;

        // Generate random for output note
        let random_out = Field::from(rand::random::<u64>());

        // Output note to recipient
        let output_note = RailgunNote::new(recipient_mpk, amount_u128, token_field, random_out);

        // Change note back to self (if any)
        let change_amount = total_input.saturating_sub(amount_u128);
        let mut output_notes = vec![output_note.clone()];

        if change_amount > 0 {
            let random_change = Field::from(rand::random::<u64>());
            let change_note = RailgunNote::new(
                wallet.master_public_key,
                change_amount,
                token_field,
                random_change,
            );
            output_notes.push(change_note);
        }

        // Get current merkle root
        let merkle_root = self.merkle_tree.root();

        // Compute bound params hash (simplified - no adapter)
        let bound_params_hash = RailgunProver::compute_bound_params_hash_simple(
            0, // tree_number
            0, // min_gas_price
            0, // unshield (not unshielding)
            self.chain_id,
        );

        // Compute nullifiers using circuit formula: Poseidon(nullifyingKey, leafIndex)
        let nullifiers: Vec<Field> = input_merkle_indices
            .iter()
            .map(|&idx| RailgunNote::joinsplit_nullifier(wallet.nullifying_key, idx))
            .collect();

        // Compute output commitments (needed for message hash)
        let commitments_out: Vec<Field> = output_notes.iter().map(|n| n.commitment()).collect();

        // Get public key coordinates
        let (pk_x, pk_y) = wallet.spending.public_xy();

        // Compute message to sign: Poseidon(merkleRoot, boundParamsHash, nullifiers..., commitments...)
        // This matches the circuit's messageHash computation in JoinSplit.circom
        let mut message_inputs = vec![merkle_root, bound_params_hash];
        message_inputs.extend(nullifiers.iter().copied());
        message_inputs.extend(commitments_out.iter().copied());

        let message = crate::poseidon::poseidon_var(&message_inputs);

        // Sign the message
        let signature = wallet.spending.sign(message);

        // Build witness
        let witness = TransactWitness {
            merkle_root,
            bound_params_hash,
            token: token_field,
            public_key: [pk_x, pk_y],
            signature: signature.to_circuit_inputs(),
            input_notes,
            input_merkle_proofs,
            input_merkle_indices,
            output_notes: output_notes.clone(),
            nullifying_key: wallet.nullifying_key,
        };

        // Generate proof
        let proof = self
            .prover
            .prove_transact(witness)
            .await
            .map_err(|e| LaneError::ProofGeneration(e.to_string()))?;

        // Encrypt output note for recipient
        // TODO: Get recipient's viewing public key from 0zk address
        let viewing_pub = [0u8; 32]; // Placeholder
        let _encrypted = EncryptedNote::encrypt(&output_note, &viewing_pub)
            .map_err(|e| LaneError::TransactionFailed(e.to_string()))?;

        // Return result with proof and commitment
        let output_commitment = output_note.commitment();

        Ok(TransferResult {
            tx_hash: None, // Would be set after on-chain submission
            proof: Some(proof.proof_bytes),
            commitment: Some(output_commitment),
        })
    }

    async fn unshield(
        &mut self,
        token: Address,
        amount: U256,
        recipient: Address,
    ) -> Result<TransferResult, LaneError> {
        use crate::prover::{RailgunProver, TransactWitness};

        let wallet = self
            .wallet
            .as_ref()
            .ok_or(LaneError::KeyDerivation("Not initialized".into()))?
            .clone();

        // Select input notes
        let note_indices = self.select_notes(token, amount)?;

        // Gather input notes and their merkle data
        let mut input_notes = Vec::new();
        let mut input_merkle_proofs = Vec::new();
        let mut input_merkle_indices = Vec::new();
        let mut total_input = 0u128;

        for &idx in &note_indices {
            let (note, merkle_idx) = &self.notes[idx];
            input_notes.push(note.clone());
            input_merkle_proofs.push(self.merkle_tree.proof(*merkle_idx));
            input_merkle_indices.push(*merkle_idx);
            total_input += note.value;
        }

        let token_field = address_to_field(token);
        let amount_u128: u128 = amount
            .try_into()
            .map_err(|_| LaneError::TransactionFailed("Amount too large".into()))?;

        // For unshield, output goes to public recipient address
        // We may still have a change note back to ourselves
        let change_amount = total_input.saturating_sub(amount_u128);

        // Create change note if needed (stays in the pool)
        let mut output_notes = Vec::new();
        if change_amount > 0 {
            let random_change = Field::from(rand::random::<u64>());
            let change_note = RailgunNote::new(
                wallet.master_public_key,
                change_amount,
                token_field,
                random_change,
            );
            output_notes.push(change_note);
        }

        // Get current merkle root
        let merkle_root = self.merkle_tree.root();

        // Convert recipient to field for unshield preimage
        let _recipient_field = address_to_field(recipient);

        // Compute bound params hash with unshield type = NORMAL (1)
        // The recipient address is encoded in unshieldPreimage.npk, not in BoundParams
        let bound_params_hash = RailgunProver::compute_bound_params_hash_simple(
            0, // tree_number
            0, // min_gas_price
            1, // unshield = NORMAL (the recipient is in unshieldPreimage)
            self.chain_id,
        );

        // Compute nullifiers using circuit formula: Poseidon(nullifyingKey, leafIndex)
        let nullifiers: Vec<Field> = input_merkle_indices
            .iter()
            .map(|&idx| RailgunNote::joinsplit_nullifier(wallet.nullifying_key, idx))
            .collect();

        // Compute output commitments (needed for message hash)
        let commitments_out: Vec<Field> = output_notes.iter().map(|n| n.commitment()).collect();

        // Get public key coordinates
        let (pk_x, pk_y) = wallet.spending.public_xy();

        // Compute message to sign: Poseidon(merkleRoot, boundParamsHash, nullifiers..., commitments...)
        // This matches the circuit's messageHash computation in JoinSplit.circom
        let mut message_inputs = vec![merkle_root, bound_params_hash];
        message_inputs.extend(nullifiers.iter().copied());
        message_inputs.extend(commitments_out.iter().copied());

        let message = crate::poseidon::poseidon_var(&message_inputs);

        // Sign the message
        let signature = wallet.spending.sign(message);

        // Build witness
        let witness = TransactWitness {
            merkle_root,
            bound_params_hash,
            token: token_field,
            public_key: [pk_x, pk_y],
            signature: signature.to_circuit_inputs(),
            input_notes,
            input_merkle_proofs,
            input_merkle_indices,
            output_notes: output_notes.clone(),
            nullifying_key: wallet.nullifying_key,
        };

        // Generate proof
        let proof = self
            .prover
            .prove_transact(witness)
            .await
            .map_err(|e| LaneError::ProofGeneration(e.to_string()))?;

        // Return result - commitment is for change note if any
        let commitment = output_notes.first().map(|n| n.commitment());

        Ok(TransferResult {
            tx_hash: None, // Would be set after on-chain submission
            proof: Some(proof.proof_bytes),
            commitment,
        })
    }

    async fn sync(&mut self, from_block: u64) -> Result<u64, LaneError> {
        self.sync_to_block(from_block, None).await
    }

    async fn sync_to_latest(&mut self) -> Result<u64, LaneError> {
        let rpc_url = self
            .rpc_url
            .as_ref()
            .ok_or(LaneError::TransactionFailed("No RPC URL configured".into()))?;

        let client = crate::rpc::RailgunRpcClient::new(rpc_url.clone(), self.chain_id)
            .map_err(|e| LaneError::TransactionFailed(e.to_string()))?;

        let latest_block = client
            .get_block_number()
            .await
            .map_err(|e| LaneError::TransactionFailed(e.to_string()))?;

        self.sync_to_block(self.last_synced_block, Some(latest_block))
            .await
    }
}

impl RailgunLane {
    /// Internal sync implementation with optional target block
    async fn sync_to_block(
        &mut self,
        from_block: u64,
        target_block: Option<u64>,
    ) -> Result<u64, LaneError> {
        use crate::notes::EncryptedNote;
        use crate::rpc::{RailgunEvent, RailgunRpcClient};

        let wallet = self
            .wallet
            .as_ref()
            .ok_or(LaneError::KeyDerivation("Not initialized".into()))?
            .clone();

        let rpc_url = self
            .rpc_url
            .as_ref()
            .ok_or(LaneError::TransactionFailed("No RPC URL configured".into()))?;

        let client = RailgunRpcClient::new(rpc_url.clone(), self.chain_id)
            .map_err(|e| LaneError::TransactionFailed(e.to_string()))?;

        let target = match target_block {
            Some(t) => t,
            None => {
                client
                    .get_block_number()
                    .await
                    .map_err(|e| LaneError::TransactionFailed(e.to_string()))?
            }
        };

        let batch_size = 10_000u64;
        let mut current_block = from_block;

        while current_block < target {
            let end_block = (current_block + batch_size).min(target);

            tracing::info!("Syncing blocks {} to {}", current_block, end_block);

            let events = client
                .fetch_all_events(current_block, end_block)
                .await
                .map_err(|e| LaneError::TransactionFailed(e.to_string()))?;

            let viewing_secret = wallet.viewing.secret.as_bytes();

            for event in events {
                match event {
                    RailgunEvent::Shield(shield_event) => {
                        for (i, commitment) in shield_event.commitments.iter().enumerate() {
                            let leaf_index = self.merkle_tree.insert(*commitment);

                            if let (Some(ciphertext), Some(preimage)) = (
                                shield_event.ciphertexts.get(i),
                                shield_event.preimages.get(i),
                            ) {
                                let shield_ct = crate::notes::ShieldCiphertext::from_parsed(ciphertext);
                                if let Ok(random_bytes) = shield_ct.try_decrypt(viewing_secret) {
                                    let random = Field::from_be_bytes_mod_order(&random_bytes);
                                    let expected_npk = crate::poseidon::poseidon2(
                                        wallet.master_public_key,
                                        random,
                                    );

                                    if expected_npk == preimage.npk {
                                        let note = RailgunNote {
                                            npk: preimage.npk,
                                            value: preimage.value,
                                            token: preimage.token,
                                            random,
                                        };

                                        if note.commitment() == *commitment {
                                            tracing::info!(
                                                "Decrypted shield note at index {} with value {}",
                                                leaf_index,
                                                note.value
                                            );
                                            self.notes.push((note, leaf_index));
                                        }
                                    }
                                }
                            }
                        }
                    }

                    RailgunEvent::Transact(transact_event) => {
                        for (i, commitment) in
                            transact_event.commitment_hashes.iter().enumerate()
                        {
                            let leaf_index = self.merkle_tree.insert(*commitment);

                            if let Some(ciphertext_bytes) = transact_event.ciphertexts.get(i) {
                                if let Ok(encrypted_note) =
                                    EncryptedNote::from_bytes(ciphertext_bytes)
                                {
                                    if let Ok(note) = encrypted_note.try_decrypt(viewing_secret) {
                                        if note.commitment() == *commitment {
                                            tracing::info!(
                                                "Decrypted note at index {} with value {}",
                                                leaf_index,
                                                note.value
                                            );
                                            self.notes.push((note, leaf_index));
                                        }
                                    }
                                }
                            }
                        }
                    }

                    RailgunEvent::Nullifier(nullifier_event) => {
                        for nullifier in &nullifier_event.nullifiers {
                            self.spent_nullifiers.insert(*nullifier);

                            self.notes.retain(|(note, _)| {
                                note.nullifier(wallet.nullifying_key) != *nullifier
                            });
                        }
                    }
                }
            }

            current_block = end_block + 1;
        }

        self.last_synced_block = target;
        Ok(target)
    }
}

// Helper functions

fn address_to_field(addr: Address) -> Field {
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(addr.as_slice());
    Field::from_be_bytes_mod_order(&bytes)
}

fn field_to_address(f: Field) -> Address {
    let bytes = f.into_bigint().to_bytes_be();
    let mut addr_bytes = [0u8; 20];
    let start = bytes.len().saturating_sub(20);
    addr_bytes.copy_from_slice(&bytes[start..]);
    Address::from_slice(&addr_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_type_names() {
        assert_eq!(PoolType::Voidgun.name(), "voidgun");
        assert_eq!(PoolType::Railgun.name(), "railgun");
    }

    #[test]
    fn test_address_field_conversion() {
        let addr = Address::ZERO;
        let field = address_to_field(addr);
        let addr2 = field_to_address(field);
        assert_eq!(addr, addr2);
    }

    #[tokio::test]
    async fn test_railgun_lane_init() {
        let lane = RailgunLane::new(1, Address::ZERO, "/tmp/circuits");

        assert!(!lane.is_initialized());
        assert_eq!(lane.pool_type(), PoolType::Railgun);
    }
}
