use alloy_primitives::{keccak256, Address, Bytes, U256};
use alloy_rlp::Decodable;
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObject};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::config::VoidgunConfig;
use crate::engine::VoidgunEngine;
use crate::storage::VoidgunStorage;
use voidgun_core::tx::{Eip1559Tx, SignedEip1559Tx};
use voidgun_core::{NoteInfo, ReceivingKey, ViewingKey, EXPORT_VK_MESSAGE};

/// Voidgun RPC API trait - defines the void_* namespace
#[rpc(server, namespace = "void")]
pub trait VoidgunRpcApi {
    /// Initialize a voidgun account from wallet signature
    #[method(name = "initAccount")]
    async fn init_account(&self, addr: Address, signature: Bytes) -> RpcResult<bool>;

    /// Check if an account is initialized
    #[method(name = "isInitialized")]
    async fn is_initialized(&self, addr: Address) -> RpcResult<bool>;

    /// Get receiving key for an address (for sending to this account)
    #[method(name = "getReceivingKey")]
    async fn get_receiving_key(&self, addr: Address) -> RpcResult<Option<ReceivingKeyInfo>>;

    /// Send a shielded transaction
    #[method(name = "sendTransaction")]
    async fn send_transaction(&self, raw_tx: Bytes) -> RpcResult<ShieldedTransferResult>;

    /// Get shielded balance for an address
    #[method(name = "getBalance")]
    async fn get_balance(&self, addr: Address, token: Option<Address>) -> RpcResult<U256>;

    /// List unspent notes for an address
    #[method(name = "listNotes")]
    async fn list_notes(&self, addr: Address) -> RpcResult<Vec<NoteInfoResponse>>;
}

/// Shared merkle tree state for RPC and ExEx (deprecated - use VoidgunEngine instead)
pub struct MerkleState {
    pub tree: voidgun_core::MerkleTree,
}

impl MerkleState {
    pub fn new() -> Self {
        Self {
            tree: voidgun_core::MerkleTree::new(),
        }
    }
}

impl Default for MerkleState {
    fn default() -> Self {
        Self::new()
    }
}

/// Voidgun RPC API implementation
///
/// Uses VoidgunEngine for Merkle tree state and VoidgunStorage for viewing keys/notes.
pub struct VoidgunRpc {
    #[allow(dead_code)]
    config: VoidgunConfig,
    storage: Arc<VoidgunStorage>,
    engine: Arc<Mutex<VoidgunEngine>>,
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

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Address mismatch: recovered {0}, expected {1}")]
    AddressMismatch(Address, Address),

    #[error("Account already initialized")]
    AccountExists,
}

impl From<RpcError> for ErrorObject<'static> {
    fn from(err: RpcError) -> Self {
        let code = match &err {
            RpcError::NotImplemented => -32601,
            RpcError::InvalidTransaction(_) => -32602,
            RpcError::InsufficientBalance => -32003,
            RpcError::ProofFailed(_) => -32004,
            RpcError::StorageError(_) => -32005,
            RpcError::InvalidSignature(_) => -32006,
            RpcError::AddressMismatch(_, _) => -32007,
            RpcError::AccountExists => -32008,
        };
        ErrorObject::owned(code, err.to_string(), None::<()>)
    }
}

impl VoidgunRpc {
    /// Create a new RPC handler with shared engine
    pub fn new(
        config: VoidgunConfig,
        storage: Arc<VoidgunStorage>,
        engine: Arc<Mutex<VoidgunEngine>>,
    ) -> Self {
        Self {
            config,
            storage,
            engine,
        }
    }

    /// Get the shared engine handle
    pub fn engine(&self) -> Arc<Mutex<VoidgunEngine>> {
        self.engine.clone()
    }
}

#[async_trait::async_trait]
impl VoidgunRpcApiServer for VoidgunRpc {
    async fn init_account(&self, addr: Address, signature: Bytes) -> RpcResult<bool> {
        tracing::info!("void_initAccount called for {}", addr);

        if self
            .storage
            .get_viewing_key(addr)
            .map_err(|e| RpcError::StorageError(e.to_string()))?
            .is_some()
        {
            return Err(RpcError::AccountExists.into());
        }

        if signature.len() != 65 {
            return Err(RpcError::InvalidSignature(format!(
                "Expected 65 bytes, got {}",
                signature.len()
            ))
            .into());
        }

        let r = &signature[0..32];
        let s = &signature[32..64];
        let v = signature[64];

        let recovery_id = match v {
            0 | 27 => RecoveryId::new(false, false),
            1 | 28 => RecoveryId::new(true, false),
            _ => return Err(RpcError::InvalidSignature(format!("Invalid v: {}", v)).into()),
        };

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(r);
        sig_bytes[32..].copy_from_slice(s);

        let sig = Signature::from_bytes((&sig_bytes).into())
            .map_err(|e| RpcError::InvalidSignature(e.to_string()))?;

        let message = EXPORT_VK_MESSAGE.as_bytes();
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut hash_input = prefix.into_bytes();
        hash_input.extend_from_slice(message);
        let msg_hash = keccak256(&hash_input);

        let recovered_key = VerifyingKey::recover_from_prehash(&msg_hash[..], &sig, recovery_id)
            .map_err(|e| RpcError::InvalidSignature(e.to_string()))?;

        let pk_uncompressed = recovered_key.to_encoded_point(false);
        let pk_bytes = pk_uncompressed.as_bytes();

        let pk_hash = keccak256(&pk_bytes[1..]);
        let recovered_addr = Address::from_slice(&pk_hash[12..]);

        if recovered_addr != addr {
            return Err(RpcError::AddressMismatch(recovered_addr, addr).into());
        }

        // Store uncompressed pubkey for circuit witness
        let mut pub_key_x = [0u8; 32];
        let mut pub_key_y = [0u8; 32];
        pub_key_x.copy_from_slice(&pk_bytes[1..33]);
        pub_key_y.copy_from_slice(&pk_bytes[33..65]);

        self.storage
            .put_secp_pubkey(addr, &pub_key_x, &pub_key_y)
            .map_err(|e| RpcError::StorageError(e.to_string()))?;

        let compressed_pk = recovered_key.to_encoded_point(true).as_bytes().to_vec();
        let vk = ViewingKey::derive(compressed_pk, &signature[..]);

        self.storage
            .put_viewing_key(addr, &vk)
            .map_err(|e| RpcError::StorageError(e.to_string()))?;

        let rk = vk.to_receiving_key();
        tracing::info!(
            "Initialized account {}: pnk={:?}, ek_x={:?}",
            addr,
            rk.pnk,
            rk.ek_x
        );

        Ok(true)
    }

    async fn is_initialized(&self, addr: Address) -> RpcResult<bool> {
        self.storage
            .get_viewing_key(addr)
            .map(|vk| vk.is_some())
            .map_err(|e| RpcError::StorageError(e.to_string()).into())
    }

    async fn get_receiving_key(&self, addr: Address) -> RpcResult<Option<ReceivingKeyInfo>> {
        match self
            .storage
            .get_viewing_key(addr)
            .map_err(|e| RpcError::StorageError(e.to_string()))?
        {
            Some(vk) => {
                let rk = vk.to_receiving_key();
                Ok(Some(ReceivingKeyInfo {
                    pnk: format!("{:?}", rk.pnk),
                    ek_x: format!("{:?}", rk.ek_x),
                    ek_y: format!("{:?}", rk.ek_y),
                }))
            }
            None => Ok(None),
        }
    }

    async fn send_transaction(&self, raw_tx: Bytes) -> RpcResult<ShieldedTransferResult> {
        tracing::info!("void_sendTransaction called");

        if raw_tx.is_empty() || raw_tx[0] != 0x02 {
            return Err(RpcError::InvalidTransaction(
                "Expected EIP-1559 transaction (0x02 prefix)".into(),
            )
            .into());
        }

        let signed_tx =
            decode_signed_eip1559(&raw_tx).map_err(|e| RpcError::InvalidTransaction(e))?;

        let sender = recover_signer(&signed_tx).map_err(|e| RpcError::InvalidSignature(e))?;

        tracing::info!(
            "Transaction from {} to {} for {} wei",
            sender,
            signed_tx.tx.to,
            signed_tx.tx.value
        );

        let sender_vk = self
            .storage
            .get_viewing_key(sender)
            .map_err(|e| RpcError::StorageError(e.to_string()))?
            .ok_or_else(|| {
                RpcError::InvalidTransaction(format!(
                    "Sender {} has no viewing key - call void_initAccount first",
                    sender
                ))
            })?;

        let notes = self
            .storage
            .get_unspent_notes(sender)
            .map_err(|e| RpcError::StorageError(e.to_string()))?;

        let token = Address::ZERO;
        let available: Vec<_> = notes.iter().filter(|n| n.token_type == token).collect();

        let max_gas_cost = signed_tx.tx.max_fee_per_gas * U256::from(signed_tx.tx.gas_limit);
        let total_needed = signed_tx.tx.value + max_gas_cost;

        let mut selected_value = U256::ZERO;
        let mut selected_note = None;
        for note in &available {
            if note.value >= total_needed {
                selected_note = Some(*note);
                selected_value = note.value;
                break;
            }
        }

        let input_note = selected_note.ok_or(RpcError::InsufficientBalance)?;

        let recipient = signed_tx.tx.to;
        let recipient_rk = self
            .storage
            .get_viewing_key(recipient)
            .map_err(|e| RpcError::StorageError(e.to_string()))?
            .map(|vk| vk.to_receiving_key())
            .ok_or_else(|| {
                RpcError::InvalidTransaction(format!(
                    "Recipient {} has no receiving key registered",
                    recipient
                ))
            })?;

        // Get merkle proof for input note from engine
        let (merkle_root, merkle_path) = {
            let engine = self.engine.lock().await;
            let merkle_root = engine.current_root();
            let merkle_path = engine
                .merkle_path(input_note.merkle_index)
                .map_err(|e| RpcError::StorageError(e.to_string()))?;
            (merkle_root, merkle_path)
        };

        let result = build_shielded_transfer_calldata(
            &signed_tx,
            &sender_vk,
            &input_note,
            &recipient_rk,
            recipient,
            &self.storage,
            merkle_root,
            merkle_path,
        )
        .map_err(|e| RpcError::ProofFailed(e))?;

        tracing::info!(
            "Shielded transfer prepared: input={} output={} change={}",
            input_note.value,
            signed_tx.tx.value,
            selected_value - total_needed
        );

        Ok(result)
    }

    async fn get_balance(&self, addr: Address, token: Option<Address>) -> RpcResult<U256> {
        let notes = self
            .storage
            .get_unspent_notes(addr)
            .map_err(|e| RpcError::StorageError(e.to_string()))?;

        let token_filter = token.unwrap_or(Address::ZERO);
        let total: U256 = notes
            .iter()
            .filter(|n| n.token_type == token_filter)
            .map(|n| n.value)
            .fold(U256::ZERO, |acc, v| acc + v);

        Ok(total)
    }

    async fn list_notes(&self, addr: Address) -> RpcResult<Vec<NoteInfoResponse>> {
        let notes = self
            .storage
            .get_unspent_notes(addr)
            .map_err(|e| RpcError::StorageError(e.to_string()))?;

        Ok(notes.into_iter().map(NoteInfoResponse::from).collect())
    }
}

/// Receiving key info for RPC response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceivingKeyInfo {
    pub pnk: String,
    pub ek_x: String,
    pub ek_y: String,
}

/// Note info for RPC response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteInfoResponse {
    pub commitment: String,
    pub value: String,
    pub token_type: Address,
    pub merkle_index: u64,
    pub spent: bool,
}

impl From<NoteInfo> for NoteInfoResponse {
    fn from(note: NoteInfo) -> Self {
        Self {
            commitment: format!("{:?}", note.commitment),
            value: note.value.to_string(),
            token_type: note.token_type,
            merkle_index: note.merkle_index,
            spent: note.spent,
        }
    }
}

/// Result of preparing a shielded transfer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedTransferResult {
    pub calldata: Bytes,
    pub proof: Bytes,
    pub encrypted_out: Bytes,
    pub encrypted_change: Bytes,
}

/// Decode a signed EIP-1559 transaction from RLP bytes using alloy-consensus
fn decode_signed_eip1559(raw: &[u8]) -> Result<SignedEip1559Tx, String> {
    if raw.is_empty() || raw[0] != 0x02 {
        return Err("Invalid EIP-1559 tx: missing 0x02 prefix".into());
    }

    let rlp_bytes = &raw[1..];

    let mut decoder = rlp_bytes;
    let header = alloy_rlp::Header::decode(&mut decoder)
        .map_err(|e| format!("Failed to decode RLP header: {}", e))?;

    if !header.list {
        return Err("Expected RLP list".into());
    }

    let chain_id: u64 =
        Decodable::decode(&mut decoder).map_err(|e| format!("Failed to decode chain_id: {}", e))?;
    let nonce: u64 =
        Decodable::decode(&mut decoder).map_err(|e| format!("Failed to decode nonce: {}", e))?;
    let max_priority_fee_per_gas: U256 = Decodable::decode(&mut decoder)
        .map_err(|e| format!("Failed to decode max_priority_fee_per_gas: {}", e))?;
    let max_fee_per_gas: U256 = Decodable::decode(&mut decoder)
        .map_err(|e| format!("Failed to decode max_fee_per_gas: {}", e))?;
    let gas_limit: u64 = Decodable::decode(&mut decoder)
        .map_err(|e| format!("Failed to decode gas_limit: {}", e))?;
    let to: Address =
        Decodable::decode(&mut decoder).map_err(|e| format!("Failed to decode to: {}", e))?;
    let value: U256 =
        Decodable::decode(&mut decoder).map_err(|e| format!("Failed to decode value: {}", e))?;
    let data: Bytes =
        Decodable::decode(&mut decoder).map_err(|e| format!("Failed to decode data: {}", e))?;

    let _access_list_header = alloy_rlp::Header::decode(&mut decoder)
        .map_err(|e| format!("Failed to decode access_list header: {}", e))?;

    let v: u8 = {
        let v_u64: u64 =
            Decodable::decode(&mut decoder).map_err(|e| format!("Failed to decode v: {}", e))?;
        v_u64 as u8
    };
    let r: U256 =
        Decodable::decode(&mut decoder).map_err(|e| format!("Failed to decode r: {}", e))?;
    let s: U256 =
        Decodable::decode(&mut decoder).map_err(|e| format!("Failed to decode s: {}", e))?;

    let tx = Eip1559Tx {
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        value,
        data,
    };

    Ok(SignedEip1559Tx {
        tx,
        v,
        r,
        s,
        raw: Bytes::copy_from_slice(raw),
    })
}

/// Recover signer address from a signed transaction
fn recover_signer(signed_tx: &SignedEip1559Tx) -> Result<Address, String> {
    let msg_hash = signed_tx.tx.signing_hash();

    let recovery_id = match signed_tx.v {
        0 => RecoveryId::new(false, false),
        1 => RecoveryId::new(true, false),
        27 => RecoveryId::new(false, false),
        28 => RecoveryId::new(true, false),
        _ => return Err(format!("Invalid v value: {}", signed_tx.v)),
    };

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&signed_tx.r.to_be_bytes::<32>());
    sig_bytes[32..].copy_from_slice(&signed_tx.s.to_be_bytes::<32>());

    let sig = Signature::from_bytes((&sig_bytes).into())
        .map_err(|e| format!("Invalid signature: {}", e))?;

    let recovered_key = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recovery_id)
        .map_err(|e| format!("Failed to recover pubkey: {}", e))?;

    let pk_uncompressed = recovered_key.to_encoded_point(false);
    let pk_bytes = pk_uncompressed.as_bytes();
    let pk_hash = keccak256(&pk_bytes[1..]);

    Ok(Address::from_slice(&pk_hash[12..]))
}

/// Build shielded transfer calldata including ZK proof
fn build_shielded_transfer_calldata(
    signed_tx: &SignedEip1559Tx,
    sender_vk: &ViewingKey,
    input_note: &NoteInfo,
    recipient_rk: &ReceivingKey,
    recipient_addr: Address,
    storage: &VoidgunStorage,
    merkle_root: voidgun_core::Field,
    merkle_path: Vec<voidgun_core::Field>,
) -> Result<ShieldedTransferResult, String> {
    use ark_ff::UniformRand;
    use voidgun_core::{
        address_to_field, encrypt_note, encrypted_note_to_bytes, note_nullifier, pool_id_field,
        tx_nullifier, u256_to_field, Note,
    };
    use voidgun_prover::{prove_transfer, TransferWitness};

    let mut rng = rand::thread_rng();

    // 1. Generate random trapdoors for output and change notes
    let r_out = voidgun_core::Field::rand(&mut rng);
    let r_change = voidgun_core::Field::rand(&mut rng);

    // 2. Compute note values
    let transfer_value = signed_tx.tx.value;
    let change_value = input_note.value.saturating_sub(transfer_value);

    // 3. Create output and change notes
    let sender_rk = sender_vk.to_receiving_key();
    let token = input_note.token_type;

    let note_out = Note::new(recipient_rk, transfer_value, token, r_out);
    let note_change = Note::new(&sender_rk, change_value, token, r_change);

    // 4. Compute commitments
    let cm_out = note_out.commitment();
    let cm_change = note_change.commitment();

    // 5. Compute nullifiers
    let nf_note = note_nullifier(input_note.commitment, sender_vk.nk);
    let nf_tx = tx_nullifier(
        sender_vk.nk,
        signed_tx.tx.chain_id,
        pool_id_field(),
        signed_tx.tx.to,
        signed_tx.tx.nonce,
    );

    // 6. Extract signature components
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&signed_tx.r.to_be_bytes::<32>());
    sig_bytes[32..].copy_from_slice(&signed_tx.s.to_be_bytes::<32>());

    // Recover public key for witness
    let msg_hash = signed_tx.tx.signing_hash();
    let recovery_id = match signed_tx.v {
        0 | 27 => k256::ecdsa::RecoveryId::new(false, false),
        1 | 28 => k256::ecdsa::RecoveryId::new(true, false),
        _ => return Err(format!("Invalid v: {}", signed_tx.v)),
    };

    let sig = Signature::from_bytes((&sig_bytes).into())
        .map_err(|e| format!("Invalid signature: {}", e))?;

    let recovered_key = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recovery_id)
        .map_err(|e| format!("Failed to recover pubkey: {}", e))?;

    let pk_uncompressed = recovered_key.to_encoded_point(false);
    let pk_bytes = pk_uncompressed.as_bytes();

    let mut pub_key_x = [0u8; 32];
    let mut pub_key_y = [0u8; 32];
    pub_key_x.copy_from_slice(&pk_bytes[1..33]);
    pub_key_y.copy_from_slice(&pk_bytes[33..65]);

    // 7. Get recipient's secp256k1 pubkey from storage
    let (recipient_pk_x, recipient_pk_y) = storage
        .get_secp_pubkey(recipient_addr)
        .map_err(|e| format!("Storage error: {}", e))?
        .ok_or_else(|| format!("Recipient {} has no stored pubkey", recipient_addr))?;

    // 8. Build TransferWitness using stored note randomness
    let witness = TransferWitness {
        root: merkle_root,
        cm_out,
        cm_change,
        nf_note,
        nf_tx,
        gas_tip: u256_to_field(signed_tx.tx.max_priority_fee_per_gas),
        gas_fee_cap: u256_to_field(signed_tx.tx.max_fee_per_gas),
        token_type: address_to_field(token),
        pool_id: pool_id_field(),

        tx_hash: signed_tx.tx.signing_hash(),
        tx_chain_id: signed_tx.tx.chain_id,
        tx_nonce: signed_tx.tx.nonce,
        tx_to: signed_tx.tx.to.0 .0,
        tx_value: u256_to_field(signed_tx.tx.value),
        tx_max_priority_fee: u256_to_field(signed_tx.tx.max_priority_fee_per_gas),
        tx_max_fee: u256_to_field(signed_tx.tx.max_fee_per_gas),

        signature: sig_bytes,
        pub_key_x,
        pub_key_y,

        note_in_rk_hash: input_note.rk_hash,
        note_in_value: u256_to_field(input_note.value),
        note_in_token: address_to_field(input_note.token_type),
        note_in_r: input_note.r,

        note_out_rk_hash: recipient_rk.hash(),
        note_out_value: u256_to_field(transfer_value),
        note_out_r: r_out,

        note_change_rk_hash: sender_rk.hash(),
        note_change_value: u256_to_field(change_value),
        note_change_r: r_change,

        merkle_path,
        merkle_index: input_note.merkle_index,

        nk: sender_vk.nk,

        recipient_pk_x,
        recipient_pk_y,
    };

    // 8. Generate proof
    let proof = prove_transfer(witness).map_err(|e| format!("Proof generation failed: {}", e))?;

    // 9. Encrypt notes for recipient and sender
    let encrypted_out = encrypt_note(
        &note_out,
        cm_out,
        recipient_rk.ek_x,
        recipient_rk.ek_y,
        sender_vk.ovk,
    );
    let encrypted_change = encrypt_note(
        &note_change,
        cm_change,
        sender_rk.ek_x,
        sender_rk.ek_y,
        sender_vk.ovk,
    );

    let encrypted_out_bytes = encrypted_note_to_bytes(&encrypted_out);
    let encrypted_change_bytes = encrypted_note_to_bytes(&encrypted_change);

    // 10. ABI-encode calldata for VoidgunPool.shieldedTransfer
    let public_inputs: Vec<U256> = proof
        .public_inputs
        .iter()
        .map(|b| U256::from_be_bytes(*b))
        .collect();

    let calldata = encode_shielded_transfer_calldata(
        &public_inputs,
        &proof.proof,
        &encrypted_out_bytes,
        &encrypted_change_bytes,
    );

    Ok(ShieldedTransferResult {
        calldata: Bytes::from(calldata),
        proof: Bytes::from(proof.proof),
        encrypted_out: Bytes::from(encrypted_out_bytes),
        encrypted_change: Bytes::from(encrypted_change_bytes),
    })
}

/// ABI-encode calldata for VoidgunPool.shieldedTransfer
fn encode_shielded_transfer_calldata(
    public_inputs: &[U256],
    proof: &[u8],
    ciphertext_out: &[u8],
    ciphertext_change: &[u8],
) -> Vec<u8> {
    use alloy_sol_types::{sol, SolCall};

    sol! {
        function shieldedTransfer(
            uint256[] calldata publicInputs,
            bytes calldata proof,
            bytes calldata ciphertextOut,
            bytes calldata ciphertextChange
        ) external;
    }

    let call = shieldedTransferCall {
        publicInputs: public_inputs.to_vec(),
        proof: Bytes::copy_from_slice(proof),
        ciphertextOut: Bytes::copy_from_slice(ciphertext_out),
        ciphertextChange: Bytes::copy_from_slice(ciphertext_change),
    };

    call.abi_encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_eip1559_basic() {
        let chain_id = 1u64;
        let nonce = 42u64;
        let max_priority_fee = U256::from(2_000_000_000u64);
        let max_fee = U256::from(100_000_000_000u64);
        let gas_limit = 21000u64;
        let to = Address::from_slice(&[
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
        let value = U256::from(1_000_000_000_000_000_000u64);

        use alloy_rlp::Encodable;

        let mut list_buf = Vec::new();
        chain_id.encode(&mut list_buf);
        nonce.encode(&mut list_buf);
        max_priority_fee.encode(&mut list_buf);
        max_fee.encode(&mut list_buf);
        gas_limit.encode(&mut list_buf);
        to.encode(&mut list_buf);
        value.encode(&mut list_buf);
        Bytes::new().encode(&mut list_buf);
        alloy_rlp::Header {
            list: true,
            payload_length: 0,
        }
        .encode(&mut list_buf);

        let v = 0u64;
        let r = U256::from(12345u64);
        let s = U256::from(67890u64);
        v.encode(&mut list_buf);
        r.encode(&mut list_buf);
        s.encode(&mut list_buf);

        let mut rlp_buf = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: list_buf.len(),
        }
        .encode(&mut rlp_buf);
        rlp_buf.extend_from_slice(&list_buf);

        let mut raw = vec![0x02u8];
        raw.extend_from_slice(&rlp_buf);

        let result = decode_signed_eip1559(&raw);
        assert!(result.is_ok(), "Failed to decode: {:?}", result.err());

        let signed_tx = result.unwrap();
        assert_eq!(signed_tx.tx.chain_id, chain_id);
        assert_eq!(signed_tx.tx.nonce, nonce);
        assert_eq!(signed_tx.tx.max_priority_fee_per_gas, max_priority_fee);
        assert_eq!(signed_tx.tx.max_fee_per_gas, max_fee);
        assert_eq!(signed_tx.tx.gas_limit, gas_limit);
        assert_eq!(signed_tx.tx.to, to);
        assert_eq!(signed_tx.tx.value, value);
        assert_eq!(signed_tx.v, 0);
        assert_eq!(signed_tx.r, r);
        assert_eq!(signed_tx.s, s);
    }
}
