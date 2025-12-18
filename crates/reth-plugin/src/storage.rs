use alloy_primitives::Address;
use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField};
use sled::Db;
use std::path::Path;
use thiserror::Error;

use voidgun_core::{NoteInfo, ViewingKey};

/// Operation types for reorg tracking
#[derive(Clone, Debug)]
pub enum RevertOperation {
    RemoveNote { addr: Address, merkle_index: u64 },
    UnmarkNullifier { nullifier_key: String },
    RemoveRoot { root_key: String },
}

/// Local storage for voidgun state
#[derive(Debug)]
pub struct VoidgunStorage {
    db: Db,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    DbError(#[from] sled::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Key not found")]
    NotFound,
}

impl VoidgunStorage {
    /// Open or create storage at the given path
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    /// Store a viewing key for an address
    pub fn put_viewing_key(&self, addr: Address, vk: &ViewingKey) -> Result<(), StorageError> {
        let key = format!("vk:{}", addr);
        let value = vk.to_bytes();
        self.db.insert(key.as_bytes(), value)?;
        Ok(())
    }

    /// Get a viewing key for an address
    pub fn get_viewing_key(&self, addr: Address) -> Result<Option<ViewingKey>, StorageError> {
        let key = format!("vk:{}", addr);
        match self.db.get(key.as_bytes())? {
            Some(bytes) => ViewingKey::from_bytes(&bytes)
                .ok_or_else(|| StorageError::SerializationError("Invalid viewing key".into()))
                .map(Some),
            None => Ok(None),
        }
    }

    /// Store uncompressed secp256k1 public key for an address (64 bytes: x || y)
    pub fn put_secp_pubkey(
        &self,
        addr: Address,
        pubkey_x: &[u8; 32],
        pubkey_y: &[u8; 32],
    ) -> Result<(), StorageError> {
        let key = format!("pk:{}", addr);
        let mut value = Vec::with_capacity(64);
        value.extend_from_slice(pubkey_x);
        value.extend_from_slice(pubkey_y);
        self.db.insert(key.as_bytes(), value)?;
        Ok(())
    }

    /// Get uncompressed secp256k1 public key for an address
    pub fn get_secp_pubkey(
        &self,
        addr: Address,
    ) -> Result<Option<([u8; 32], [u8; 32])>, StorageError> {
        let key = format!("pk:{}", addr);
        match self.db.get(key.as_bytes())? {
            Some(bytes) if bytes.len() >= 64 => {
                let mut x = [0u8; 32];
                let mut y = [0u8; 32];
                x.copy_from_slice(&bytes[0..32]);
                y.copy_from_slice(&bytes[32..64]);
                Ok(Some((x, y)))
            }
            _ => Ok(None),
        }
    }

    /// Store a decrypted note for an address
    pub fn add_note(&self, addr: Address, note: &NoteInfo) -> Result<(), StorageError> {
        let key = format!("note:{}:{}", addr, note.merkle_index);
        let value = note_info_to_bytes(note);
        self.db.insert(key.as_bytes(), value)?;
        Ok(())
    }

    /// Get all unspent notes for an address
    pub fn get_unspent_notes(&self, addr: Address) -> Result<Vec<NoteInfo>, StorageError> {
        let prefix = format!("note:{}:", addr);
        let mut notes = Vec::new();

        for result in self.db.scan_prefix(prefix.as_bytes()) {
            let (_, value) = result?;
            if let Some(note) = note_info_from_bytes(&value) {
                if !note.spent {
                    notes.push(note);
                }
            }
        }

        Ok(notes)
    }

    /// Mark a note as spent by nullifier
    pub fn mark_note_spent(&self, addr: Address, nullifier: Field) -> Result<(), StorageError> {
        let prefix = format!("note:{}:", addr);
        for result in self.db.scan_prefix(prefix.as_bytes()) {
            let (key, value) = result?;
            if let Some(mut note) = note_info_from_bytes(&value) {
                let note_nf = voidgun_core::poseidon2::hash_nullifier(note.commitment, nullifier);
                if note_nf == nullifier {
                    note.spent = true;
                    self.db.insert(key, note_info_to_bytes(&note))?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Get all stored viewing keys with their addresses
    pub fn get_all_viewing_keys(&self) -> Result<Vec<(Address, ViewingKey)>, StorageError> {
        let prefix = b"vk:";
        let mut keys = Vec::new();

        for result in self.db.scan_prefix(prefix) {
            let (key_bytes, value) = result?;
            let key_str = String::from_utf8_lossy(&key_bytes);
            if let Some(addr_hex) = key_str.strip_prefix("vk:") {
                if let Ok(addr) = addr_hex.parse::<Address>() {
                    if let Some(vk) = ViewingKey::from_bytes(&value) {
                        keys.push((addr, vk));
                    }
                }
            }
        }

        Ok(keys)
    }

    /// Store a known merkle root
    pub fn add_known_root(&self, root: Field) -> Result<(), StorageError> {
        let key_bytes = root.into_bigint().to_bytes_be();
        let key = format!("root:{}", hex::encode(&key_bytes));
        self.db.insert(key.as_bytes(), &[1])?;
        Ok(())
    }

    /// Check if a root is known
    pub fn is_known_root(&self, root: Field) -> Result<bool, StorageError> {
        let key_bytes = root.into_bigint().to_bytes_be();
        let key = format!("root:{}", hex::encode(&key_bytes));
        Ok(self.db.contains_key(key.as_bytes())?)
    }

    /// Store a used note nullifier
    pub fn add_note_nullifier(&self, nf: Field) -> Result<(), StorageError> {
        let key_bytes = nf.into_bigint().to_bytes_be();
        let key = format!("nf_note:{}", hex::encode(&key_bytes));
        self.db.insert(key.as_bytes(), &[1])?;
        Ok(())
    }

    /// Store a used tx nullifier
    pub fn add_tx_nullifier(&self, nf: Field) -> Result<(), StorageError> {
        let key_bytes = nf.into_bigint().to_bytes_be();
        let key = format!("nf_tx:{}", hex::encode(&key_bytes));
        self.db.insert(key.as_bytes(), &[1])?;
        Ok(())
    }

    /// Flush all pending writes
    pub fn flush(&self) -> Result<(), StorageError> {
        self.db.flush()?;
        Ok(())
    }

    /// Store revert operations for a block (for reorg handling)
    pub fn store_block_revert_ops(
        &self,
        block_number: u64,
        ops: &[RevertOperation],
    ) -> Result<(), StorageError> {
        let key = format!("revert:{}", block_number);
        let value = serialize_revert_ops(ops);
        self.db.insert(key.as_bytes(), value)?;
        Ok(())
    }

    /// Get revert operations for a block
    pub fn get_block_revert_ops(
        &self,
        block_number: u64,
    ) -> Result<Option<Vec<RevertOperation>>, StorageError> {
        let key = format!("revert:{}", block_number);
        match self.db.get(key.as_bytes())? {
            Some(bytes) => Ok(Some(deserialize_revert_ops(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Remove revert operations for a block (after it's finalized)
    pub fn remove_block_revert_ops(&self, block_number: u64) -> Result<(), StorageError> {
        let key = format!("revert:{}", block_number);
        self.db.remove(key.as_bytes())?;
        Ok(())
    }

    /// Execute revert operations for a block
    pub fn execute_revert(&self, ops: &[RevertOperation]) -> Result<(), StorageError> {
        for op in ops {
            match op {
                RevertOperation::RemoveNote { addr, merkle_index } => {
                    let key = format!("note:{}:{}", addr, merkle_index);
                    self.db.remove(key.as_bytes())?;
                }
                RevertOperation::UnmarkNullifier { nullifier_key } => {
                    self.db.remove(nullifier_key.as_bytes())?;
                }
                RevertOperation::RemoveRoot { root_key } => {
                    self.db.remove(root_key.as_bytes())?;
                }
            }
        }
        Ok(())
    }

    /// Remove a note by address and merkle index
    pub fn remove_note(&self, addr: Address, merkle_index: u64) -> Result<(), StorageError> {
        let key = format!("note:{}:{}", addr, merkle_index);
        self.db.remove(key.as_bytes())?;
        Ok(())
    }

    /// Remove a nullifier
    pub fn remove_nullifier(&self, key: &str) -> Result<(), StorageError> {
        self.db.remove(key.as_bytes())?;
        Ok(())
    }

    /// Get the last processed block number
    pub fn get_last_block(&self) -> Result<Option<u64>, StorageError> {
        match self.db.get(b"last_block")? {
            Some(bytes) if bytes.len() >= 8 => Ok(Some(u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]))),
            _ => Ok(None),
        }
    }

    /// Set the last processed block number
    pub fn set_last_block(&self, block_number: u64) -> Result<(), StorageError> {
        self.db.insert(b"last_block", &block_number.to_be_bytes())?;
        Ok(())
    }
}

fn note_info_to_bytes(note: &NoteInfo) -> Vec<u8> {
    // Layout: commitment(32) + rk_hash(32) + value(32) + token(20) + r(32) + merkle_index(8) + spent(1)
    let mut bytes = Vec::with_capacity(32 + 32 + 32 + 20 + 32 + 8 + 1);
    bytes.extend_from_slice(&note.commitment.into_bigint().to_bytes_be());
    bytes.extend_from_slice(&note.rk_hash.into_bigint().to_bytes_be());
    bytes.extend_from_slice(&note.value.to_be_bytes::<32>());
    bytes.extend_from_slice(note.token_type.as_slice());
    bytes.extend_from_slice(&note.r.into_bigint().to_bytes_be());
    bytes.extend_from_slice(&note.merkle_index.to_be_bytes());
    bytes.push(if note.spent { 1 } else { 0 });
    bytes
}

fn note_info_from_bytes(bytes: &[u8]) -> Option<NoteInfo> {
    // Layout: commitment(32) + rk_hash(32) + value(32) + token(20) + r(32) + merkle_index(8) + spent(1)
    const MIN_LEN: usize = 32 + 32 + 32 + 20 + 32 + 8 + 1;
    if bytes.len() < MIN_LEN {
        return None;
    }

    let commitment = Field::from_be_bytes_mod_order(&bytes[0..32]);
    let rk_hash = Field::from_be_bytes_mod_order(&bytes[32..64]);
    let value = alloy_primitives::U256::from_be_slice(&bytes[64..96]);
    let token_type = Address::from_slice(&bytes[96..116]);
    let r = Field::from_be_bytes_mod_order(&bytes[116..148]);
    let merkle_index = u64::from_be_bytes([
        bytes[148], bytes[149], bytes[150], bytes[151], bytes[152], bytes[153], bytes[154],
        bytes[155],
    ]);
    let spent = bytes[156] == 1;

    Some(NoteInfo {
        commitment,
        rk_hash,
        value,
        token_type,
        r,
        merkle_index,
        spent,
    })
}

fn serialize_revert_ops(ops: &[RevertOperation]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(ops.len() as u32).to_be_bytes());

    for op in ops {
        match op {
            RevertOperation::RemoveNote { addr, merkle_index } => {
                bytes.push(0);
                bytes.extend_from_slice(addr.as_slice());
                bytes.extend_from_slice(&merkle_index.to_be_bytes());
            }
            RevertOperation::UnmarkNullifier { nullifier_key } => {
                bytes.push(1);
                let key_bytes = nullifier_key.as_bytes();
                bytes.extend_from_slice(&(key_bytes.len() as u32).to_be_bytes());
                bytes.extend_from_slice(key_bytes);
            }
            RevertOperation::RemoveRoot { root_key } => {
                bytes.push(2);
                let key_bytes = root_key.as_bytes();
                bytes.extend_from_slice(&(key_bytes.len() as u32).to_be_bytes());
                bytes.extend_from_slice(key_bytes);
            }
        }
    }

    bytes
}

fn deserialize_revert_ops(bytes: &[u8]) -> Result<Vec<RevertOperation>, StorageError> {
    if bytes.len() < 4 {
        return Err(StorageError::SerializationError("Too short".into()));
    }

    let count = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let mut ops = Vec::with_capacity(count);
    let mut pos = 4;

    for _ in 0..count {
        if pos >= bytes.len() {
            return Err(StorageError::SerializationError("Unexpected end".into()));
        }

        let op_type = bytes[pos];
        pos += 1;

        match op_type {
            0 => {
                if pos + 20 + 8 > bytes.len() {
                    return Err(StorageError::SerializationError(
                        "Invalid RemoveNote".into(),
                    ));
                }
                let addr = Address::from_slice(&bytes[pos..pos + 20]);
                pos += 20;
                let merkle_index = u64::from_be_bytes([
                    bytes[pos],
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                    bytes[pos + 4],
                    bytes[pos + 5],
                    bytes[pos + 6],
                    bytes[pos + 7],
                ]);
                pos += 8;
                ops.push(RevertOperation::RemoveNote { addr, merkle_index });
            }
            1 => {
                if pos + 4 > bytes.len() {
                    return Err(StorageError::SerializationError(
                        "Invalid UnmarkNullifier".into(),
                    ));
                }
                let len = u32::from_be_bytes([
                    bytes[pos],
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                ]) as usize;
                pos += 4;
                if pos + len > bytes.len() {
                    return Err(StorageError::SerializationError(
                        "Invalid UnmarkNullifier key".into(),
                    ));
                }
                let nullifier_key = String::from_utf8_lossy(&bytes[pos..pos + len]).to_string();
                pos += len;
                ops.push(RevertOperation::UnmarkNullifier { nullifier_key });
            }
            2 => {
                if pos + 4 > bytes.len() {
                    return Err(StorageError::SerializationError(
                        "Invalid RemoveRoot".into(),
                    ));
                }
                let len = u32::from_be_bytes([
                    bytes[pos],
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                ]) as usize;
                pos += 4;
                if pos + len > bytes.len() {
                    return Err(StorageError::SerializationError(
                        "Invalid RemoveRoot key".into(),
                    ));
                }
                let root_key = String::from_utf8_lossy(&bytes[pos..pos + len]).to_string();
                pos += len;
                ops.push(RevertOperation::RemoveRoot { root_key });
            }
            _ => return Err(StorageError::SerializationError("Unknown op type".into())),
        }
    }

    Ok(ops)
}
