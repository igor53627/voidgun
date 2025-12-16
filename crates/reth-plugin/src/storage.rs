use alloy_primitives::Address;
use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField};
use sled::Db;
use std::path::Path;
use thiserror::Error;

use voidgun_core::{ViewingKey, NoteInfo};

/// Local storage for voidgun state
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
            Some(bytes) => {
                ViewingKey::from_bytes(&bytes)
                    .ok_or_else(|| StorageError::SerializationError("Invalid viewing key".into()))
                    .map(Some)
            }
            None => Ok(None),
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
    
    /// Mark a note as spent
    pub fn mark_note_spent(&self, _addr: Address, _nullifier: Field) -> Result<(), StorageError> {
        // TODO: Implement efficient nullifier lookup
        Ok(())
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
}

fn note_info_to_bytes(note: &NoteInfo) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 32 + 20 + 8 + 1);
    bytes.extend_from_slice(&note.commitment.into_bigint().to_bytes_be());
    bytes.extend_from_slice(&note.value.to_be_bytes::<32>());
    bytes.extend_from_slice(note.token_type.as_slice());
    bytes.extend_from_slice(&note.merkle_index.to_be_bytes());
    bytes.push(if note.spent { 1 } else { 0 });
    bytes
}

fn note_info_from_bytes(bytes: &[u8]) -> Option<NoteInfo> {
    if bytes.len() < 32 + 32 + 20 + 8 + 1 {
        return None;
    }
    
    let commitment = Field::from_be_bytes_mod_order(&bytes[0..32]);
    let value = alloy_primitives::U256::from_be_slice(&bytes[32..64]);
    let token_type = Address::from_slice(&bytes[64..84]);
    let merkle_index = u64::from_be_bytes([
        bytes[84], bytes[85], bytes[86], bytes[87],
        bytes[88], bytes[89], bytes[90], bytes[91],
    ]);
    let spent = bytes[92] == 1;
    
    Some(NoteInfo {
        commitment,
        value,
        token_type,
        merkle_index,
        spent,
    })
}
