use ark_bn254::Fr as Field;
use ark_ff::PrimeField;
use alloy_primitives::{Address, U256};

use crate::keys::ReceivingKey;
use crate::poseidon2::{hash_commitment, hash_nullifier};

/// A Voidgun Note (UTXO in the shielded pool)
#[derive(Clone, Debug)]
pub struct Note {
    /// Receiving key hash of the owner
    pub rk_hash: Field,
    /// Note value
    pub value: U256,
    /// Token type (zero address for ETH, otherwise ERC20 address)
    pub token_type: Address,
    /// Random trapdoor for hiding commitment
    pub r: Field,
}

/// Encrypted note as stored on-chain
#[derive(Clone, Debug)]
pub struct EncryptedNote {
    /// Ephemeral DH key for recipient (x, y)
    pub dh_ek: (Field, Field),
    /// Encrypted shared secret for sender (outgoing viewing)
    pub ek_out: Field,
    /// Encrypted note fields (masked with Poseidon2)
    pub ciphertext: Vec<Field>,
}

impl Note {
    /// Create a new note
    pub fn new(rk: &ReceivingKey, value: U256, token_type: Address, r: Field) -> Self {
        Self {
            rk_hash: rk.hash(),
            value,
            token_type,
            r,
        }
    }
    
    /// Compute note commitment
    /// cm = Poseidon2(DOMAIN_COMMITMENT, rk_hash, value, token_type, r)
    pub fn commitment(&self) -> Field {
        let value_field = u256_to_field(self.value);
        let token_field = address_to_field(self.token_type);
        hash_commitment(&[self.rk_hash, value_field, token_field, self.r])
    }
    
    /// Compute note nullifier given the nullifying key
    /// nf = Poseidon2(DOMAIN_NULLIFIER, cm, nk)
    pub fn nullifier(&self, nk: Field) -> Field {
        let cm = self.commitment();
        hash_nullifier(&[cm, nk])
    }
}

/// Information about a note for display/querying
#[derive(Clone, Debug)]
pub struct NoteInfo {
    pub commitment: Field,
    pub value: U256,
    pub token_type: Address,
    pub merkle_index: u64,
    pub spent: bool,
}

pub fn u256_to_field(value: U256) -> Field {
    Field::from_be_bytes_mod_order(&value.to_be_bytes::<32>())
}

pub fn address_to_field(addr: Address) -> Field {
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(addr.as_slice());
    Field::from_be_bytes_mod_order(&bytes)
}
