use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField};

use crate::poseidon2::hash_key_derivation;

/// Viewing Key - grants view access to account transaction history
/// Derived deterministically from wallet signature of EXPORT_VK_MESSAGE
#[derive(Clone, Debug)]
pub struct ViewingKey {
    /// Wallet's secp256k1 public key (compressed, 33 bytes)
    pub pk: Vec<u8>,
    /// Nullifying key - used to derive note nullifiers
    pub nk: Field,
    /// Incoming viewing key - for trial-decryption of incoming notes
    pub ivk: Field,
    /// Outgoing viewing key - for encrypting outgoing note receipts
    pub ovk: Field,
}

/// Receiving Key - public portion needed to send funds to this account
#[derive(Clone, Debug)]
pub struct ReceivingKey {
    /// Wallet's secp256k1 public key (compressed, 33 bytes)
    pub pk: Vec<u8>,
    /// Public nullifying key = hash(nk)
    pub pnk: Field,
    /// Encryption key x-coordinate (on BabyJubjub/BN254 embedded curve)
    pub ek_x: Field,
    /// Encryption key y-coordinate
    pub ek_y: Field,
}

impl ViewingKey {
    /// Derive viewing key from signature of EXPORT_VK_MESSAGE
    /// 
    /// Algorithm:
    /// 1. seed = Poseidon2(signature)
    /// 2. nk = Poseidon2(seed, 1)
    /// 3. ivk = Poseidon2(seed, 2)
    /// 4. ovk = Poseidon2(seed, 3)
    pub fn derive(pk: Vec<u8>, signature: &[u8]) -> Self {
        let seed = hash_key_derivation(&[field_from_bytes(signature)]);
        let nk = hash_key_derivation(&[seed, Field::from(1u64)]);
        let ivk = hash_key_derivation(&[seed, Field::from(2u64)]);
        let ovk = hash_key_derivation(&[seed, Field::from(3u64)]);
        
        Self { pk, nk, ivk, ovk }
    }
    
    /// Derive the corresponding receiving key
    pub fn to_receiving_key(&self) -> ReceivingKey {
        let pnk = hash_key_derivation(&[self.nk]);
        // Simplified: ek = ivk * G, but we just store the scalar for now
        // In practice, need to do scalar multiplication on embedded curve
        let ek_x = self.ivk;
        let ek_y = Field::from(0u64); // Placeholder
        
        ReceivingKey {
            pk: self.pk.clone(),
            pnk,
            ek_x,
            ek_y,
        }
    }
    
    /// Serialize to bytes for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // pk length + pk
        bytes.extend_from_slice(&(self.pk.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.pk);
        
        // nk, ivk, ovk (each 32 bytes)
        bytes.extend_from_slice(&self.nk.into_bigint().to_bytes_be());
        bytes.extend_from_slice(&self.ivk.into_bigint().to_bytes_be());
        bytes.extend_from_slice(&self.ovk.into_bigint().to_bytes_be());
        
        bytes
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        
        let pk_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + pk_len + 96 {
            return None;
        }
        
        let pk = bytes[4..4 + pk_len].to_vec();
        let nk = Field::from_be_bytes_mod_order(&bytes[4 + pk_len..4 + pk_len + 32]);
        let ivk = Field::from_be_bytes_mod_order(&bytes[4 + pk_len + 32..4 + pk_len + 64]);
        let ovk = Field::from_be_bytes_mod_order(&bytes[4 + pk_len + 64..4 + pk_len + 96]);
        
        Some(Self { pk, nk, ivk, ovk })
    }
}

impl ReceivingKey {
    /// Hash the receiving key for use in note commitments
    pub fn hash(&self) -> Field {
        hash_key_derivation(&[self.pnk, self.ek_x, self.ek_y])
    }
}

fn field_from_bytes(bytes: &[u8]) -> Field {
    Field::from_be_bytes_mod_order(bytes)
}
