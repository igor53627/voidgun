//! BIP32 key derivation for Baby Jubjub curve
//!
//! Railgun uses a modified BIP32 derivation that works with Baby Jubjub
//! instead of secp256k1. The key differences:
//!
//! 1. Uses "babyjubjub seed" as the HMAC key (not "Bitcoin seed")
//! 2. Only supports hardened derivation (all path segments must be >= 0x80000000)
//! 3. Derived keys are scalars on the Baby Jubjub curve

use ark_ed_on_bn254::Fr as BabyJubjubScalar;
use ark_ff::PrimeField;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use thiserror::Error;

/// BIP32 curve seed for Baby Jubjub (Railgun-specific)
const BABYJUBJUB_SEED: &[u8] = b"babyjubjub seed";

/// Hardened key offset
const HARDENED_OFFSET: u32 = 0x80000000;

#[derive(Debug, Error)]
pub enum Bip32Error {
    #[error("Invalid seed length")]
    InvalidSeedLength,

    #[error("Invalid child index (must be hardened)")]
    InvalidChildIndex,

    #[error("Key derivation failed")]
    DerivationFailed,
}

/// Extended key node for BIP32 derivation
#[derive(Clone)]
pub struct ExtendedKey {
    /// The key material (32 bytes)
    pub key: [u8; 32],
    /// The chain code for further derivation (32 bytes)
    pub chain_code: [u8; 32],
}

impl ExtendedKey {
    /// Derive master key from BIP39 seed
    ///
    /// Uses Baby Jubjub curve seed instead of Bitcoin seed
    pub fn master_from_seed(seed: &[u8]) -> Result<Self, Bip32Error> {
        if seed.len() < 16 {
            return Err(Bip32Error::InvalidSeedLength);
        }

        let mut hmac = Hmac::<Sha512>::new_from_slice(BABYJUBJUB_SEED)
            .map_err(|_| Bip32Error::DerivationFailed)?;
        hmac.update(seed);
        let result = hmac.finalize().into_bytes();

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        Ok(Self { key, chain_code })
    }

    /// Derive hardened child key
    ///
    /// Railgun only uses hardened derivation for privacy
    pub fn derive_hardened(&self, index: u32) -> Result<Self, Bip32Error> {
        if index < HARDENED_OFFSET {
            return Err(Bip32Error::InvalidChildIndex);
        }

        let mut hmac = Hmac::<Sha512>::new_from_slice(&self.chain_code)
            .map_err(|_| Bip32Error::DerivationFailed)?;

        // Hardened derivation: 0x00 || key || index
        hmac.update(&[0x00]);
        hmac.update(&self.key);
        hmac.update(&index.to_be_bytes());

        let result = hmac.finalize().into_bytes();

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        Ok(Self { key, chain_code })
    }

    /// Derive key at a full path (all segments must be hardened)
    ///
    /// Path format: [44', 1984', 0', 0', index']
    /// The ' indicates hardened (add 0x80000000)
    pub fn derive_path(&self, path: &[u32]) -> Result<Self, Bip32Error> {
        let mut current = self.clone();
        for &index in path {
            let hardened_index = if index < HARDENED_OFFSET {
                index | HARDENED_OFFSET
            } else {
                index
            };
            current = current.derive_hardened(hardened_index)?;
        }
        Ok(current)
    }

    /// Convert key bytes to Baby Jubjub scalar
    pub fn to_babyjubjub_scalar(&self) -> BabyJubjubScalar {
        BabyJubjubScalar::from_be_bytes_mod_order(&self.key)
    }
}

/// Derive Railgun spending key path
///
/// Standard path: m/44'/1984'/0'/0'/{index}'
pub fn spending_path(index: u32) -> [u32; 5] {
    [
        44 | HARDENED_OFFSET,
        1984 | HARDENED_OFFSET, // RAILGUN coin type
        0 | HARDENED_OFFSET,
        0 | HARDENED_OFFSET,
        index | HARDENED_OFFSET,
    ]
}

/// Derive Railgun viewing key path
///
/// Non-standard path: m/420'/1984'/0'/0'/{index}'
pub fn viewing_path(index: u32) -> [u32; 5] {
    [
        420 | HARDENED_OFFSET,  // Privacy purpose
        1984 | HARDENED_OFFSET, // RAILGUN coin type
        0 | HARDENED_OFFSET,
        0 | HARDENED_OFFSET,
        index | HARDENED_OFFSET,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use bip39::{Language, Mnemonic};

    #[test]
    fn test_master_key_derivation() {
        let mnemonic = Mnemonic::parse_in_normalized(
            Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();

        let seed = mnemonic.to_seed("");
        let master = ExtendedKey::master_from_seed(&seed).unwrap();

        // Master key should be 32 bytes
        assert_eq!(master.key.len(), 32);
        assert_eq!(master.chain_code.len(), 32);

        // Should be deterministic
        let master2 = ExtendedKey::master_from_seed(&seed).unwrap();
        assert_eq!(master.key, master2.key);
        assert_eq!(master.chain_code, master2.chain_code);
    }

    #[test]
    fn test_hardened_derivation() {
        let mnemonic = Mnemonic::parse_in_normalized(
            Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();

        let seed = mnemonic.to_seed("");
        let master = ExtendedKey::master_from_seed(&seed).unwrap();

        // Derive spending key path
        let spending = master.derive_path(&spending_path(0)).unwrap();
        assert_ne!(spending.key, master.key);

        // Derive viewing key path
        let viewing = master.derive_path(&viewing_path(0)).unwrap();
        assert_ne!(viewing.key, master.key);
        assert_ne!(viewing.key, spending.key);

        // Different indices should give different keys
        let spending1 = master.derive_path(&spending_path(1)).unwrap();
        assert_ne!(spending.key, spending1.key);
    }

    #[test]
    fn test_babyjubjub_scalar_conversion() {
        let mnemonic = Mnemonic::parse_in_normalized(
            Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();

        let seed = mnemonic.to_seed("");
        let master = ExtendedKey::master_from_seed(&seed).unwrap();
        let spending = master.derive_path(&spending_path(0)).unwrap();

        let scalar = spending.to_babyjubjub_scalar();

        // Scalar should be non-zero
        assert!(!scalar.is_zero());
    }
}
