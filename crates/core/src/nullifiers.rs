use ark_bn254::Fr as Field;
use ark_ff::AdditiveGroup;
use alloy_primitives::Address;

use crate::poseidon2::hash_4;
use crate::utils::address_to_field;

/// Pool contract address - included in nullifiers for cross-pool replay protection
/// This should be set to the actual deployed VoidgunPool address
pub const POOL_ID: &[u8] = b"voidgun-pool-v1";

/// Domain separation tag for nullifiers
const DOMAIN_NULLIFIER: u64 = 2;

/// Compute note nullifier with domain separation
/// nf_note = hash_3([DOMAIN_NULLIFIER, cm, nk])
pub fn note_nullifier(cm: Field, nk: Field) -> Field {
    use crate::poseidon2::hash_3;
    hash_3(Field::from(DOMAIN_NULLIFIER), cm, nk)
}

/// Compute transaction nullifier with cross-chain/pool replay protection
/// Uses sponge-style construction matching Noir circuit:
/// intermediate = hash_4([DOMAIN_NULLIFIER, nk, chain_id, 0])
/// nf_tx = hash_4([intermediate, pool_id, from, nonce])
/// 
/// This binds the shielded transfer to:
/// - A specific wallet transaction (from + nonce)
/// - A specific chain (chain_id)
/// - A specific pool deployment (pool_id)
/// 
/// This prevents:
/// - Proxy replaying the same signed transaction
/// - Cross-chain replay attacks
/// - Cross-pool replay if multiple pools exist
pub fn tx_nullifier(nk: Field, chain_id: u64, pool_id: Field, from: Address, nonce: u64) -> Field {
    let chain_id_field = Field::from(chain_id);
    let from_field = address_to_field(from);
    let nonce_field = Field::from(nonce);
    
    let intermediate = hash_4(Field::from(DOMAIN_NULLIFIER), nk, chain_id_field, Field::ZERO);
    hash_4(intermediate, pool_id, from_field, nonce_field)
}

/// Get the pool ID as a field element
pub fn pool_id_field() -> Field {
    use ark_ff::PrimeField;
    Field::from_be_bytes_mod_order(POOL_ID)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tx_nullifier_different_nonces() {
        let nk = Field::from(12345u64);
        let chain_id = 1u64;
        let pool_id = pool_id_field();
        let from = Address::ZERO;
        
        let nf1 = tx_nullifier(nk, chain_id, pool_id, from, 0);
        let nf2 = tx_nullifier(nk, chain_id, pool_id, from, 1);
        
        assert_ne!(nf1, nf2);
    }
    
    #[test]
    fn test_tx_nullifier_different_chains() {
        let nk = Field::from(12345u64);
        let pool_id = pool_id_field();
        let from = Address::ZERO;
        let nonce = 0u64;
        
        let nf_mainnet = tx_nullifier(nk, 1, pool_id, from, nonce);
        let nf_sepolia = tx_nullifier(nk, 11155111, pool_id, from, nonce);
        
        assert_ne!(nf_mainnet, nf_sepolia, "Same tx should have different nullifiers on different chains");
    }
    
    #[test]
    fn test_tx_nullifier_different_pools() {
        let nk = Field::from(12345u64);
        let chain_id = 1u64;
        let from = Address::ZERO;
        let nonce = 0u64;
        
        let pool1 = Field::from(1u64);
        let pool2 = Field::from(2u64);
        
        let nf_pool1 = tx_nullifier(nk, chain_id, pool1, from, nonce);
        let nf_pool2 = tx_nullifier(nk, chain_id, pool2, from, nonce);
        
        assert_ne!(nf_pool1, nf_pool2, "Same tx should have different nullifiers on different pools");
    }
}
