use ark_bn254::Fr as Field;
use alloy_primitives::Address;

/// Compute note nullifier
/// nf_note = Poseidon2(cm, nk)
pub fn note_nullifier(cm: Field, nk: Field) -> Field {
    poseidon2_hash(&[cm, nk])
}

/// Compute transaction nullifier
/// nf_tx = Poseidon2(nk, chain_id, from, nonce)
/// 
/// This binds the shielded transfer to a specific wallet transaction,
/// preventing the proxy from replaying the same signed transaction.
pub fn tx_nullifier(nk: Field, chain_id: u64, from: Address, nonce: u64) -> Field {
    let chain_id_field = Field::from(chain_id);
    let from_field = address_to_field(from);
    let nonce_field = Field::from(nonce);
    
    poseidon2_hash(&[nk, chain_id_field, from_field, nonce_field])
}

fn address_to_field(addr: Address) -> Field {
    use ark_ff::PrimeField;
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(addr.as_slice());
    Field::from_be_bytes_mod_order(&bytes)
}

// TODO: Implement actual Poseidon2 hash
fn poseidon2_hash(inputs: &[Field]) -> Field {
    let mut acc = Field::from(0u64);
    for (i, input) in inputs.iter().enumerate() {
        acc += *input * Field::from(i as u64 + 1);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tx_nullifier_different_nonces() {
        let nk = Field::from(12345u64);
        let chain_id = 1u64;
        let from = Address::ZERO;
        
        let nf1 = tx_nullifier(nk, chain_id, from, 0);
        let nf2 = tx_nullifier(nk, chain_id, from, 1);
        
        assert_ne!(nf1, nf2);
    }
}
