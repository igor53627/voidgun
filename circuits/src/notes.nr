use poseidon2::bn254::{hash_2, hash_3, hash_4};

// Domain separation tags
global DOMAIN_COMMITMENT: Field = 0;
global DOMAIN_NULLIFIER: Field = 2;

/// A Voidgun Note (UTXO)
struct Note {
    rk_hash: Field,      // hash of receiving key
    value: Field,        // note value
    token_type: Field,   // token identifier (0 for ETH, address for ERC20)
    r: Field,            // randomness/trapdoor for hiding
}

/// Compute note commitment (with domain separation)
fn commit(note: Note) -> Field {
    // Embed domain in first element
    let combined = DOMAIN_COMMITMENT * 0x1000000000000000000000000000000000000000000000000 + note.rk_hash;
    hash_4([combined, note.value, note.token_type, note.r])
}

/// Compute note nullifier (with domain separation)
pub fn nullify(cm: Field, nk: Field) -> Field {
    hash_3([DOMAIN_NULLIFIER, cm, nk])
}

/// Compute transaction nullifier with pool binding
/// Uses sponge-style construction matching Rust: hash_4 twice with domain
/// nf_tx = hash_4([intermediate, pool_id, from, nonce])
/// where intermediate = hash_4([DOMAIN_NULLIFIER, nk, chain_id, 0])
pub fn tx_nullifier(nk: Field, chain_id: Field, pool_id: Field, from: Field, nonce: Field) -> Field {
    let intermediate = hash_4([DOMAIN_NULLIFIER, nk, chain_id, 0]);
    hash_4([intermediate, pool_id, from, nonce])
}

/// Note encryption mask for field i
pub fn encryption_mask(shared_secret: Field, index: Field) -> Field {
    hash_2([shared_secret, index])
}

/// Encrypt a note field
pub fn encrypt_field(plaintext: Field, shared_secret: Field, index: Field) -> Field {
    plaintext + encryption_mask(shared_secret, index)
}

/// Decrypt a note field
pub fn decrypt_field(ciphertext: Field, shared_secret: Field, index: Field) -> Field {
    ciphertext - encryption_mask(shared_secret, index)
}
