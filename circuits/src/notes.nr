use std::hash::poseidon2::Poseidon2;

/// A Voidgun Note (UTXO)
struct Note {
    rk_hash: Field,      // hash of receiving key
    value: Field,        // note value
    token_type: Field,   // token identifier (0 for ETH, address for ERC20)
    r: Field,            // randomness/trapdoor for hiding
}

/// Compute note commitment
/// cm = Poseidon2(rk_hash, value, token_type, r)
pub fn commit(note: Note) -> Field {
    Poseidon2::hash([note.rk_hash, note.value, note.token_type, note.r], 4)
}

/// Compute note nullifier
/// nf = Poseidon2(cm, nk)
pub fn nullify(cm: Field, nk: Field) -> Field {
    Poseidon2::hash([cm, nk], 2)
}

/// Compute transaction nullifier (prevents replay of signed tx)
/// nf_tx = Poseidon2(nk, chain_id, from, nonce)
pub fn tx_nullifier(nk: Field, chain_id: Field, from: Field, nonce: Field) -> Field {
    Poseidon2::hash([nk, chain_id, from, nonce], 4)
}

/// Note encryption mask for field i
/// mask_i = Poseidon2(shared_secret, i)
pub fn encryption_mask(shared_secret: Field, index: Field) -> Field {
    Poseidon2::hash([shared_secret, index], 2)
}

/// Encrypt a note field
pub fn encrypt_field(plaintext: Field, shared_secret: Field, index: Field) -> Field {
    plaintext + encryption_mask(shared_secret, index)
}

/// Decrypt a note field
pub fn decrypt_field(ciphertext: Field, shared_secret: Field, index: Field) -> Field {
    ciphertext - encryption_mask(shared_secret, index)
}
