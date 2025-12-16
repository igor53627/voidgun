use dep::poseidon::poseidon2::Poseidon2;

global DOMAIN_COMMITMENT: Field = 1;
global DOMAIN_NULLIFIER: Field = 3;

struct Note {
    rk_hash: Field,
    value: Field,
    token_type: Field,
    r: Field,
}

fn commit(note: Note) -> Field {
    Poseidon2::hash([DOMAIN_COMMITMENT, note.rk_hash, note.value, note.token_type, note.r], 5)
}

pub fn nullify(cm: Field, nk: Field) -> Field {
    Poseidon2::hash([DOMAIN_NULLIFIER, cm, nk], 3)
}

pub fn tx_nullifier(nk: Field, chain_id: Field, pool_id: Field, from: Field, nonce: Field) -> Field {
    Poseidon2::hash([DOMAIN_NULLIFIER, nk, chain_id, pool_id, from, nonce], 6)
}

pub fn encryption_mask(shared_secret: Field, index: Field) -> Field {
    Poseidon2::hash([shared_secret, index], 2)
}

pub fn encrypt_field(plaintext: Field, shared_secret: Field, index: Field) -> Field {
    plaintext + encryption_mask(shared_secret, index)
}

pub fn decrypt_field(ciphertext: Field, shared_secret: Field, index: Field) -> Field {
    ciphertext - encryption_mask(shared_secret, index)
}
