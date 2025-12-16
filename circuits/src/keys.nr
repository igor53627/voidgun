use dep::poseidon::poseidon2::Poseidon2;

global DOMAIN_KEY_DERIVATION: Field = 4;

struct ViewingKey {
    pk_x: [u8; 32],
    pk_y: [u8; 32],
    nk: Field,
    ivk: Field,
    ovk: Field,
}

struct ReceivingKey {
    pk_x: [u8; 32],
    pk_y: [u8; 32],
    pnk: Field,
    ek_x: Field,
    ek_y: Field,
}

pub fn derive_viewing_key_components(seed: Field) -> (Field, Field, Field) {
    let nk = Poseidon2::hash([DOMAIN_KEY_DERIVATION, seed, 1], 3);
    let ivk = Poseidon2::hash([DOMAIN_KEY_DERIVATION, seed, 2], 3);
    let ovk = Poseidon2::hash([DOMAIN_KEY_DERIVATION, seed, 3], 3);
    (nk, ivk, ovk)
}

pub fn derive_pnk(nk: Field) -> Field {
    Poseidon2::hash([DOMAIN_KEY_DERIVATION, nk, 0], 3)
}

pub fn hash_receiving_key(pnk: Field, ek_x: Field, ek_y: Field) -> Field {
    Poseidon2::hash([DOMAIN_KEY_DERIVATION, pnk, ek_x, ek_y], 4)
}
