use std::hash::poseidon2::Poseidon2;

/// Viewing Key components derived from wallet signature
struct ViewingKey {
    pk_x: [u8; 32],      // secp256k1 public key x
    pk_y: [u8; 32],      // secp256k1 public key y
    nk: Field,           // nullifying key
    ivk: Field,          // incoming viewing key
    ovk: Field,          // outgoing viewing key
}

/// Receiving Key - public portion for receiving funds
struct ReceivingKey {
    pk_x: [u8; 32],      // secp256k1 public key x
    pk_y: [u8; 32],      // secp256k1 public key y
    pnk: Field,          // public nullifying key = hash(nk)
    ek_x: Field,         // encryption key (curve point) x
    ek_y: Field,         // encryption key (curve point) y
}

/// Derive viewing key components from signature seed
/// seed = Poseidon2(signature)
/// nk = Poseidon2(seed, 1)
/// ivk = Poseidon2(seed, 2)
/// ovk = Poseidon2(seed, 3)
pub fn derive_viewing_key_components(seed: Field) -> (Field, Field, Field) {
    let nk = Poseidon2::hash([seed, 1], 2);
    let ivk = Poseidon2::hash([seed, 2], 2);
    let ovk = Poseidon2::hash([seed, 3], 2);
    (nk, ivk, ovk)
}

/// Derive public nullifying key from nullifying key
/// pnk = Poseidon2(nk)
pub fn derive_pnk(nk: Field) -> Field {
    Poseidon2::hash([nk], 1)
}

/// Hash a receiving key for use in note commitments
pub fn hash_receiving_key(pnk: Field, ek_x: Field, ek_y: Field) -> Field {
    Poseidon2::hash([pnk, ek_x, ek_y], 3)
}
