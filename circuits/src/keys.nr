use poseidon2::bn254::{hash_2, hash_3, hash_4};

// Domain separation tag for key derivation
global DOMAIN_KEY_DERIVATION: Field = 3;

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
pub fn derive_viewing_key_components(seed: Field) -> (Field, Field, Field) {
    let nk = hash_3([DOMAIN_KEY_DERIVATION, seed, 1]);
    let ivk = hash_3([DOMAIN_KEY_DERIVATION, seed, 2]);
    let ovk = hash_3([DOMAIN_KEY_DERIVATION, seed, 3]);
    (nk, ivk, ovk)
}

/// Derive public nullifying key from nullifying key
pub fn derive_pnk(nk: Field) -> Field {
    hash_2([DOMAIN_KEY_DERIVATION, nk])
}

/// Hash a receiving key for use in note commitments
pub fn hash_receiving_key(pnk: Field, ek_x: Field, ek_y: Field) -> Field {
    hash_4([DOMAIN_KEY_DERIVATION, pnk, ek_x, ek_y])
}
