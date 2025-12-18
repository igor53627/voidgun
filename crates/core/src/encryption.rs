use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField};

use crate::notes::{EncryptedNote, Note};
use crate::poseidon2::sponge_hash;
use crate::utils::{address_to_field, u256_to_field};

const DOMAIN_ENCRYPTION: u64 = 5;

fn poseidon2_hash(inputs: &[Field]) -> Field {
    sponge_hash(inputs)
}

/// Encrypt a note for a recipient
///
/// Algorithm (from Nullmask paper):
/// 1. epk = randomScalar()
/// 2. dh_ek = epk * G
/// 3. shared_secret = Poseidon2(epk * recipient.ek)
/// 4. ciphertext = SymEncrypt(note, shared_secret)
/// 5. ek_out = shared_secret + Poseidon2(cm, sender.ovk)
///
/// Simplified DH: We use scalar multiplication on the field rather than
/// actual elliptic curve operations. For proper DH:
/// - recipient generates (sk, pk) where pk = sk * G
/// - ivk = sk (the incoming viewing key)
/// - ek = pk (the encryption key published in receiving key)
/// - Shared secret = epk * ek = epk * sk * G (for sender)
///                 = ivk * dh_ek = sk * epk * G (for recipient)
///
/// Here we simplify by computing shared_secret = epk * ek_x (scalar mult)
/// and storing epk in dh_ek so recipient can compute ivk * epk = sk * epk
pub fn encrypt_note(
    note: &Note,
    cm: Field,
    recipient_ek_x: Field,
    _recipient_ek_y: Field,
    sender_ovk: Field,
) -> EncryptedNote {
    use ark_ff::UniformRand;

    let mut rng = rand::thread_rng();

    // Generate ephemeral key scalar
    let epk = Field::rand(&mut rng);

    // Simplified DH: shared_secret = epk * recipient_ek_x
    // Store epk so recipient can compute: ivk * epk (where ivk was used to derive ek_x)
    let dh_ek_x = epk;
    let dh_ek_y = Field::from(0u64);

    // shared_secret = Poseidon2(DOMAIN_ENCRYPTION, epk * recipient_ek_x)
    let dh_scalar = epk * recipient_ek_x;
    let shared_secret = poseidon2_hash(&[Field::from(DOMAIN_ENCRYPTION), dh_scalar]);

    // Encrypt note fields with Poseidon2 masking
    let ciphertext = vec![
        note.rk_hash + encryption_mask(shared_secret, 0),
        u256_to_field(note.value) + encryption_mask(shared_secret, 1),
        address_to_field(note.token_type) + encryption_mask(shared_secret, 2),
        note.r + encryption_mask(shared_secret, 3),
    ];

    // Compute ek_out for sender to recover
    let ek_out = shared_secret + poseidon2_hash(&[Field::from(DOMAIN_ENCRYPTION), cm, sender_ovk]);

    EncryptedNote {
        dh_ek: (dh_ek_x, dh_ek_y),
        ek_out,
        ciphertext,
    }
}

/// Try to decrypt a note using incoming viewing key
///
/// For simplified DH:
/// - dh_ek.0 contains epk (the ephemeral key scalar)
/// - Sender computed: shared_secret = Poseidon2(epk * ek_x)
/// - ek_x was derived from ivk, so: shared_secret = Poseidon2(epk * f(ivk))
///
/// The recipient has ivk, but needs to compute the same DH.
/// We need ek_x = f(ivk) where f is the key derivation function.
/// Then: dh_scalar = epk * ek_x = epk * f(ivk)
pub fn try_decrypt_note(
    encrypted: &EncryptedNote,
    ek_x: Field,
) -> Option<(Field, Field, Field, Field)> {
    // Reconstruct shared secret: epk * ek_x (same as sender computed)
    let epk = encrypted.dh_ek.0;
    let dh_scalar = epk * ek_x;
    let shared_secret = poseidon2_hash(&[Field::from(DOMAIN_ENCRYPTION), dh_scalar]);

    // Decrypt fields
    if encrypted.ciphertext.len() < 4 {
        return None;
    }

    let rk_hash = encrypted.ciphertext[0] - encryption_mask(shared_secret, 0);
    let value = encrypted.ciphertext[1] - encryption_mask(shared_secret, 1);
    let token = encrypted.ciphertext[2] - encryption_mask(shared_secret, 2);
    let r = encrypted.ciphertext[3] - encryption_mask(shared_secret, 3);

    Some((rk_hash, value, token, r))
}

fn encryption_mask(shared_secret: Field, index: u64) -> Field {
    poseidon2_hash(&[
        Field::from(DOMAIN_ENCRYPTION),
        shared_secret,
        Field::from(index),
    ])
}

/// Serialize an EncryptedNote to bytes
pub fn encrypted_note_to_bytes(enc: &EncryptedNote) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 * 3 + 32 * enc.ciphertext.len());

    // dh_ek.0 (32 bytes)
    bytes.extend_from_slice(&enc.dh_ek.0.into_bigint().to_bytes_be());
    // dh_ek.1 (32 bytes)
    bytes.extend_from_slice(&enc.dh_ek.1.into_bigint().to_bytes_be());
    // ek_out (32 bytes)
    bytes.extend_from_slice(&enc.ek_out.into_bigint().to_bytes_be());
    // ciphertext length (4 bytes)
    bytes.extend_from_slice(&(enc.ciphertext.len() as u32).to_be_bytes());
    // ciphertext fields
    for field in &enc.ciphertext {
        bytes.extend_from_slice(&field.into_bigint().to_bytes_be());
    }

    bytes
}

/// Deserialize an EncryptedNote from bytes
pub fn encrypted_note_from_bytes(bytes: &[u8]) -> Option<EncryptedNote> {
    if bytes.len() < 32 * 3 + 4 {
        return None;
    }

    let dh_ek_x = Field::from_be_bytes_mod_order(&bytes[0..32]);
    let dh_ek_y = Field::from_be_bytes_mod_order(&bytes[32..64]);
    let ek_out = Field::from_be_bytes_mod_order(&bytes[64..96]);
    let ct_len = u32::from_be_bytes([bytes[96], bytes[97], bytes[98], bytes[99]]) as usize;

    if bytes.len() < 100 + ct_len * 32 {
        return None;
    }

    let mut ciphertext = Vec::with_capacity(ct_len);
    for i in 0..ct_len {
        let start = 100 + i * 32;
        ciphertext.push(Field::from_be_bytes_mod_order(&bytes[start..start + 32]));
    }

    Some(EncryptedNote {
        dh_ek: (dh_ek_x, dh_ek_y),
        ek_out,
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ViewingKey;
    use crate::notes::Note;
    use alloy_primitives::{Address, U256};

    #[test]
    fn test_encryption_round_trip() {
        let sig = vec![1u8; 65];
        let pk = vec![2u8; 33];
        let vk = ViewingKey::derive(pk, &sig);
        let rk = vk.to_receiving_key();

        let r = Field::from(12345u64);
        let note = Note::new(&rk, U256::from(1000u64), Address::ZERO, r);
        let cm = note.commitment();

        let encrypted = encrypt_note(&note, cm, rk.ek_x, rk.ek_y, vk.ovk);

        let (dec_rk_hash, dec_value, dec_token, dec_r) =
            try_decrypt_note(&encrypted, rk.ek_x).expect("decryption should succeed");

        assert_eq!(dec_rk_hash, note.rk_hash);
        assert_eq!(dec_value, u256_to_field(note.value));
        assert_eq!(dec_token, address_to_field(note.token_type));
        assert_eq!(dec_r, note.r);

        let recomputed_cm =
            crate::poseidon2::hash_commitment(dec_rk_hash, dec_value, dec_token, dec_r);
        assert_eq!(recomputed_cm, cm);
    }

    #[test]
    fn test_encrypted_note_serialization() {
        let sig = vec![1u8; 65];
        let pk = vec![2u8; 33];
        let vk = ViewingKey::derive(pk, &sig);
        let rk = vk.to_receiving_key();

        let r = Field::from(999u64);
        let note = Note::new(&rk, U256::from(5000u64), Address::ZERO, r);
        let cm = note.commitment();

        let encrypted = encrypt_note(&note, cm, rk.ek_x, rk.ek_y, vk.ovk);

        let bytes = encrypted_note_to_bytes(&encrypted);
        let deserialized =
            encrypted_note_from_bytes(&bytes).expect("deserialization should succeed");

        assert_eq!(deserialized.dh_ek.0, encrypted.dh_ek.0);
        assert_eq!(deserialized.dh_ek.1, encrypted.dh_ek.1);
        assert_eq!(deserialized.ek_out, encrypted.ek_out);
        assert_eq!(deserialized.ciphertext.len(), encrypted.ciphertext.len());
        for (a, b) in deserialized
            .ciphertext
            .iter()
            .zip(encrypted.ciphertext.iter())
        {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let sig1 = vec![1u8; 65];
        let sig2 = vec![2u8; 65];
        let pk1 = vec![3u8; 33];
        let pk2 = vec![4u8; 33];

        let vk1 = ViewingKey::derive(pk1, &sig1);
        let vk2 = ViewingKey::derive(pk2, &sig2);
        let rk1 = vk1.to_receiving_key();
        let rk2 = vk2.to_receiving_key();

        let r = Field::from(54321u64);
        let note = Note::new(&rk1, U256::from(2000u64), Address::ZERO, r);
        let cm = note.commitment();

        let encrypted = encrypt_note(&note, cm, rk1.ek_x, rk1.ek_y, vk1.ovk);

        // Decrypt with wrong key should give wrong commitment
        let (dec_rk_hash, dec_value, dec_token, dec_r) =
            try_decrypt_note(&encrypted, rk2.ek_x).expect("decryption should return values");

        let wrong_cm = crate::poseidon2::hash_commitment(dec_rk_hash, dec_value, dec_token, dec_r);
        assert_ne!(
            wrong_cm, cm,
            "Wrong key should produce different commitment"
        );
    }
}
