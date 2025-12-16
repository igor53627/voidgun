use ark_bn254::Fr as Field;

use crate::notes::{EncryptedNote, Note};
use crate::utils::{u256_to_field, address_to_field};

/// Encrypt a note for a recipient
/// 
/// Algorithm (from Nullmask paper):
/// 1. epk = randomScalar()
/// 2. dh_ek = epk * G
/// 3. shared_secret = Poseidon2(epk * recipient.ek)
/// 4. ciphertext = SymEncrypt(note, shared_secret)
/// 5. ek_out = shared_secret + Poseidon2(cm, sender.ovk)
pub fn encrypt_note(
    note: &Note,
    cm: Field,
    recipient_ek_x: Field,
    recipient_ek_y: Field,
    sender_ovk: Field,
) -> EncryptedNote {
    use ark_ff::UniformRand;
    
    let mut rng = rand::thread_rng();
    
    // Generate ephemeral key
    let epk = Field::rand(&mut rng);
    
    // Simplified DH: in practice need actual curve multiplication
    // dh_ek = epk * G (on embedded curve)
    let dh_ek_x = epk; // Placeholder
    let dh_ek_y = Field::from(0u64); // Placeholder
    
    // shared_secret = Poseidon2(epk * recipient.ek)
    // Simplified: just hash the scalars together
    let shared_secret = poseidon2_hash(&[epk, recipient_ek_x, recipient_ek_y]);
    
    // Encrypt note fields with Poseidon2 masking
    let ciphertext = vec![
        note.rk_hash + encryption_mask(shared_secret, 0),
        u256_to_field(note.value) + encryption_mask(shared_secret, 1),
        address_to_field(note.token_type) + encryption_mask(shared_secret, 2),
        note.r + encryption_mask(shared_secret, 3),
    ];
    
    // Compute ek_out for sender to recover
    let ek_out = shared_secret + poseidon2_hash(&[cm, sender_ovk]);
    
    EncryptedNote {
        dh_ek: (dh_ek_x, dh_ek_y),
        ek_out,
        ciphertext,
    }
}

/// Try to decrypt a note using incoming viewing key
pub fn try_decrypt_note(
    encrypted: &EncryptedNote,
    ivk: Field,
) -> Option<(Field, Field, Field, Field)> {
    // Reconstruct shared secret: ivk * dh_ek
    // Simplified: just hash the scalars together
    let shared_secret = poseidon2_hash(&[ivk, encrypted.dh_ek.0, encrypted.dh_ek.1]);
    
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
    poseidon2_hash(&[shared_secret, Field::from(index)])
}

// TODO: Implement actual Poseidon2 hash
fn poseidon2_hash(inputs: &[Field]) -> Field {
    let mut acc = Field::from(0u64);
    for (i, input) in inputs.iter().enumerate() {
        acc += *input * Field::from(i as u64 + 1);
    }
    acc
}
