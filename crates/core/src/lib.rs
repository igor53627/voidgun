pub mod encryption;
pub mod keys;
pub mod merkle;
pub mod notes;
pub mod nullifiers;
pub mod poseidon2;
pub mod tx;
pub mod utils;

pub use encryption::{
    encrypt_note, encrypted_note_from_bytes, encrypted_note_to_bytes, try_decrypt_note,
};
pub use keys::{ReceivingKey, ViewingKey};
pub use merkle::{MerkleProof, MerkleTree};
pub use notes::{EncryptedNote, Note, NoteInfo};
pub use nullifiers::{note_nullifier, pool_id_field, tx_nullifier};
pub use utils::{address_to_field, u256_to_field};

pub type Field = ark_bn254::Fr;

pub const TREE_DEPTH: usize = 20;
pub const EXPORT_VK_MESSAGE: &str = "Authorize view-only access to Voidgun shielded account.";
