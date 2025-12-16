pub mod keys;
pub mod notes;
pub mod merkle;
pub mod tx;
pub mod nullifiers;
pub mod encryption;

pub use keys::{ViewingKey, ReceivingKey};
pub use notes::{Note, NoteInfo};
pub use merkle::MerkleTree;

pub type Field = ark_bn254::Fr;

pub const TREE_DEPTH: usize = 20;
pub const EXPORT_VK_MESSAGE: &str = "Authorize view-only access to Voidgun shielded account.";
