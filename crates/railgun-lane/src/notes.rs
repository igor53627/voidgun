//! Railgun note structure and encryption
//!
//! Notes are the UTXO-like primitives in Railgun's privacy system.
//!
//! Encryption uses:
//! - X25519 ECDH to derive shared secret from ephemeral keypair + recipient viewing key
//! - ChaCha20-Poly1305 AEAD for authenticated encryption

use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use once_cell::sync::Lazy;
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

#[derive(Debug, Error)]
pub enum NoteError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid note data: {0}")]
    InvalidNote(String),
}

/// Railgun note (unencrypted)
#[derive(Clone, Debug)]
pub struct RailgunNote {
    /// Nullifier public key (derived from master public key)
    pub npk: Field,
    /// Note value
    pub value: u128,
    /// Token address (as field element)
    pub token: Field,
    /// Random blinding factor
    pub random: Field,
}

impl RailgunNote {
    /// Create a new note for a recipient
    pub fn new(recipient_mpk: Field, value: u128, token: Field, random: Field) -> Self {
        // NPK is derived from recipient's master public key
        // From JoinSplit.circom: npk = Poseidon(mpk, random)
        let npk = crate::poseidon::poseidon2(recipient_mpk, random);

        Self {
            npk,
            value,
            token,
            random,
        }
    }

    /// Compute note commitment (Railgun v2 JoinSplit compatible)
    ///
    /// From JoinSplit.circom:
    ///   outNoteHash = Poseidon(npkOut, token, valueOut)
    ///
    /// This is a 3-input Poseidon hash with order: npk, token, value
    pub fn commitment(&self) -> Field {
        crate::poseidon::poseidon3(self.npk, self.token, Field::from(self.value))
    }

    /// Compute nullifier using owner's nullifying key (legacy/Voidgun style)
    ///
    /// nf = Poseidon(commitment, nullifying_key)
    ///
    /// NOTE: This is NOT the same as Railgun v2 JoinSplit circuits!
    /// Use `joinsplit_nullifier()` for circuit-compatible nullifiers.
    pub fn nullifier(&self, nullifying_key: Field) -> Field {
        crate::poseidon::poseidon2(self.commitment(), nullifying_key)
    }

    /// Compute nullifier for Railgun v2 JoinSplit circuits
    ///
    /// From nullifier-check.circom:
    ///   nullifier = Poseidon(nullifyingKey, leafIndex)
    ///
    /// This is the circuit-compatible nullifier formula.
    pub fn joinsplit_nullifier(nullifying_key: Field, leaf_index: u64) -> Field {
        crate::poseidon::poseidon2(nullifying_key, Field::from(leaf_index))
    }
}

/// Encrypted note (on-chain format)
///
/// Uses X25519 ECDH + ChaCha20-Poly1305 AEAD encryption.
#[derive(Clone, Debug)]
pub struct EncryptedNote {
    /// Ephemeral X25519 public key for ECDH
    pub ephemeral_key: [u8; 32],
    /// ChaCha20-Poly1305 ciphertext (includes 16-byte auth tag)
    pub ciphertext: Vec<u8>,
}

/// Nonce size for ChaCha20-Poly1305 (12 bytes)
const NONCE_SIZE: usize = 12;

impl EncryptedNote {
    /// Encrypt a note for a recipient using X25519 + ChaCha20-Poly1305
    ///
    /// 1. Generate ephemeral X25519 keypair
    /// 2. Perform ECDH with recipient's viewing public key
    /// 3. Derive symmetric key from shared secret using SHA3-256
    /// 4. Encrypt serialized note with ChaCha20-Poly1305
    pub fn encrypt(
        note: &RailgunNote,
        recipient_viewing_pub: &[u8; 32],
    ) -> Result<Self, NoteError> {
        // Generate ephemeral X25519 keypair
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Perform ECDH
        let recipient_public = PublicKey::from(*recipient_viewing_pub);
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);

        // Derive symmetric key using SHA3-256
        let mut hasher = Sha3_256::new();
        hasher.update(b"railgun-note-encryption-v1");
        hasher.update(shared_secret.as_bytes());
        hasher.update(ephemeral_public.as_bytes());
        let key_material = hasher.finalize();

        // Serialize note fields: npk (32) + value (16) + token (32) + random (32) = 112 bytes
        let mut plaintext = Vec::with_capacity(112);
        plaintext.extend_from_slice(&note.npk.into_bigint().to_bytes_be());
        plaintext.extend_from_slice(&note.value.to_be_bytes());
        plaintext.extend_from_slice(&note.token.into_bigint().to_bytes_be());
        plaintext.extend_from_slice(&note.random.into_bigint().to_bytes_be());

        // Create cipher and encrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&key_material)
            .map_err(|e| NoteError::EncryptionFailed(e.to_string()))?;

        // Generate nonce from hash of ephemeral public key
        let mut nonce_hasher = Sha3_256::new();
        nonce_hasher.update(b"railgun-nonce");
        nonce_hasher.update(ephemeral_public.as_bytes());
        let nonce_hash = nonce_hasher.finalize();
        let nonce = Nonce::from_slice(&nonce_hash[..NONCE_SIZE]);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_slice())
            .map_err(|e| NoteError::EncryptionFailed(e.to_string()))?;

        Ok(Self {
            ephemeral_key: *ephemeral_public.as_bytes(),
            ciphertext,
        })
    }

    /// Try to decrypt a note using viewing private key
    ///
    /// Returns the decrypted note if the ciphertext was intended for this viewing key.
    /// Used for "trial decryption" when scanning on-chain events.
    pub fn try_decrypt(&self, viewing_secret: &[u8; 32]) -> Result<RailgunNote, NoteError> {
        // Reconstruct shared secret using ECDH
        let secret = StaticSecret::from(*viewing_secret);
        let ephemeral_public = PublicKey::from(self.ephemeral_key);
        let shared_secret = secret.diffie_hellman(&ephemeral_public);

        // Derive symmetric key (same as encryption)
        let mut hasher = Sha3_256::new();
        hasher.update(b"railgun-note-encryption-v1");
        hasher.update(shared_secret.as_bytes());
        hasher.update(&self.ephemeral_key);
        let key_material = hasher.finalize();

        // Recreate nonce
        let mut nonce_hasher = Sha3_256::new();
        nonce_hasher.update(b"railgun-nonce");
        nonce_hasher.update(&self.ephemeral_key);
        let nonce_hash = nonce_hasher.finalize();
        let nonce = Nonce::from_slice(&nonce_hash[..NONCE_SIZE]);

        // Create cipher and decrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&key_material)
            .map_err(|e| NoteError::DecryptionFailed(e.to_string()))?;

        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|_| NoteError::DecryptionFailed("auth tag mismatch".into()))?;

        // Deserialize (112 bytes expected)
        if plaintext.len() < 112 {
            return Err(NoteError::InvalidNote(format!(
                "plaintext too short: {} < 112",
                plaintext.len()
            )));
        }

        let npk = Field::from_be_bytes_mod_order(&plaintext[0..32]);
        let value = u128::from_be_bytes(
            plaintext[32..48]
                .try_into()
                .map_err(|_| NoteError::InvalidNote("value parse failed".into()))?,
        );
        let token = Field::from_be_bytes_mod_order(&plaintext[48..80]);
        let random = Field::from_be_bytes_mod_order(&plaintext[80..112]);

        Ok(RailgunNote {
            npk,
            value,
            token,
            random,
        })
    }

    /// Serialize to on-chain format
    ///
    /// Format: ephemeral_key (32) || ciphertext (128 = 112 + 16 tag)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + self.ciphertext.len());
        bytes.extend_from_slice(&self.ephemeral_key);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Parse from on-chain format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NoteError> {
        if bytes.len() < 32 + 16 {
            // Need at least ephemeral key + auth tag
            return Err(NoteError::InvalidNote("bytes too short".into()));
        }

        let mut ephemeral_key = [0u8; 32];
        ephemeral_key.copy_from_slice(&bytes[0..32]);

        Ok(Self {
            ephemeral_key,
            ciphertext: bytes[32..].to_vec(),
        })
    }
}

/// Shield ciphertext structure (different from Transact ciphertext)
///
/// Shield ciphertext format:
/// - encryptedBundle[3]: 3 x 32 bytes = 96 bytes of AES-GCM ciphertext
/// - shieldKey: 32 bytes - sender's random key used for ECDH
///
/// The encrypted data contains: random (32 bytes) for deriving NPK
/// The receiver can decrypt using their viewing key to get the random value,
/// then reconstruct the note using the public preimage (token, value, npk).
#[derive(Clone, Debug)]
pub struct ShieldCiphertext {
    /// Encrypted bundle (3 x 32 bytes = 96 bytes containing random + padding)
    pub encrypted_bundle: [[u8; 32]; 3],
    /// Shield key (sender's ephemeral public key for ECDH)
    pub shield_key: [u8; 32],
}

impl ShieldCiphertext {
    /// Try to decrypt the shield ciphertext using the viewing secret
    ///
    /// For shield events, the ciphertext contains the `random` value used
    /// to derive NPK = Poseidon(masterPublicKey, random).
    ///
    /// The receiver needs to:
    /// 1. ECDH with shieldKey using their viewing private key
    /// 2. Derive AES key from shared secret
    /// 3. Decrypt to get the random value
    /// 4. Use random + their MPK to verify NPK matches
    pub fn try_decrypt(&self, viewing_secret: &[u8; 32]) -> Result<[u8; 32], NoteError> {
        use aes_gcm::{aead::Aead as AesAead, Aes256Gcm, KeyInit as AesKeyInit, Nonce as AesNonce};

        let secret = StaticSecret::from(*viewing_secret);
        let shield_public = PublicKey::from(self.shield_key);
        let shared_secret = secret.diffie_hellman(&shield_public);

        let mut hasher = Sha3_256::new();
        hasher.update(b"railgun-shield-v1");
        hasher.update(shared_secret.as_bytes());
        hasher.update(&self.shield_key);
        let key_material = hasher.finalize();

        let mut nonce_hasher = Sha3_256::new();
        nonce_hasher.update(b"railgun-shield-nonce");
        nonce_hasher.update(&self.shield_key);
        let nonce_hash = nonce_hasher.finalize();
        let nonce = AesNonce::from_slice(&nonce_hash[..12]);

        let cipher = Aes256Gcm::new_from_slice(&key_material)
            .map_err(|e| NoteError::DecryptionFailed(e.to_string()))?;

        let mut ciphertext_bytes = Vec::with_capacity(96);
        for chunk in &self.encrypted_bundle {
            ciphertext_bytes.extend_from_slice(chunk);
        }

        let plaintext = cipher
            .decrypt(nonce, ciphertext_bytes.as_slice())
            .map_err(|_| NoteError::DecryptionFailed("shield decryption failed".into()))?;

        if plaintext.len() < 32 {
            return Err(NoteError::InvalidNote("decrypted data too short".into()));
        }

        let mut random = [0u8; 32];
        random.copy_from_slice(&plaintext[..32]);
        Ok(random)
    }

    /// Create from parsed shield ciphertext
    pub fn from_parsed(parsed: &crate::contracts::ParsedShieldCiphertext) -> Self {
        Self {
            encrypted_bundle: parsed.encrypted_bundle,
            shield_key: parsed.shield_key,
        }
    }
}

/// Railgun's ZERO_VALUE = keccak256("Railgun") % SNARK_SCALAR_FIELD
/// This is used for empty leaves in the Merkle tree.
/// From Railgun's PoseidonMerkle.sol:
/// `bytes32 internal constant ZERO_VALUE = bytes32(uint256(keccak256("Railgun")) % SNARK_SCALAR_FIELD);`
pub static ZERO_VALUE: Lazy<Field> = Lazy::new(|| {
    use sha3::{Digest, Keccak256};
    let hash = Keccak256::digest(b"Railgun");
    Field::from_be_bytes_mod_order(&hash)
});

/// Precomputed zero hashes for each level of the Merkle tree (depth 16).
/// ZERO_HASHES[0] = ZERO_VALUE (empty leaf)
/// ZERO_HASHES[i] = Poseidon2(ZERO_HASHES[i-1], ZERO_HASHES[i-1])
pub static ZERO_HASHES: Lazy<[Field; 17]> = Lazy::new(|| {
    let mut zeros = [Field::from(0u64); 17];
    zeros[0] = *ZERO_VALUE;
    for i in 1..17 {
        zeros[i] = crate::poseidon::poseidon2(zeros[i - 1], zeros[i - 1]);
    }
    zeros
});

/// Merkle tree for note commitments
pub struct NoteMerkleTree {
    /// Tree depth (Railgun uses 16)
    pub depth: usize,
    /// Current leaves
    pub leaves: Vec<Field>,
    /// Cached intermediate nodes (for efficient updates)
    pub nodes: Vec<Vec<Field>>,
}

impl NoteMerkleTree {
    pub fn new(depth: usize) -> Self {
        let mut nodes = Vec::with_capacity(depth + 1);
        for level in 0..=depth {
            let size = 1 << (depth - level);
            // Initialize with precomputed zero hashes for this level
            nodes.push(vec![ZERO_HASHES[level]; size]);
        }

        Self {
            depth,
            leaves: Vec::new(),
            nodes,
        }
    }

    /// Insert a new leaf and return its index
    pub fn insert(&mut self, leaf: Field) -> u64 {
        let index = self.leaves.len() as u64;
        self.leaves.push(leaf);

        // Update tree
        self.nodes[0][index as usize] = leaf;
        let mut current_idx = index as usize;

        for level in 0..self.depth {
            let sibling_idx = current_idx ^ 1;
            let sibling = self.nodes[level]
                .get(sibling_idx)
                .copied()
                .unwrap_or(ZERO_HASHES[level]);

            let parent_idx = current_idx / 2;
            let (left, right) = if current_idx % 2 == 0 {
                (self.nodes[level][current_idx], sibling)
            } else {
                (sibling, self.nodes[level][current_idx])
            };

            self.nodes[level + 1][parent_idx] = crate::poseidon::poseidon2(left, right);
            current_idx = parent_idx;
        }

        index
    }

    /// Batch insert leaves without computing intermediate nodes during insertion.
    /// Call `rebuild()` afterwards to compute the full tree.
    /// Returns the number of leaves actually inserted (may be less than input if tree is full).
    pub fn batch_insert(&mut self, leaves: &[Field]) -> usize {
        let max_leaves = 1 << self.depth;
        let mut inserted = 0;

        for leaf in leaves {
            let index = self.leaves.len();
            if index >= max_leaves {
                break;
            }
            self.leaves.push(*leaf);
            self.nodes[0][index] = *leaf;
            inserted += 1;
        }

        inserted
    }

    /// Rebuild the tree from leaves (after batch_insert).
    /// Uses parallel computation for speed.
    pub fn rebuild(&mut self) {
        use rayon::prelude::*;

        let num_leaves = self.leaves.len();
        if num_leaves == 0 {
            return;
        }

        // For each level, compute parent nodes from children
        for level in 0..self.depth {
            let child_level = &self.nodes[level];
            let num_parents = (child_level.len() + 1) / 2;

            // Compute all parents in parallel
            let zero_hash = ZERO_HASHES[level];
            let parents: Vec<Field> = (0..num_parents)
                .into_par_iter()
                .map(|i| {
                    let left_idx = i * 2;
                    let right_idx = left_idx + 1;
                    let left = child_level[left_idx];
                    let right = child_level.get(right_idx).copied().unwrap_or(zero_hash);
                    crate::poseidon::poseidon2(left, right)
                })
                .collect();

            // Copy to parent level
            for (i, parent) in parents.into_iter().enumerate() {
                self.nodes[level + 1][i] = parent;
            }
        }
    }

    /// Get current root
    pub fn root(&self) -> Field {
        self.nodes[self.depth][0]
    }

    /// Get merkle proof for a leaf
    pub fn proof(&self, index: u64) -> Vec<Field> {
        let mut path = Vec::with_capacity(self.depth);
        let mut current_idx = index as usize;

        for level in 0..self.depth {
            let sibling_idx = current_idx ^ 1;
            let sibling = self.nodes[level]
                .get(sibling_idx)
                .copied()
                .unwrap_or(ZERO_HASHES[level]);
            path.push(sibling);
            current_idx /= 2;
        }

        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{UniformRand, Zero};

    #[test]
    fn test_note_commitment() {
        let mut rng = rand::thread_rng();

        let note = RailgunNote {
            npk: Field::rand(&mut rng),
            value: 1_000_000_000_000_000_000, // 1 ETH
            token: Field::from(0u64),         // ETH
            random: Field::rand(&mut rng),
        };

        let cm = note.commitment();
        assert!(!cm.is_zero());

        // Deterministic
        let cm2 = note.commitment();
        assert_eq!(cm, cm2);
    }

    #[test]
    fn test_note_nullifier() {
        let mut rng = rand::thread_rng();
        let nk = Field::rand(&mut rng);

        let note = RailgunNote {
            npk: Field::rand(&mut rng),
            value: 1_000_000_000_000_000_000,
            token: Field::from(0u64),
            random: Field::rand(&mut rng),
        };

        let nf = note.nullifier(nk);
        assert!(!nf.is_zero());

        // Same note + same nk = same nullifier
        let nf2 = note.nullifier(nk);
        assert_eq!(nf, nf2);

        // Different nk = different nullifier
        let nk2 = Field::rand(&mut rng);
        let nf3 = note.nullifier(nk2);
        assert_ne!(nf, nf3);
    }

    #[test]
    fn test_merkle_tree() {
        let mut tree = NoteMerkleTree::new(4); // Small tree for testing

        let leaf1 = Field::from(1u64);
        let leaf2 = Field::from(2u64);

        let idx1 = tree.insert(leaf1);
        let root1 = tree.root();

        let idx2 = tree.insert(leaf2);
        let root2 = tree.root();

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_ne!(root1, root2);

        // Proof should have correct length
        let proof = tree.proof(0);
        assert_eq!(proof.len(), 4);
    }
}
