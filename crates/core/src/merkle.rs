use ark_bn254::Fr as Field;
use ark_ff::Zero;

use crate::poseidon2::hash_merkle_node;
use crate::TREE_DEPTH;

/// Incremental Merkle tree for note commitments
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Current number of leaves
    pub next_index: u64,
    /// Filled subtrees at each level
    filled_subtrees: Vec<Field>,
    /// All inserted leaves (for proof generation)
    leaves: Vec<Field>,
    /// Current root
    root: Field,
    /// Zero values at each level (for empty subtrees)
    zeros: Vec<Field>,
}

/// Merkle proof for a leaf
#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub leaf: Field,
    pub index: u64,
    pub path: Vec<Field>,
    pub root: Field,
}

impl MerkleTree {
    /// Create a new empty Merkle tree
    pub fn new() -> Self {
        let zeros = Self::compute_zeros();
        let root = zeros[TREE_DEPTH];

        Self {
            next_index: 0,
            filled_subtrees: zeros[..TREE_DEPTH].to_vec(),
            leaves: Vec::new(),
            root,
            zeros,
        }
    }

    /// Get current root
    pub fn root(&self) -> Field {
        self.root
    }

    /// Insert a leaf and return its index
    pub fn insert(&mut self, leaf: Field) -> u64 {
        let index = self.next_index;
        let mut current_index = index;
        let mut current_level_hash = leaf;

        // Store the leaf for proof generation
        self.leaves.push(leaf);

        for i in 0..TREE_DEPTH {
            let (left, right) = if current_index % 2 == 0 {
                self.filled_subtrees[i] = current_level_hash;
                (current_level_hash, self.zeros[i])
            } else {
                (self.filled_subtrees[i], current_level_hash)
            };

            current_level_hash = hash_merkle_node(left, right);
            current_index /= 2;
        }

        self.root = current_level_hash;
        self.next_index += 1;

        index
    }

    /// Generate a Merkle proof for a leaf at given index
    /// Uses optimized bottom-up approach instead of recursive computation
    pub fn proof(&self, index: u64, leaf: Field) -> MerkleProof {
        let mut path = Vec::with_capacity(TREE_DEPTH);
        let mut current_index = index as usize;

        // Compute all nodes level by level (bottom-up, cached)
        let mut current_level: Vec<Field> = self.leaves.clone();

        for level in 0..TREE_DEPTH {
            // Pad current level to even length with zeros
            if current_level.len() % 2 == 1 {
                current_level.push(self.zeros[level]);
            }
            if current_level.is_empty() {
                current_level.push(self.zeros[level]);
                current_level.push(self.zeros[level]);
            }

            // Get sibling at this level
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling = if sibling_index < current_level.len() {
                current_level[sibling_index]
            } else {
                self.zeros[level]
            };
            path.push(sibling);

            // Compute next level
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    self.zeros[level]
                };
                next_level.push(hash_merkle_node(left, right));
            }

            current_level = next_level;
            current_index /= 2;
        }

        MerkleProof {
            leaf,
            index,
            path,
            root: self.root,
        }
    }

    /// Compute zero values for empty tree
    fn compute_zeros() -> Vec<Field> {
        let mut zeros = vec![Field::zero()];

        for i in 0..TREE_DEPTH {
            let next = hash_merkle_node(zeros[i], zeros[i]);
            zeros.push(next);
        }

        zeros
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleProof {
    /// Verify this proof against a root
    pub fn verify(&self, expected_root: Field) -> bool {
        let computed_root = self.compute_root();
        computed_root == expected_root
    }

    /// Compute the root from this proof
    pub fn compute_root(&self) -> Field {
        let mut current = self.leaf;
        let mut index = self.index;

        for sibling in &self.path {
            let (left, right) = if index % 2 == 0 {
                (current, *sibling)
            } else {
                (*sibling, current)
            };

            current = hash_merkle_node(left, right);
            index /= 2;
        }

        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new();
        assert_eq!(tree.next_index, 0);
    }

    #[test]
    fn test_insert() {
        let mut tree = MerkleTree::new();
        let leaf = Field::from(123u64);
        let index = tree.insert(leaf);
        assert_eq!(index, 0);
        assert_eq!(tree.next_index, 1);
    }

    #[test]
    fn test_proof_single_leaf() {
        let mut tree = MerkleTree::new();
        let leaf = Field::from(123u64);
        let index = tree.insert(leaf);
        let root = tree.root();

        let proof = tree.proof(index, leaf);
        assert_eq!(proof.path.len(), TREE_DEPTH);

        // Verify the proof
        let computed_root = proof.compute_root();
        assert_eq!(computed_root, root, "Proof should verify against root");
    }

    #[test]
    fn test_proof_multiple_leaves() {
        let mut tree = MerkleTree::new();
        let leaf0 = Field::from(100u64);
        let leaf1 = Field::from(200u64);

        let idx0 = tree.insert(leaf0);
        let idx1 = tree.insert(leaf1);
        let root = tree.root();

        // Both proofs should verify
        let proof0 = tree.proof(idx0, leaf0);
        let proof1 = tree.proof(idx1, leaf1);

        assert!(proof0.verify(root), "Proof for leaf0 should verify");
        assert!(proof1.verify(root), "Proof for leaf1 should verify");
    }
}
