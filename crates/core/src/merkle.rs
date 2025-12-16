use ark_bn254::Fr as Field;
use ark_ff::Zero;

use crate::TREE_DEPTH;

/// Incremental Merkle tree for note commitments
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Current number of leaves
    pub next_index: u64,
    /// Filled subtrees at each level
    filled_subtrees: Vec<Field>,
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
        
        for i in 0..TREE_DEPTH {
            let (left, right) = if current_index % 2 == 0 {
                self.filled_subtrees[i] = current_level_hash;
                (current_level_hash, self.zeros[i])
            } else {
                (self.filled_subtrees[i], current_level_hash)
            };
            
            current_level_hash = poseidon2_hash(&[left, right]);
            current_index /= 2;
        }
        
        self.root = current_level_hash;
        self.next_index += 1;
        
        index
    }
    
    /// Generate a Merkle proof for a leaf at given index
    pub fn proof(&self, index: u64, leaf: Field) -> MerkleProof {
        // TODO: This requires storing all leaves or reconstructing from events
        // For now, return a placeholder
        MerkleProof {
            leaf,
            index,
            path: vec![Field::zero(); TREE_DEPTH],
            root: self.root,
        }
    }
    
    /// Compute zero values for empty tree
    fn compute_zeros() -> Vec<Field> {
        let mut zeros = vec![Field::zero()];
        
        for i in 0..TREE_DEPTH {
            let next = poseidon2_hash(&[zeros[i], zeros[i]]);
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
            
            current = poseidon2_hash(&[left, right]);
            index /= 2;
        }
        
        current
    }
}

// TODO: Implement actual Poseidon2 hash matching Noir circuit
fn poseidon2_hash(inputs: &[Field]) -> Field {
    let mut acc = Field::from(0u64);
    for (i, input) in inputs.iter().enumerate() {
        acc += *input * Field::from(i as u64 + 1);
    }
    acc
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
}
