use std::hash::poseidon2::Poseidon2;

global TREE_DEPTH: u32 = 20;
global EMPTY_LEAF: Field = 0;

/// Compute the root of a Merkle tree given a leaf, its path, and index
pub fn compute_root(leaf: Field, path: [Field; TREE_DEPTH], index: Field) -> Field {
    let mut current = leaf;
    let mut idx = index;
    
    for i in 0..TREE_DEPTH {
        let sibling = path[i];
        let is_right = idx as u64 & 1;
        
        current = if is_right == 1 {
            Poseidon2::hash([sibling, current], 2)
        } else {
            Poseidon2::hash([current, sibling], 2)
        };
        
        idx = idx / 2;
    }
    
    current
}

/// Verify a Merkle proof
pub fn verify_proof(leaf: Field, path: [Field; TREE_DEPTH], index: Field, root: Field) -> bool {
    compute_root(leaf, path, index) == root
}

/// Compute empty tree root (all leaves are EMPTY_LEAF)
pub fn empty_root() -> Field {
    let mut current = EMPTY_LEAF;
    
    for _i in 0..TREE_DEPTH {
        current = Poseidon2::hash([current, current], 2);
    }
    
    current
}
