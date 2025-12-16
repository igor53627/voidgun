use poseidon2::bn254::hash_3;

global TREE_DEPTH: u32 = 20;
global EMPTY_LEAF: Field = 0;

// Domain separation tag for Merkle nodes
global DOMAIN_MERKLE_NODE: Field = 1;

/// Hash two children to get parent node (with domain separation)
fn hash_node(left: Field, right: Field) -> Field {
    hash_3([DOMAIN_MERKLE_NODE, left, right])
}

/// Compute the root of a Merkle tree given a leaf, its path, and index
pub fn compute_root(leaf: Field, path: [Field; TREE_DEPTH], index: Field) -> Field {
    let mut current = leaf;
    // Note: Bit width must match TREE_DEPTH (20)
    let index_bits = index.to_le_bits::<20>();
    
    for i in 0..TREE_DEPTH {
        let sibling = path[i];
        let is_right = index_bits[i] != 0;
        
        current = if is_right {
            hash_node(sibling, current)
        } else {
            hash_node(current, sibling)
        };
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
        current = hash_node(current, current);
    }
    
    current
}
