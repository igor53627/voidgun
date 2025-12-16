use dep::poseidon::poseidon2::Poseidon2;

global TREE_DEPTH: u32 = 20;
global EMPTY_LEAF: Field = 0;

global DOMAIN_MERKLE_NODE: Field = 2;

fn hash_node(left: Field, right: Field) -> Field {
    Poseidon2::hash([DOMAIN_MERKLE_NODE, left, right], 3)
}

pub fn compute_root(leaf: Field, path: [Field; TREE_DEPTH], index: Field) -> Field {
    let mut current = leaf;
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

pub fn verify_proof(leaf: Field, path: [Field; TREE_DEPTH], index: Field, root: Field) -> bool {
    compute_root(leaf, path, index) == root
}

pub fn empty_root() -> Field {
    let mut current = EMPTY_LEAF;
    
    for _i in 0..TREE_DEPTH {
        current = hash_node(current, current);
    }
    
    current
}
