use poseidon2::bn254::{hash_2, hash_3, hash_4};
use keccak256::keccak256;

global TREE_DEPTH: u32 = 20;

// Domain separation tags for Poseidon2 hashing
// These prevent collision attacks between different hash usages
global DOMAIN_COMMITMENT: Field = 0;
global DOMAIN_MERKLE_NODE: Field = 1;
global DOMAIN_NULLIFIER: Field = 2;
global DOMAIN_KEY_DERIVATION: Field = 3;

struct Note {
    rk_hash: Field,      // hash of receiving key
    value: Field,
    token_type: Field,
    r: Field,            // randomness/trapdoor
}

/// Compute note commitment with domain separation
/// cm = hash(DOMAIN_COMMITMENT, rk_hash, value, token_type, r)
fn commit_note(note: Note) -> Field {
    // Use hash_4 with domain tag embedded in first element
    let combined_domain = DOMAIN_COMMITMENT * 0x1000000000000000000000000000000000000000000000000 + note.rk_hash;
    hash_4([combined_domain, note.value, note.token_type, note.r])
}

/// Compute Merkle node hash with domain separation
fn hash_merkle_node(left: Field, right: Field) -> Field {
    hash_3([DOMAIN_MERKLE_NODE, left, right])
}

/// Compute note nullifier with domain separation
fn compute_nullifier(cm: Field, nk: Field) -> Field {
    hash_3([DOMAIN_NULLIFIER, cm, nk])
}

/// Compute transaction nullifier with domain separation and pool binding
/// Uses sponge-style construction matching Rust: hash_4 twice with domain
/// nf_tx = hash_4([intermediate, pool_id, from, nonce])
/// where intermediate = hash_4([DOMAIN_NULLIFIER, nk, chain_id, 0])
fn compute_tx_nullifier(nk: Field, chain_id: Field, pool_id: Field, from: Field, nonce: Field) -> Field {
    let intermediate = hash_4([DOMAIN_NULLIFIER, nk, chain_id, 0]);
    hash_4([intermediate, pool_id, from, nonce])
}

/// Derive receiving key hash from nullifying key
fn derive_rk_hash(nk: Field) -> Field {
    let pnk = hash_2([DOMAIN_KEY_DERIVATION, nk]);
    let ek_x = hash_3([DOMAIN_KEY_DERIVATION, nk, 1]);
    let ek_y = hash_3([DOMAIN_KEY_DERIVATION, nk, 2]);
    hash_4([DOMAIN_KEY_DERIVATION, pnk, ek_x, ek_y])
}

/// Compute Merkle root from leaf and path with domain-separated hashing
fn compute_merkle_root(leaf: Field, path: [Field; TREE_DEPTH], index: Field) -> Field {
    let mut current = leaf;
    let _ = index; // Used by to_le_bits above
    let index_bits = index.to_le_bits::<20>();
    
    for i in 0..TREE_DEPTH {
        let sibling = path[i];
        let is_right = index_bits[i] != 0;
        
        if is_right {
            current = hash_merkle_node(sibling, current);
        } else {
            current = hash_merkle_node(current, sibling);
        }
    }
    
    current
}

/// Main transfer circuit - "Proxy without spending authority"
/// Note: Public inputs are marked with pub when this is compiled as a binary
pub fn transfer(
    // Public inputs (marked with pub when compiled as binary)
    root: Field,
    cm_out: Field,
    cm_change: Field,
    nf_note: Field,
    nf_tx: Field,
    gas_tip: Field,
    gas_fee_cap: Field,
    token_type: Field,
    pool_id: Field,
    
    // Signed transaction (private)
    tx_hash: [u8; 32],
    tx_chain_id: Field,
    tx_nonce: Field,
    tx_to: [u8; 20],
    tx_value: Field,
    tx_max_priority_fee: Field,
    tx_max_fee: Field,
    
    // ECDSA signature (private)
    signature: [u8; 64],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    
    // Input note (private)
    note_in_rk_hash: Field,
    note_in_value: Field,
    note_in_token: Field,
    note_in_r: Field,
    
    // Output note (private)
    note_out_rk_hash: Field,
    note_out_value: Field,
    note_out_r: Field,
    
    // Change note (private)
    note_change_rk_hash: Field,
    note_change_value: Field,
    note_change_r: Field,
    
    // Merkle proof (private)
    merkle_path: [Field; TREE_DEPTH],
    merkle_index: Field,
    
    // Nullifying key (private) - proves ownership of input note
    nk: Field,
    
    // Recipient public key for address derivation (private)
    recipient_pk_x: [u8; 32],
    recipient_pk_y: [u8; 32],
) {
    // ============================================
    // 1. Verify ECDSA signature (placeholder)
    // ============================================
    // TODO: Add ECDSA verification when available in stdlib
    let _ = signature[0];
    let _ = tx_hash[0];
    let _ = pub_key_x[0];
    let _ = pub_key_y[0];
    
    // ============================================
    // 2. Verify sender owns the input note
    // ============================================
    let sender_rk_hash = derive_rk_hash(nk);
    assert(sender_rk_hash == note_in_rk_hash, "Sender does not own input note");
    
    // ============================================
    // 3. Verify tx.to matches recipient address
    // ============================================
    let mut pk_bytes: [u8; 64] = [0; 64];
    for i in 0..32 {
        pk_bytes[i] = recipient_pk_x[i];
        pk_bytes[i + 32] = recipient_pk_y[i];
    }
    let pk_hash: [u8; 32] = keccak256(pk_bytes, 64);
    for i in 0..20 {
        assert(pk_hash[i + 12] == tx_to[i], "tx.to does not match recipient");
    }
    
    // ============================================
    // 4. Build and verify note commitments
    // ============================================
    let note_in = Note {
        rk_hash: note_in_rk_hash,
        value: note_in_value,
        token_type: note_in_token,
        r: note_in_r,
    };
    let cm_in = commit_note(note_in);
    
    let note_out = Note {
        rk_hash: note_out_rk_hash,
        value: note_out_value,
        token_type: token_type,
        r: note_out_r,
    };
    let cm_out_computed = commit_note(note_out);
    assert(cm_out_computed == cm_out, "Output commitment mismatch");
    
    let note_change = Note {
        rk_hash: note_change_rk_hash,
        value: note_change_value,
        token_type: token_type,
        r: note_change_r,
    };
    let cm_change_computed = commit_note(note_change);
    assert(cm_change_computed == cm_change, "Change commitment mismatch");
    
    // ============================================
    // 5. Value conservation
    // ============================================
    assert(note_in_value == note_out_value + note_change_value, "Value not conserved");
    assert(note_in_token == token_type, "Token type mismatch");
    
    // ============================================
    // 6. Bind tx.value to output note value
    // ============================================
    assert(tx_value == note_out_value, "tx.value does not match output");
    
    // ============================================
    // 7. Verify gas parameters
    // ============================================
    assert(tx_max_priority_fee == gas_tip, "Gas tip mismatch");
    assert(tx_max_fee == gas_fee_cap, "Gas fee cap mismatch");
    
    // ============================================
    // 8. Verify Merkle proof for input note
    // ============================================
    let computed_root = compute_merkle_root(cm_in, merkle_path, merkle_index);
    assert(computed_root == root, "Invalid Merkle proof");
    
    // ============================================
    // 9. Compute and verify note nullifier
    // ============================================
    let nf_note_computed = compute_nullifier(cm_in, nk);
    assert(nf_note_computed == nf_note, "Note nullifier mismatch");
    
    // ============================================
    // 10. Compute and verify transaction nullifier
    // ============================================
    let mut sender_pk_bytes: [u8; 64] = [0; 64];
    for i in 0..32 {
        sender_pk_bytes[i] = pub_key_x[i];
        sender_pk_bytes[i + 32] = pub_key_y[i];
    }
    let sender_pk_hash: [u8; 32] = keccak256(sender_pk_bytes, 64);
    let mut sender_addr_field: Field = 0;
    for i in 0..20 {
        sender_addr_field = sender_addr_field * 256 + sender_pk_hash[i + 12] as Field;
    }
    
    let nf_tx_computed = compute_tx_nullifier(nk, tx_chain_id, pool_id, sender_addr_field, tx_nonce);
    assert(nf_tx_computed == nf_tx, "Transaction nullifier mismatch");
}
