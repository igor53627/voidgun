use std::hash::poseidon2::Poseidon2;
use std::hash::keccak256;
use std::ecdsa_secp256k1::verify_signature;

global TREE_DEPTH: u32 = 20;

struct Note {
    rk_hash: Field,      // hash of receiving key
    value: Field,
    token_type: Field,
    r: Field,            // randomness/trapdoor
}

struct TransferPublicInputs {
    root: Field,
    cm_out: Field,
    cm_change: Field,
    nf_note: Field,
    nf_tx: Field,
    gas_tip: Field,
    gas_fee_cap: Field,
    token_type: Field,
}

fn commit_note(note: Note) -> Field {
    Poseidon2::hash([note.rk_hash, note.value, note.token_type, note.r], 4)
}

fn compute_nullifier(cm: Field, nk: Field) -> Field {
    Poseidon2::hash([cm, nk], 2)
}

fn compute_tx_nullifier(nk: Field, chain_id: Field, from: Field, nonce: Field) -> Field {
    Poseidon2::hash([nk, chain_id, from, nonce], 4)
}

/// Main transfer circuit - "Proxy without spending authority"
/// 
/// Public inputs:
///   - root: Merkle root of note commitments
///   - cm_out: commitment of output note (to recipient)
///   - cm_change: commitment of change note (back to sender)
///   - nf_note: nullifier of spent note
///   - nf_tx: transaction nullifier (prevents replay)
///   - gas_tip, gas_fee_cap: gas parameters from signed tx
///   - token_type: token being transferred
///
/// Private witnesses:
///   - The signed EIP-1559 transaction
///   - ECDSA signature components
///   - Notes and Merkle proof
///   - Nullifying key
fn main(
    // Public inputs
    root: pub Field,
    cm_out: pub Field,
    cm_change: pub Field,
    nf_note: pub Field,
    nf_tx: pub Field,
    gas_tip: pub Field,
    gas_fee_cap: pub Field,
    token_type: pub Field,
    
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
    
    // Nullifying key (private)
    nk: Field,
    
    // Recipient public key for address derivation (private)
    recipient_pk_x: [u8; 32],
    recipient_pk_y: [u8; 32],
) {
    // ============================================
    // 1. Verify ECDSA signature
    // ============================================
    let sig_valid = verify_signature(pub_key_x, pub_key_y, signature, tx_hash);
    assert(sig_valid, "Invalid ECDSA signature");
    
    // ============================================
    // 2. Verify tx.to matches recipient address
    // ============================================
    // Derive address from recipient public key: keccak256(pk)[12:32]
    let mut pk_bytes: [u8; 64] = [0; 64];
    for i in 0..32 {
        pk_bytes[i] = recipient_pk_x[i];
        pk_bytes[i + 32] = recipient_pk_y[i];
    }
    let pk_hash = keccak256(pk_bytes, 64);
    for i in 0..20 {
        assert(pk_hash[i + 12] == tx_to[i], "tx.to does not match recipient");
    }
    
    // ============================================
    // 3. Build and verify note commitments
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
    // 4. Value conservation
    // ============================================
    assert(note_in_value == note_out_value + note_change_value, "Value not conserved");
    assert(note_in_token == token_type, "Token type mismatch");
    
    // ============================================
    // 5. Bind tx.value to output note value
    // ============================================
    assert(tx_value == note_out_value, "tx.value does not match output");
    
    // ============================================
    // 6. Verify gas parameters
    // ============================================
    assert(tx_max_priority_fee == gas_tip, "Gas tip mismatch");
    assert(tx_max_fee == gas_fee_cap, "Gas fee cap mismatch");
    
    // ============================================
    // 7. Verify Merkle proof for input note
    // ============================================
    let computed_root = compute_merkle_root(cm_in, merkle_path, merkle_index);
    assert(computed_root == root, "Invalid Merkle proof");
    
    // ============================================
    // 8. Compute and verify note nullifier
    // ============================================
    let nf_note_computed = compute_nullifier(cm_in, nk);
    assert(nf_note_computed == nf_note, "Note nullifier mismatch");
    
    // ============================================
    // 9. Compute and verify transaction nullifier
    // ============================================
    // Derive sender address from signing pubkey
    let mut sender_pk_bytes: [u8; 64] = [0; 64];
    for i in 0..32 {
        sender_pk_bytes[i] = pub_key_x[i];
        sender_pk_bytes[i + 32] = pub_key_y[i];
    }
    let sender_pk_hash = keccak256(sender_pk_bytes, 64);
    let mut sender_addr_field: Field = 0;
    for i in 0..20 {
        sender_addr_field = sender_addr_field * 256 + sender_pk_hash[i + 12] as Field;
    }
    
    let nf_tx_computed = compute_tx_nullifier(nk, tx_chain_id, sender_addr_field, tx_nonce);
    assert(nf_tx_computed == nf_tx, "Transaction nullifier mismatch");
}

/// Compute Merkle root from leaf and path
fn compute_merkle_root(leaf: Field, path: [Field; TREE_DEPTH], index: Field) -> Field {
    let mut current = leaf;
    let mut idx = index;
    
    for i in 0..TREE_DEPTH {
        let path_element = path[i];
        let is_right = idx as u64 & 1;
        
        if is_right == 1 {
            current = Poseidon2::hash([path_element, current], 2);
        } else {
            current = Poseidon2::hash([current, path_element], 2);
        }
        
        idx = idx / 2;
    }
    
    current
}
