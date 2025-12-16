use dep::poseidon::poseidon2::Poseidon2;
use keccak256::keccak256;
use std::ecdsa_secp256k1::verify_signature;

global TREE_DEPTH: u32 = 20;

// Domain separation tags for Poseidon2 hashing
// These prevent collision attacks between different hash usages
// Using non-zero values to ensure domain separation is active
global DOMAIN_COMMITMENT: Field = 1;
global DOMAIN_MERKLE_NODE: Field = 2;
global DOMAIN_NULLIFIER: Field = 3;
global DOMAIN_KEY_DERIVATION: Field = 4;

/// Check if a field element fits in 64 bits (value < 2^64)
fn assert_u64(value: Field) {
    let bits = value.to_le_bits::<64>();
    // Reconstruct from bits to verify no overflow
    let mut reconstructed: Field = 0;
    let mut power: Field = 1;
    for i in 0..64 {
        if bits[i] == 1 {
            reconstructed += power;
        }
        power *= 2;
    }
    assert(reconstructed == value);
}

// secp256k1 n/2 for low-S malleability check (big-endian bytes)
// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
global SECP256K1_N_OVER_2: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

struct Note {
    rk_hash: Field,      // hash of receiving key
    value: Field,
    token_type: Field,
    r: Field,            // randomness/trapdoor
}

/// Compute note commitment with domain separation
/// Uses sponge hash matching Poseidon2Yul: H(domain, rk, value, token, r)
fn commit_note(note: Note) -> Field {
    Poseidon2::hash([DOMAIN_COMMITMENT, note.rk_hash, note.value, note.token_type, note.r], 5)
}

/// Compute Merkle node hash with domain separation
/// Uses sponge hash: H(domain, left, right)
fn hash_merkle_node(left: Field, right: Field) -> Field {
    Poseidon2::hash([DOMAIN_MERKLE_NODE, left, right], 3)
}

/// Compute note nullifier with domain separation
/// Uses sponge hash: H(domain, cm, nk)
fn compute_nullifier(cm: Field, nk: Field) -> Field {
    Poseidon2::hash([DOMAIN_NULLIFIER, cm, nk], 3)
}

/// Compute transaction nullifier with domain separation and pool binding
/// Uses sponge hash: H(domain, nk, chain_id, pool_id, from, nonce)
fn compute_tx_nullifier(nk: Field, chain_id: Field, pool_id: Field, from: Field, nonce: Field) -> Field {
    Poseidon2::hash([DOMAIN_NULLIFIER, nk, chain_id, pool_id, from, nonce], 6)
}

/// Derive receiving key hash from nullifying key
/// Uses sponge hash for all sub-hashes
fn derive_rk_hash(nk: Field) -> Field {
    let pnk = Poseidon2::hash([DOMAIN_KEY_DERIVATION, nk, 0], 3);
    let ek_x = Poseidon2::hash([DOMAIN_KEY_DERIVATION, nk, 1], 3);
    let ek_y = Poseidon2::hash([DOMAIN_KEY_DERIVATION, nk, 2], 3);
    Poseidon2::hash([DOMAIN_KEY_DERIVATION, pnk, ek_x, ek_y], 4)
}

/// Check that signature S component is in lower half (s <= n/2)
/// This prevents signature malleability where (r, s) can be transformed to (r, n-s)
/// Signature format: [r: 32 bytes, s: 32 bytes] big-endian
fn is_low_s(signature: [u8; 64]) -> bool {
    let mut result: i8 = 0; // 0 = equal so far, 1 = less, -1 = greater
    for i in 0..32 {
        let s_byte = signature[32 + i];
        let n2_byte = SECP256K1_N_OVER_2[i];
        
        if result == 0 {
            if s_byte < n2_byte {
                result = 1;
            } else if s_byte > n2_byte {
                result = -1;
            }
        }
    }
    result >= 0
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
    // 1. Verify ECDSA signature with low-S check
    // ============================================
    // std::ecdsa_secp256k1::verify_signature enforces s <= n/2 (BIP-62 style)
    // We add an explicit low-S check for defense-in-depth
    assert(is_low_s(signature), "Signature S must be in lower half (malleability protection)");
    let is_valid_sig = verify_signature(pub_key_x, pub_key_y, signature, tx_hash);
    assert(is_valid_sig, "Invalid ECDSA secp256k1 signature");
    
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
    // 5. Value conservation with range checks
    // ============================================
    // Range checks prevent field wraparound attacks
    assert_u64(note_in_value);
    assert_u64(note_out_value);
    assert_u64(note_change_value);
    assert_u64(tx_value);
    
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
