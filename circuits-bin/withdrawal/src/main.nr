use dep::poseidon::poseidon2::Poseidon2;
use keccak256::keccak256;
use std::ecdsa_secp256k1::verify_signature;

global TREE_DEPTH: u32 = 20;

global DOMAIN_COMMITMENT: Field = 1;
global DOMAIN_MERKLE_NODE: Field = 2;
global DOMAIN_NULLIFIER: Field = 3;
global DOMAIN_KEY_DERIVATION: Field = 4;

fn assert_u64(value: Field) {
    let bits = value.to_le_bits::<64>();
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

global SECP256K1_N_OVER_2: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

struct Note {
    rk_hash: Field,
    value: Field,
    token_type: Field,
    r: Field,
}

fn commit_note(note: Note) -> Field {
    Poseidon2::hash([DOMAIN_COMMITMENT, note.rk_hash, note.value, note.token_type, note.r], 5)
}

fn hash_merkle_node(left: Field, right: Field) -> Field {
    Poseidon2::hash([DOMAIN_MERKLE_NODE, left, right], 3)
}

fn compute_nullifier(cm: Field, nk: Field) -> Field {
    Poseidon2::hash([DOMAIN_NULLIFIER, cm, nk], 3)
}

fn compute_tx_nullifier(nk: Field, chain_id: Field, pool_id: Field, from: Field, nonce: Field) -> Field {
    Poseidon2::hash([DOMAIN_NULLIFIER, nk, chain_id, pool_id, from, nonce], 6)
}

fn derive_rk_hash(nk: Field) -> Field {
    let pnk = Poseidon2::hash([DOMAIN_KEY_DERIVATION, nk, 0], 3);
    let ek_x = Poseidon2::hash([DOMAIN_KEY_DERIVATION, nk, 1], 3);
    let ek_y = Poseidon2::hash([DOMAIN_KEY_DERIVATION, nk, 2], 3);
    Poseidon2::hash([DOMAIN_KEY_DERIVATION, pnk, ek_x, ek_y], 4)
}

fn is_low_s(signature: [u8; 64]) -> bool {
    let mut result: i8 = 0;
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

fn compute_merkle_root(leaf: Field, path: [Field; TREE_DEPTH], index: Field) -> Field {
    let mut current = leaf;
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

/// Withdrawal circuit entry point
/// Public inputs match VoidgunPool.sol withdraw:
/// [root, nfNote, nfTx, value, tokenType, recipient, poolId]
fn main(
    // Public inputs (7 elements)
    root: pub Field,
    nf_note: pub Field,
    nf_tx: pub Field,
    value: pub Field,
    token_type: pub Field,
    recipient: pub Field,  // recipient address as Field (uint160)
    pool_id: pub Field,
    
    // Transaction data (private)
    tx_hash: [u8; 32],
    tx_chain_id: Field,
    tx_nonce: Field,
    
    // ECDSA signature (private)
    signature: [u8; 64],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    
    // Input note (private)
    note_rk_hash: Field,
    note_value: Field,
    note_token: Field,
    note_r: Field,
    
    // Merkle proof (private)
    merkle_path: [Field; TREE_DEPTH],
    merkle_index: Field,
    
    // Nullifying key (private)
    nk: Field,
) {
    // 1. Verify ECDSA signature
    assert(is_low_s(signature), "Signature S must be in lower half");
    let is_valid_sig = verify_signature(pub_key_x, pub_key_y, signature, tx_hash);
    assert(is_valid_sig, "Invalid ECDSA signature");
    
    // 2. Verify sender owns input note
    let sender_rk_hash = derive_rk_hash(nk);
    assert(sender_rk_hash == note_rk_hash, "Sender does not own input note");
    
    // 3. Verify note commitment and Merkle proof
    let note = Note { rk_hash: note_rk_hash, value: note_value, token_type: note_token, r: note_r };
    let cm = commit_note(note);
    let computed_root = compute_merkle_root(cm, merkle_path, merkle_index);
    assert(computed_root == root, "Invalid Merkle proof");
    
    // 4. Verify value matches (with range check)
    assert_u64(note_value);
    assert_u64(value);
    assert(note_value == value, "Value mismatch");
    
    // 5. Verify token type matches
    assert(note_token == token_type, "Token type mismatch");
    
    // 6. Verify recipient matches sender address (derived from signing key)
    let mut pk_bytes: [u8; 64] = [0; 64];
    for i in 0..32 {
        pk_bytes[i] = pub_key_x[i];
        pk_bytes[i + 32] = pub_key_y[i];
    }
    let pk_hash: [u8; 32] = keccak256(pk_bytes, 64);
    let mut sender_addr: Field = 0;
    for i in 0..20 {
        sender_addr = sender_addr * 256 + pk_hash[i + 12] as Field;
    }
    assert(sender_addr == recipient, "Recipient mismatch - must withdraw to own address");
    
    // 7. Verify note nullifier
    assert(compute_nullifier(cm, nk) == nf_note, "Note nullifier mismatch");
    
    // 8. Verify transaction nullifier (for replay protection)
    assert(compute_tx_nullifier(nk, tx_chain_id, pool_id, sender_addr, tx_nonce) == nf_tx, "Tx nullifier mismatch");
}
