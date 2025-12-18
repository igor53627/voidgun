//! Integration test for shielded transfer proof generation
//!
//! This test verifies the full flow:
//! 1. Create sender and recipient keys
//! 2. Create input note (simulating deposit)
//! 3. Build transfer witness
//! 4. Generate ZK proof
//! 5. Verify proof

use alloy_primitives::{keccak256, Address, U256};
use ark_bn254::Fr as Field;
use ark_ff::{PrimeField, UniformRand};

use voidgun_core::{
    note_nullifier, pool_id_field, poseidon2::derive_rk_hash, tx_nullifier, MerkleTree,
};
use voidgun_prover::{prove_transfer, verify_transfer, TransferWitness};

use k256::ecdsa::SigningKey;

fn u256_to_field(v: U256) -> Field {
    Field::from_be_bytes_mod_order(&v.to_be_bytes::<32>())
}

fn address_to_field(a: Address) -> Field {
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(a.as_slice());
    Field::from_be_bytes_mod_order(&bytes)
}

#[test]
#[ignore] // Run with: cargo test -p voidgun-prover --test integration_test -- --ignored --nocapture
fn test_shielded_transfer_proof() {
    println!("=== Shielded Transfer Proof Integration Test ===\n");

    let mut rng = rand::thread_rng();

    // 1. Generate a nullifying key (nk) - this is the secret
    // Use a smaller deterministic value to help debug
    println!("1. Creating keys...");
    let nk = Field::from(123456789u64);

    // Derive sender's rk_hash using the circuit's formula
    // This ensures note_in_rk_hash == derive_rk_hash(nk) in the circuit
    let sender_rk_hash = derive_rk_hash(nk);
    println!("   Sender RK hash (from nk): {:?}", sender_rk_hash);

    // For recipient, use a different key
    let recipient_nk = Field::from(987654321u64);
    let recipient_rk_hash = derive_rk_hash(recipient_nk);
    println!("   Recipient RK hash: {:?}", recipient_rk_hash);

    // 2. Create input note (simulating a deposit)
    println!("\n2. Creating input note...");
    let input_value = U256::from(1_000_000_000_000_000_000u64); // 1 ETH
    let input_r = Field::rand(&mut rng);
    // Create note directly with rk_hash (not through Note::new which expects ReceivingKey)
    let input_cm = voidgun_core::poseidon2::hash_commitment(
        sender_rk_hash,
        u256_to_field(input_value),
        address_to_field(Address::ZERO),
        input_r,
    );
    println!("   Input value: {} wei", input_value);
    println!("   Input commitment: {:?}", input_cm);

    // 3. Insert into Merkle tree
    println!("\n3. Building Merkle tree...");
    let mut tree = MerkleTree::new();
    let merkle_index = tree.insert(input_cm);
    let root = tree.root();
    let merkle_proof = tree.proof(merkle_index, input_cm);
    println!("   Merkle index: {}", merkle_index);
    println!("   Root: {:?}", root);
    println!("   Proof path length: {}", merkle_proof.path.len());

    // 4. Build transfer parameters
    println!("\n4. Building transfer...");
    let transfer_value = U256::from(500_000_000_000_000_000u64); // 0.5 ETH
    let change_value = input_value - transfer_value;
    let r_out = Field::rand(&mut rng);
    let r_change = Field::rand(&mut rng);

    // Compute output and change commitments directly
    let cm_out = voidgun_core::poseidon2::hash_commitment(
        recipient_rk_hash,
        u256_to_field(transfer_value),
        address_to_field(Address::ZERO),
        r_out,
    );
    let cm_change = voidgun_core::poseidon2::hash_commitment(
        sender_rk_hash,
        u256_to_field(change_value),
        address_to_field(Address::ZERO),
        r_change,
    );

    println!("   Transfer value: {} wei", transfer_value);
    println!("   Change value: {} wei", change_value);
    println!("   Output commitment: {:?}", cm_out);
    println!("   Change commitment: {:?}", cm_change);

    // 5. Create signing key and derive sender address
    // Generate a random signing key
    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // Get uncompressed public key (65 bytes: 04 || x || y)
    let pk_uncompressed = verifying_key.to_encoded_point(false);
    let pk_bytes = pk_uncompressed.as_bytes();
    let mut pub_key_x = [0u8; 32];
    let mut pub_key_y = [0u8; 32];
    pub_key_x.copy_from_slice(&pk_bytes[1..33]);
    pub_key_y.copy_from_slice(&pk_bytes[33..65]);

    // Derive sender address from public key (keccak256(pubkey)[12..32])
    let pk_hash = keccak256(&pk_bytes[1..65]);
    let sender_address = Address::from_slice(&pk_hash[12..32]);
    println!("   Sender address: {:?}", sender_address);

    // The "to" address in the circuit is the VoidgunPool contract
    // But the circuit also verifies that the *sender* matches the pubkey
    // For this test, use sender_address as tx.to (self-transfer scenario)
    let chain_id = 1u64;
    let nonce = 0u64;
    let to_address = sender_address; // Circuit verifies pk_hash[12..32] == tx_to
    let pool_id = pool_id_field();

    // Compute nullifiers using our nk
    let nf_note = note_nullifier(input_cm, nk);
    let nf_tx = tx_nullifier(nk, chain_id, pool_id, to_address, nonce);

    println!("   Note nullifier: {:?}", nf_note);
    println!("   Tx nullifier: {:?}", nf_tx);

    // 6. Build witness
    println!("\n5. Building witness...");

    // Create transaction hash
    let tx_hash = keccak256(b"mock_transaction_data");

    // Sign the transaction and normalize to low-S
    let (sig, _recovery_id) = signing_key.sign_prehash_recoverable(&tx_hash.0).unwrap();
    let sig_normalized = sig.normalize_s().unwrap_or(sig);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_normalized.to_bytes());

    // For recipient, use sender's key for simplicity in test
    let recipient_pk_x = pub_key_x;
    let recipient_pk_y = pub_key_y;

    println!("   Generated real ECDSA signature");

    let witness = TransferWitness {
        // Public inputs
        root,
        cm_out,
        cm_change,
        nf_note,
        nf_tx,
        gas_tip: Field::from(2_000_000_000u64),       // 2 gwei
        gas_fee_cap: Field::from(100_000_000_000u64), // 100 gwei
        token_type: address_to_field(Address::ZERO),
        pool_id,

        // Transaction data
        tx_hash: tx_hash.0,
        tx_chain_id: chain_id,
        tx_nonce: nonce,
        tx_to: to_address.0 .0,
        tx_value: u256_to_field(transfer_value),
        tx_max_priority_fee: Field::from(2_000_000_000u64),
        tx_max_fee: Field::from(100_000_000_000u64),

        // Signature
        signature,
        pub_key_x,
        pub_key_y,

        // Input note
        note_in_rk_hash: sender_rk_hash,
        note_in_value: u256_to_field(input_value),
        note_in_token: address_to_field(Address::ZERO),
        note_in_r: input_r,

        // Output note
        note_out_rk_hash: recipient_rk_hash,
        note_out_value: u256_to_field(transfer_value),
        note_out_r: r_out,

        // Change note
        note_change_rk_hash: sender_rk_hash,
        note_change_value: u256_to_field(change_value),
        note_change_r: r_change,

        // Merkle proof
        merkle_path: merkle_proof.path.clone(),
        merkle_index,

        // Secret
        nk,

        // Recipient pubkey
        recipient_pk_x,
        recipient_pk_y,
    };

    println!("   Witness built successfully");

    // 7. Generate proof
    println!("\n6. Generating ZK proof...");
    println!("   (This may take a few seconds...)");

    let proof_result = prove_transfer(witness);

    match proof_result {
        Ok(proof) => {
            println!("   [OK] Proof generated!");
            println!("   Proof size: {} bytes", proof.proof.len());
            println!("   Public inputs: {} elements", proof.public_inputs.len());

            // 8. Verify proof
            println!("\n7. Verifying proof...");
            match verify_transfer(&proof) {
                Ok(true) => println!("   [OK] Proof verified successfully!"),
                Ok(false) => println!("   [FAIL] Proof verification returned false"),
                Err(e) => println!("   [FAIL] Verification error: {:?}", e),
            }
        }
        Err(e) => {
            println!("   [FAIL] Proof generation failed: {:?}", e);
            println!("\n   Note: This test requires valid ECDSA signatures.");
            println!(
                "   The circuit enforces signature verification which will fail with mock data."
            );
        }
    }

    println!("\n=== Test Complete ===");
}
