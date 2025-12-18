//! Proof generation tests for RailgunProver
//!
//! These tests validate that the downloaded circuit artifacts (WASM + ZKEY)
//! work correctly with ark-circom to generate valid Groth16 proofs.
//!
//! Run with: cargo test -p railgun-lane --test proof_generation -- --nocapture

mod common;

use ark_bn254::Fr as Field;
use ark_ff::UniformRand;
use railgun_lane::{
    ArtifactStore, CircuitVariant, NoteMerkleTree, RailgunNote, RailgunProver,
    TransactWitness,
};
use std::sync::Arc;

use common::{setup_prover, setup_wallet, compute_message_hash, ARTIFACTS_PATH};

// Re-export RailgunWallet for tests that use it directly
#[allow(unused_imports)]
use railgun_lane::RailgunWallet;

#[tokio::test]
async fn test_artifact_loading() {
    let store = ArtifactStore::new(ARTIFACTS_PATH, false);

    for (nullifiers, commitments) in [(1, 1), (1, 2), (2, 1), (2, 2)] {
        let variant = CircuitVariant::new(nullifiers, commitments).unwrap();
        let artifacts = store.get_artifacts(&variant).await;

        match artifacts {
            Ok(a) => {
                println!(
                    "Loaded {}: ZKEY={} bytes, WASM={}",
                    variant.as_string(),
                    a.zkey.len(),
                    a.wasm.as_ref().map(|w| w.len()).unwrap_or(0)
                );
                assert!(!a.zkey.is_empty(), "ZKEY should not be empty");
                assert!(a.wasm.is_some(), "WASM should be present");
            }
            Err(e) => {
                panic!("Failed to load {}: {}", variant.as_string(), e);
            }
        }
    }
}

#[tokio::test]
async fn test_zkey_parsing() {
    use ark_circom::read_zkey;
    use std::io::Cursor;

    let store = ArtifactStore::new(ARTIFACTS_PATH, false);
    let variant = CircuitVariant::new(1, 1).unwrap();
    let artifacts = store.get_artifacts(&variant).await.unwrap();

    let mut cursor = Cursor::new(&artifacts.zkey);
    let result = read_zkey(&mut cursor);

    match result {
        Ok((pk, matrices)) => {
            println!("ZKEY parsed successfully:");
            println!("  Constraints: {}", matrices.num_constraints);
            println!("  Instance variables: {}", matrices.num_instance_variables);
            println!("  Witness variables: {}", matrices.num_witness_variables);
            println!("  VK alpha_g1: {:?}", pk.vk.alpha_g1);
        }
        Err(e) => {
            panic!("ZKEY parsing failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_wasm_witness_calculator() {
    use ark_circom::WitnessCalculator;
    use wasmer::{Module, Store};

    let store = ArtifactStore::new(ARTIFACTS_PATH, false);
    let variant = CircuitVariant::new(1, 1).unwrap();
    let artifacts = store.get_artifacts(&variant).await.unwrap();
    let wasm = artifacts.wasm.as_ref().unwrap();

    let mut wasmer_store = Store::default();
    let module = Module::new(&wasmer_store, wasm);

    match module {
        Ok(m) => {
            println!("WASM module compiled successfully");
            let wtns = WitnessCalculator::from_module(&mut wasmer_store, m);
            match wtns {
                Ok(_) => println!("WitnessCalculator created successfully"),
                Err(e) => panic!("WitnessCalculator creation failed: {}", e),
            }
        }
        Err(e) => {
            panic!("WASM compilation failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_prove_transact_1x1() {
    let prover = setup_prover();
    let wallet = setup_wallet();
    let mut rng = rand::thread_rng();

    // Create a simple merkle tree with one note
    let mut tree = NoteMerkleTree::new(16);

    // Create input note
    let input_note = RailgunNote::new(
        wallet.master_public_key,
        1_000_000_000_000_000_000u128, // 1 ETH
        Field::from(0u64),             // ETH token
        Field::rand(&mut rng),
    );

    // Insert into tree
    let leaf_idx = tree.insert(input_note.commitment());
    let merkle_proof = tree.proof(leaf_idx);
    let merkle_root = tree.root();

    // Create output note (sending to self for simplicity)
    let output_note = RailgunNote::new(
        wallet.master_public_key,
        1_000_000_000_000_000_000u128,
        Field::from(0u64),
        Field::rand(&mut rng),
    );

    // Compute bound params hash
    let bound_params_hash = RailgunProver::compute_bound_params_hash_simple(
        0, // tree_number
        0, // min_gas_price
        0, // no unshield
        1, // chain_id (mainnet)
    );

    // Compute nullifiers using circuit formula: Poseidon(nullifyingKey, leafIndex)
    let nullifiers = vec![RailgunNote::joinsplit_nullifier(
        wallet.nullifying_key,
        leaf_idx,
    )];
    let commitments = vec![output_note.commitment()];

    // Get public key and sign with correct message hash
    let (pk_x, pk_y) = wallet.spending.public_xy();
    let message = compute_message_hash(merkle_root, bound_params_hash, &nullifiers, &commitments);
    let signature = wallet.spending.sign(message);

    // Build witness
    let witness = TransactWitness {
        merkle_root,
        bound_params_hash,
        token: Field::from(0u64),
        public_key: [pk_x, pk_y],
        signature: signature.to_circuit_inputs(),
        input_notes: vec![input_note],
        input_merkle_proofs: vec![merkle_proof],
        input_merkle_indices: vec![leaf_idx],
        output_notes: vec![output_note],
        nullifying_key: wallet.nullifying_key,
    };

    println!("Generating proof for 1x1 transact circuit...");
    let start = std::time::Instant::now();

    let result = prover.prove_transact(witness).await;

    match result {
        Ok(proof) => {
            let elapsed = start.elapsed();
            println!("[OK] Proof generated successfully in {:?}", elapsed);
            println!("  Proof size: {} bytes", proof.proof_bytes.len());
            println!("  Public inputs: {}", proof.public_inputs.len());

            // Verify proof structure (ark-groth16 compressed is 128 bytes, not 192)
            assert!(
                proof.proof_bytes.len() >= 128,
                "Groth16 proof should be at least 128 bytes"
            );
            assert!(!proof.public_inputs.is_empty(), "Should have public inputs");

            // Test Solidity format conversion
            let sol_proof = proof.to_solidity_proof();
            assert!(sol_proof.is_ok(), "Should convert to Solidity format");
        }
        Err(e) => {
            panic!("[FAIL] Proof generation failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_prove_transact_1x2() {
    let prover = setup_prover();
    let wallet = setup_wallet();
    let mut rng = rand::thread_rng();

    let mut tree = NoteMerkleTree::new(16);

    // Input: 1 note of 2 ETH
    let input_note = RailgunNote::new(
        wallet.master_public_key,
        2_000_000_000_000_000_000u128,
        Field::from(0u64),
        Field::rand(&mut rng),
    );

    let leaf_idx = tree.insert(input_note.commitment());
    let merkle_proof = tree.proof(leaf_idx);
    let merkle_root = tree.root();

    // Output: 2 notes of 1 ETH each (split)
    let output_note1 = RailgunNote::new(
        wallet.master_public_key,
        1_000_000_000_000_000_000u128,
        Field::from(0u64),
        Field::rand(&mut rng),
    );
    let output_note2 = RailgunNote::new(
        wallet.master_public_key,
        1_000_000_000_000_000_000u128,
        Field::from(0u64),
        Field::rand(&mut rng),
    );

    let bound_params_hash = RailgunProver::compute_bound_params_hash_simple(0, 0, 0, 1);

    // Compute nullifiers using circuit formula: Poseidon(nullifyingKey, leafIndex)
    let nullifiers = vec![RailgunNote::joinsplit_nullifier(
        wallet.nullifying_key,
        leaf_idx,
    )];
    let commitments = vec![output_note1.commitment(), output_note2.commitment()];

    let (pk_x, pk_y) = wallet.spending.public_xy();
    let message = compute_message_hash(merkle_root, bound_params_hash, &nullifiers, &commitments);
    let signature = wallet.spending.sign(message);

    let witness = TransactWitness {
        merkle_root,
        bound_params_hash,
        token: Field::from(0u64),
        public_key: [pk_x, pk_y],
        signature: signature.to_circuit_inputs(),
        input_notes: vec![input_note],
        input_merkle_proofs: vec![merkle_proof],
        input_merkle_indices: vec![leaf_idx],
        output_notes: vec![output_note1, output_note2],
        nullifying_key: wallet.nullifying_key,
    };

    println!("Generating proof for 1x2 transact circuit (split)...");
    let start = std::time::Instant::now();

    let result = prover.prove_transact(witness).await;

    match result {
        Ok(proof) => {
            println!("[OK] 1x2 proof generated in {:?}", start.elapsed());
            assert!(proof.proof_bytes.len() >= 128);
        }
        Err(e) => {
            panic!("[FAIL] 1x2 proof generation failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_prove_transact_2x1() {
    let prover = setup_prover();
    let wallet = setup_wallet();
    let mut rng = rand::thread_rng();

    let mut tree = NoteMerkleTree::new(16);

    // Input: 2 notes of 0.5 ETH each (merge)
    let input_note1 = RailgunNote::new(
        wallet.master_public_key,
        500_000_000_000_000_000u128,
        Field::from(0u64),
        Field::rand(&mut rng),
    );
    let input_note2 = RailgunNote::new(
        wallet.master_public_key,
        500_000_000_000_000_000u128,
        Field::from(0u64),
        Field::rand(&mut rng),
    );

    let leaf_idx1 = tree.insert(input_note1.commitment());
    let leaf_idx2 = tree.insert(input_note2.commitment());
    let merkle_proof1 = tree.proof(leaf_idx1);
    let merkle_proof2 = tree.proof(leaf_idx2);
    let merkle_root = tree.root();

    // Output: 1 note of 1 ETH (merged)
    let output_note = RailgunNote::new(
        wallet.master_public_key,
        1_000_000_000_000_000_000u128,
        Field::from(0u64),
        Field::rand(&mut rng),
    );

    let bound_params_hash = RailgunProver::compute_bound_params_hash_simple(0, 0, 0, 1);

    // Compute nullifiers using circuit formula: Poseidon(nullifyingKey, leafIndex)
    let nullifiers = vec![
        RailgunNote::joinsplit_nullifier(wallet.nullifying_key, leaf_idx1),
        RailgunNote::joinsplit_nullifier(wallet.nullifying_key, leaf_idx2),
    ];
    let commitments = vec![output_note.commitment()];

    let (pk_x, pk_y) = wallet.spending.public_xy();
    let message = compute_message_hash(merkle_root, bound_params_hash, &nullifiers, &commitments);
    let signature = wallet.spending.sign(message);

    let witness = TransactWitness {
        merkle_root,
        bound_params_hash,
        token: Field::from(0u64),
        public_key: [pk_x, pk_y],
        signature: signature.to_circuit_inputs(),
        input_notes: vec![input_note1, input_note2],
        input_merkle_proofs: vec![merkle_proof1, merkle_proof2],
        input_merkle_indices: vec![leaf_idx1, leaf_idx2],
        output_notes: vec![output_note],
        nullifying_key: wallet.nullifying_key,
    };

    println!("Generating proof for 2x1 transact circuit (merge)...");
    let start = std::time::Instant::now();

    let result = prover.prove_transact(witness).await;

    match result {
        Ok(proof) => {
            println!("[OK] 2x1 proof generated in {:?}", start.elapsed());
            assert!(proof.proof_bytes.len() >= 128);
        }
        Err(e) => {
            panic!("[FAIL] 2x1 proof generation failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_prove_transact_2x2() {
    let prover = setup_prover();
    let wallet = setup_wallet();
    let mut rng = rand::thread_rng();

    let mut tree = NoteMerkleTree::new(16);

    // Input: 2 notes
    let input_note1 = RailgunNote::new(
        wallet.master_public_key,
        1_000_000_000_000_000_000u128,
        Field::from(0u64),
        Field::rand(&mut rng),
    );
    let input_note2 = RailgunNote::new(
        wallet.master_public_key,
        500_000_000_000_000_000u128,
        Field::from(0u64),
        Field::rand(&mut rng),
    );

    let leaf_idx1 = tree.insert(input_note1.commitment());
    let leaf_idx2 = tree.insert(input_note2.commitment());
    let merkle_proof1 = tree.proof(leaf_idx1);
    let merkle_proof2 = tree.proof(leaf_idx2);
    let merkle_root = tree.root();

    // Output: 2 notes (transfer + change)
    let output_note1 = RailgunNote::new(
        wallet.master_public_key,
        1_200_000_000_000_000_000u128, // Transfer
        Field::from(0u64),
        Field::rand(&mut rng),
    );
    let output_note2 = RailgunNote::new(
        wallet.master_public_key,
        300_000_000_000_000_000u128, // Change
        Field::from(0u64),
        Field::rand(&mut rng),
    );

    let bound_params_hash = RailgunProver::compute_bound_params_hash_simple(0, 0, 0, 1);

    // Compute nullifiers using circuit formula: Poseidon(nullifyingKey, leafIndex)
    let nullifiers = vec![
        RailgunNote::joinsplit_nullifier(wallet.nullifying_key, leaf_idx1),
        RailgunNote::joinsplit_nullifier(wallet.nullifying_key, leaf_idx2),
    ];
    let commitments = vec![output_note1.commitment(), output_note2.commitment()];

    let (pk_x, pk_y) = wallet.spending.public_xy();
    let message = compute_message_hash(merkle_root, bound_params_hash, &nullifiers, &commitments);
    let signature = wallet.spending.sign(message);

    let witness = TransactWitness {
        merkle_root,
        bound_params_hash,
        token: Field::from(0u64),
        public_key: [pk_x, pk_y],
        signature: signature.to_circuit_inputs(),
        input_notes: vec![input_note1, input_note2],
        input_merkle_proofs: vec![merkle_proof1, merkle_proof2],
        input_merkle_indices: vec![leaf_idx1, leaf_idx2],
        output_notes: vec![output_note1, output_note2],
        nullifying_key: wallet.nullifying_key,
    };

    println!("Generating proof for 2x2 transact circuit...");
    let start = std::time::Instant::now();

    let result = prover.prove_transact(witness).await;

    match result {
        Ok(proof) => {
            println!("[OK] 2x2 proof generated in {:?}", start.elapsed());
            assert!(proof.proof_bytes.len() >= 128);
        }
        Err(e) => {
            panic!("[FAIL] 2x2 proof generation failed: {}", e);
        }
    }
}

/// Test proof verification with correct message hash
///
/// NOTE: Local verification with ark-circom has a known issue (see arkworks-rs/circom-compat#35)
/// where verification fails when using externally-generated ZKEYs (like Railgun's).
/// The proof IS valid - it will verify on-chain with the Railgun smart contract verifier.
/// This test documents the limitation and will be enabled when ark-circom fixes issue #35.
#[tokio::test]
#[ignore = "ark-circom issue #35: verification fails with externally-generated ZKEYs"]
async fn test_proof_verification() {
    let prover = setup_prover();
    let wallet = setup_wallet();
    let mut rng = rand::thread_rng();

    let mut tree = NoteMerkleTree::new(16);

    let input_note = RailgunNote::new(
        wallet.master_public_key,
        1_000_000_000_000_000_000u128,
        Field::from(0u64),
        Field::rand(&mut rng),
    );

    let leaf_idx = tree.insert(input_note.commitment());
    let merkle_proof = tree.proof(leaf_idx);
    let merkle_root = tree.root();

    let output_note = RailgunNote::new(
        wallet.master_public_key,
        1_000_000_000_000_000_000u128,
        Field::from(0u64),
        Field::rand(&mut rng),
    );

    let bound_params_hash = RailgunProver::compute_bound_params_hash_simple(0, 0, 0, 1);

    // Compute nullifiers using circuit formula: Poseidon(nullifyingKey, leafIndex)
    let nullifiers = vec![RailgunNote::joinsplit_nullifier(
        wallet.nullifying_key,
        leaf_idx,
    )];
    let commitments = vec![output_note.commitment()];

    let (pk_x, pk_y) = wallet.spending.public_xy();
    let message = compute_message_hash(merkle_root, bound_params_hash, &nullifiers, &commitments);
    let signature = wallet.spending.sign(message);

    let witness = TransactWitness {
        merkle_root,
        bound_params_hash,
        token: Field::from(0u64),
        public_key: [pk_x, pk_y],
        signature: signature.to_circuit_inputs(),
        input_notes: vec![input_note],
        input_merkle_proofs: vec![merkle_proof],
        input_merkle_indices: vec![leaf_idx],
        output_notes: vec![output_note],
        nullifying_key: wallet.nullifying_key,
    };

    println!("Generating proof for verification test...");
    println!("=== EXPECTED VALUES (computed by test) ===");
    println!("  merkleRoot: {:?}", merkle_root);
    println!("  boundParamsHash: {:?}", bound_params_hash);
    println!("  nullifier[0]: {:?}", nullifiers[0]);
    println!("  commitment[0]: {:?}", commitments[0]);
    println!("  message (signed): {:?}", message);
    println!("  pk_x: {:?}", pk_x);
    println!("  pk_y: {:?}", pk_y);
    println!("  signature R8.x: {:?}", signature.r8_x);
    println!("  signature R8.y: {:?}", signature.r8_y);
    println!("  signature S: {:?}", signature.s);

    let proof = prover
        .prove_transact(witness)
        .await
        .expect("proof generation");

    println!("=== ACTUAL VALUES (from circuit witness) ===");
    println!(
        "  public_inputs[0] (merkleRoot): {:?}",
        proof.public_inputs[0]
    );
    println!(
        "  public_inputs[1] (boundParamsHash): {:?}",
        proof.public_inputs[1]
    );
    println!(
        "  public_inputs[2] (nullifier[0]): {:?}",
        proof.public_inputs[2]
    );
    println!(
        "  public_inputs[3] (commitment[0]): {:?}",
        proof.public_inputs[3]
    );

    // Check for mismatches
    println!("=== COMPARISON ===");
    println!(
        "  merkleRoot match: {}",
        merkle_root == proof.public_inputs[0]
    );
    println!(
        "  boundParamsHash match: {}",
        bound_params_hash == proof.public_inputs[1]
    );
    println!(
        "  nullifier match: {}",
        nullifiers[0] == proof.public_inputs[2]
    );
    println!(
        "  commitment match: {}",
        commitments[0] == proof.public_inputs[3]
    );

    println!("Verifying proof locally...");
    let variant = CircuitVariant::new(1, 1).unwrap();
    let result = prover.verify(&variant, &proof).await;

    match result {
        Ok(valid) => {
            println!(
                "[OK] Verification result: {}",
                if valid { "VALID" } else { "INVALID" }
            );
            if !valid {
                println!("DEBUG: The proof generated successfully but verification failed.");
                println!("This typically means the public inputs used for verification");
                println!("don't match the actual witness values.");
            }
            assert!(valid, "Proof should be valid");
        }
        Err(e) => {
            panic!("[FAIL] Verification failed: {}", e);
        }
    }
}
