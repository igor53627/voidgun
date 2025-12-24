//! Sepolia testnet integration tests for RailgunLane
//!
//! These tests validate the full RailgunLane flow against Sepolia testnet.
//!
//! ## Running tests
//!
//! ```bash
//! SEPOLIA_RPC_URL="https://sepolia.infura.io/v3/YOUR_KEY" \
//!   cargo test -p railgun-lane --test sepolia_integration -- --ignored --nocapture
//! ```
//!
//! ## Sepolia Railgun Contract Addresses
//!
//! - Proxy (SmartWallet): 0x942D5026b421cf2705363A525897576cFAdA5964
//! - Delegator (Relay): 0x464a0c9e62534b3b160c35638DD7d5cf761f429e
//! - Deployment Block: ~4,495,479

mod common;

use alloy_primitives::Address;
use ark_bn254::Fr as Field;
use ark_ff::UniformRand;
use railgun_lane::{
    GasEstimate, PoolLane, PoolType, RailgunLane, RailgunNote, RailgunRpcClient, RailgunWallet,
    TransactWitness,
};

use common::{compute_message_hash, setup_prover, ARTIFACTS_PATH};

const SEPOLIA_CHAIN_ID: u64 = 11155111;
const SEPOLIA_RELAY: &str = "0x464a0c9e62534b3b160c35638DD7d5cf761f429e";
const SEPOLIA_SMART_WALLET: &str = "0x942D5026b421cf2705363A525897576cFAdA5964";
const SEPOLIA_DEPLOYMENT_BLOCK: u64 = 4_495_479;

fn get_sepolia_rpc() -> Option<String> {
    std::env::var("SEPOLIA_RPC_URL").ok()
}

/// Test that RailgunLane can sync events from Sepolia
#[tokio::test]
#[ignore = "requires SEPOLIA_RPC_URL"]
async fn test_sepolia_sync_events() {
    let rpc_url = match get_sepolia_rpc() {
        Some(url) => url,
        None => {
            println!("[SKIP] Set SEPOLIA_RPC_URL to run this test");
            return;
        }
    };

    println!("=== SEPOLIA SYNC TEST ===");
    println!("RPC: {}...", &rpc_url[..rpc_url.len().min(50)]);

    let contract: Address = SEPOLIA_RELAY.parse().unwrap();
    let mut lane = RailgunLane::with_rpc(SEPOLIA_CHAIN_ID, contract, ARTIFACTS_PATH, &rpc_url);

    // Initialize with a test wallet
    let test_sig = [0x42u8; 65];
    lane.init(&test_sig).await.expect("lane init");

    assert!(lane.is_initialized());
    assert_eq!(lane.pool_type(), PoolType::Railgun);

    // Check that we can get a receiving address
    let addr = lane.receiving_address().expect("should have address");
    println!("Receiving address: {}", addr);
    assert!(
        addr.starts_with("0zks1"),
        "Sepolia address should start with 0zks1"
    );

    // Sync a small block range to verify event fetching works
    let start_block = SEPOLIA_DEPLOYMENT_BLOCK;
    let end_block = start_block + 1000;

    println!(
        "Syncing blocks {} to {} (limited range for speed)...",
        start_block, end_block
    );

    // Use the RPC client directly for controlled sync
    let client = RailgunRpcClient::new(&rpc_url, SEPOLIA_CHAIN_ID).expect("client");

    let current_block = client.get_block_number().await.expect("block number");
    println!("Current Sepolia block: {}", current_block);

    let events = client
        .fetch_all_events(start_block, end_block.min(current_block))
        .await
        .expect("fetch events");

    println!("Fetched {} events in range", events.len());

    // Count event types
    let mut shields = 0;
    let mut transacts = 0;
    let mut nullifiers = 0;
    for event in &events {
        match event {
            railgun_lane::RailgunEvent::Shield(_) => shields += 1,
            railgun_lane::RailgunEvent::Transact(_) => transacts += 1,
            railgun_lane::RailgunEvent::Nullifier(_) => nullifiers += 1,
        }
    }
    println!("  Shield events: {}", shields);
    println!("  Transact events: {}", transacts);
    println!("  Nullifier events: {}", nullifiers);

    println!("[OK] Sepolia sync test passed");
}

/// Test gas estimation on Sepolia
#[tokio::test]
#[ignore = "requires SEPOLIA_RPC_URL"]
async fn test_sepolia_gas_estimation() {
    let rpc_url = match get_sepolia_rpc() {
        Some(url) => url,
        None => {
            println!("[SKIP] Set SEPOLIA_RPC_URL to run this test");
            return;
        }
    };

    println!("=== SEPOLIA GAS ESTIMATION TEST ===");

    let contract: Address = SEPOLIA_RELAY.parse().unwrap();
    let lane = RailgunLane::with_rpc(SEPOLIA_CHAIN_ID, contract, ARTIFACTS_PATH, &rpc_url);

    // Get gas price
    let client = RailgunRpcClient::new(&rpc_url, SEPOLIA_CHAIN_ID).expect("client");
    let gas_price = client.get_gas_price().await.expect("gas price");
    println!(
        "Current gas price: {} wei ({} gwei)",
        gas_price,
        gas_price / 1_000_000_000
    );

    // Estimate transfer gas (uses static estimate)
    let from: Address = "0x0000000000000000000000000000000000000001"
        .parse()
        .unwrap();
    let estimate = lane.estimate_transfer_gas(from).await.expect("estimate");

    println!("Transfer gas estimate:");
    println!("  Gas units: {}", estimate.gas);
    println!("  Gas price: {} wei", estimate.gas_price);
    println!(
        "  Total cost: {} wei ({:.6} ETH)",
        estimate.total_cost,
        estimate.total_cost as f64 / 1e18
    );

    assert!(estimate.gas > 0);
    assert!(estimate.gas_price > 0);

    println!("[OK] Gas estimation test passed");
}

/// Test wallet creation and address generation for Sepolia
#[tokio::test]
async fn test_sepolia_wallet_addresses() {
    println!("=== SEPOLIA WALLET ADDRESS TEST ===");

    let test_sig = [0x42u8; 65];
    let wallet = RailgunWallet::from_wallet_signature(&test_sig).expect("wallet");

    // Generate Sepolia address
    let sepolia_addr = wallet.to_0zk_address(SEPOLIA_CHAIN_ID);
    println!("Sepolia 0zk address: {}", sepolia_addr);
    assert!(
        sepolia_addr.starts_with("0zks1"),
        "Should have Sepolia prefix"
    );

    // Parse it back
    let (version, mpk, chain_id, vpk) =
        RailgunWallet::parse_0zk_address(&sepolia_addr).expect("parse address");

    assert_eq!(version, 0x01);
    assert_eq!(mpk, wallet.master_public_key);
    assert_eq!(chain_id, SEPOLIA_CHAIN_ID);
    println!("  Version: {}", version);
    println!("  Chain ID: {}", chain_id);
    println!("  MPK: 0x{}", hex::encode(mpk.to_string().as_bytes()));

    // Mainnet should be different
    let mainnet_addr = wallet.to_0zk_address(1);
    assert_ne!(sepolia_addr, mainnet_addr);
    assert!(mainnet_addr.starts_with("0zk1"));
    println!("Mainnet 0zk address: {}", mainnet_addr);

    println!("[OK] Wallet address test passed");
}

/// Test that proof generation works for Sepolia chain ID
#[tokio::test]
#[ignore = "requires circuit artifacts"]
async fn test_sepolia_proof_generation() {
    use ark_ff::Zero;

    println!("=== SEPOLIA PROOF GENERATION TEST ===");

    let prover = setup_prover();
    let test_sig = [0x42u8; 65];
    let wallet = RailgunWallet::from_wallet_signature(&test_sig).expect("wallet");

    // Create a test note
    let mut rng = rand::thread_rng();
    let random = Field::rand(&mut rng);
    let token = Field::from(0u64); // ETH
    let value = 1_000_000_000_000_000_000u128; // 1 ETH

    let note = RailgunNote::new(wallet.master_public_key, value, token, random);
    let commitment = note.commitment();
    println!(
        "Test note commitment: 0x{}",
        hex::encode(commitment.to_string().as_bytes())
    );

    // Build a minimal merkle tree
    let mut tree = railgun_lane::NoteMerkleTree::new(16).expect("tree");
    let leaf_idx = tree.insert(commitment).expect("insert");
    let merkle_root = tree.root();
    let merkle_proof = tree.proof(leaf_idx);

    println!(
        "Merkle root: 0x{}",
        hex::encode(merkle_root.to_string().as_bytes())
    );

    // Create output note
    let output_random = Field::rand(&mut rng);
    let output_note = RailgunNote::new(wallet.master_public_key, value, token, output_random);

    // Compute bound params hash for Sepolia
    let bound_params_hash = railgun_lane::RailgunProver::compute_bound_params_hash_simple(
        0, // tree number
        0, // min gas price
        0, // unshield = NONE
        SEPOLIA_CHAIN_ID,
    );

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
        token,
        public_key: [pk_x, pk_y],
        signature: signature.to_circuit_inputs(),
        input_notes: vec![note],
        input_merkle_proofs: vec![merkle_proof],
        input_merkle_indices: vec![leaf_idx],
        output_notes: vec![output_note],
        nullifying_key: wallet.nullifying_key,
    };

    println!(
        "Generating proof for Sepolia (chain ID {})...",
        SEPOLIA_CHAIN_ID
    );
    let start = std::time::Instant::now();

    let proof = prover
        .prove_transact(witness)
        .await
        .expect("proof generation");

    println!("  Proof generated in {:?}", start.elapsed());
    println!("  Proof size: {} bytes", proof.proof_bytes.len());
    println!("  Public inputs: {}", proof.public_inputs.len());

    // Verify locally
    let variant = railgun_lane::artifacts::select_circuit(1, 1).expect("variant");
    let verified = prover.verify_proof(&variant, &proof).await.expect("verify");

    if verified {
        println!("  [OK] Proof verified locally!");
    } else {
        println!("  [FAIL] Local verification failed");
    }

    assert!(verified, "Proof should verify locally");

    println!("[OK] Sepolia proof generation test passed");
}

/// Test RPC client operations on Sepolia
#[tokio::test]
#[ignore = "requires SEPOLIA_RPC_URL"]
async fn test_sepolia_rpc_client() {
    let rpc_url = match get_sepolia_rpc() {
        Some(url) => url,
        None => {
            println!("[SKIP] Set SEPOLIA_RPC_URL to run this test");
            return;
        }
    };

    println!("=== SEPOLIA RPC CLIENT TEST ===");

    let client = RailgunRpcClient::new(&rpc_url, SEPOLIA_CHAIN_ID).expect("client creation");

    // Test block number
    let block = client.get_block_number().await.expect("block number");
    println!("Current block: {}", block);
    assert!(block > SEPOLIA_DEPLOYMENT_BLOCK);

    // Test gas price
    let gas_price = client.get_gas_price().await.expect("gas price");
    println!("Gas price: {} gwei", gas_price / 1_000_000_000);
    assert!(gas_price > 0);

    // Test fetching a single block of events
    let events = client
        .fetch_all_events(block - 100, block)
        .await
        .expect("fetch events");
    println!("Events in last 100 blocks: {}", events.len());

    println!("[OK] RPC client test passed");
}
