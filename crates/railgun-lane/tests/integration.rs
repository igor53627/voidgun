//! Integration tests for RailgunLane using Tenderly (Mainnet fork)
//!
//! These tests require TENDERLY_RPC_URL environment variable to be set.
//! Get it from ~/.zsh_secrets or Tenderly dashboard.
//!
//! Run with: cargo test -p railgun-lane --test integration -- --ignored

use alloy_primitives::Address;
use railgun_lane::{EventSyncer, PoolLane, RailgunLane, RailgunRpcClient, RailgunWallet};

/// Railgun mainnet deployment block (approximate)
const RAILGUN_DEPLOY_BLOCK: u64 = 14_500_000;

/// Recent block to start syncing from (to avoid scanning entire history)
/// Using a very recent block to avoid archive node requirements
const RECENT_BLOCK: u64 = 21_400_000; // December 2024

fn get_rpc_url() -> String {
    // Try explicit URL first
    if let Ok(url) = std::env::var("TENDERLY_RPC_URL") {
        println!("Using TENDERLY_RPC_URL");
        return url;
    }

    // Try ETH_RPC_URL (common env var)
    if let Ok(url) = std::env::var("ETH_RPC_URL") {
        println!("Using ETH_RPC_URL");
        return url;
    }

    // Fallback to public RPC
    println!("Using public RPC (eth.drpc.org)");
    "https://eth.drpc.org".to_string()
}

#[allow(dead_code)]
fn get_tenderly_rpc() -> Option<String> {
    std::env::var("TENDERLY_RPC_URL").ok()
}

#[tokio::test]
#[ignore = "requires RPC access"]
async fn test_rpc_client_fetch_events() {
    let rpc_url = get_rpc_url();

    let client = RailgunRpcClient::new(&rpc_url, 1).expect("Failed to create client");

    // Fetch a small range of events (max 800 blocks for Cloudflare)
    let events = client
        .fetch_all_events(RECENT_BLOCK, RECENT_BLOCK + 500)
        .await
        .expect("Failed to fetch events");

    println!(
        "Fetched {} events from blocks {} to {}",
        events.len(),
        RECENT_BLOCK,
        RECENT_BLOCK + 500
    );

    // Should have at least some events (Railgun is active on mainnet)
    // Note: This might be 0 if no activity in that range
    println!("Event breakdown:");
    let shields = events
        .iter()
        .filter(|e| matches!(e, railgun_lane::RailgunEvent::Shield(_)))
        .count();
    let transacts = events
        .iter()
        .filter(|e| matches!(e, railgun_lane::RailgunEvent::Transact(_)))
        .count();
    let nullifiers = events
        .iter()
        .filter(|e| matches!(e, railgun_lane::RailgunEvent::Nullifier(_)))
        .count();
    println!("  Shields: {}", shields);
    println!("  Transacts: {}", transacts);
    println!("  Nullifiers: {}", nullifiers);
}

#[tokio::test]
#[ignore = "requires RPC access"]
async fn test_lane_init_and_address() {
    let rpc_url = get_rpc_url();

    // Create lane with Tenderly RPC
    let mut lane = RailgunLane::with_rpc(
        1, // Ethereum mainnet
        "0xc0BEF2D373A1EfaDE8B952f33c1370E486f209Cc"
            .parse()
            .unwrap(),
        "crates/railgun-lane/artifacts",
        &rpc_url,
    );

    // Initialize with a test signature
    let test_sig = [0x42u8; 65];
    lane.init(&test_sig).await.expect("Failed to init");

    assert!(lane.is_initialized());

    // Get receiving address
    let addr = lane.receiving_address().expect("Should have address");
    println!("0zk address: {}", addr);
    assert!(addr.starts_with("0zk1"), "Expected mainnet 0zk1 prefix");

    // Parse it back
    let (version, _mpk, chain_id, _vpk) =
        RailgunWallet::parse_0zk_address(&addr).expect("Failed to parse address");
    assert_eq!(version, 0x01);
    assert_eq!(chain_id, 1);
}

#[tokio::test]
#[ignore = "requires RPC access"]
async fn test_lane_sync() {
    let rpc_url = get_rpc_url();

    let mut lane = RailgunLane::with_rpc(
        1,
        "0xc0BEF2D373A1EfaDE8B952f33c1370E486f209Cc"
            .parse()
            .unwrap(),
        "crates/railgun-lane/artifacts",
        &rpc_url,
    );

    // Initialize
    let test_sig = [0x42u8; 65];
    lane.init(&test_sig).await.expect("Failed to init");

    // Sync a small range
    let synced_block = lane.sync(RECENT_BLOCK).await.expect("Failed to sync");

    println!("Synced to block {}", synced_block);
    assert!(synced_block > RECENT_BLOCK);

    // Check balance (should be 0 for test wallet)
    let balance = lane
        .get_balance(Address::ZERO)
        .await
        .expect("Failed to get balance");
    println!(
        "ETH balance: {} (from {} notes)",
        balance.balance, balance.note_count
    );
}

#[tokio::test]
#[ignore = "requires RPC access"]
async fn test_event_syncer() {
    let rpc_url = get_rpc_url();

    let client = RailgunRpcClient::new(&rpc_url, 1).expect("Failed to create client");
    let mut syncer = EventSyncer::new(client, RECENT_BLOCK);

    // Sync a batch
    let events = syncer
        .sync_to(RECENT_BLOCK + 5000)
        .await
        .expect("Failed to sync");

    println!("Syncer fetched {} events", events.len());
    println!("Current synced block: {}", syncer.synced_block());

    assert_eq!(syncer.synced_block(), RECENT_BLOCK + 5000);
}

#[test]
fn test_wallet_deterministic() {
    // Test that wallet derivation is deterministic
    let sig1 = [0xAB; 65];
    let sig2 = [0xAB; 65];
    let sig3 = [0xCD; 65];

    let wallet1 = RailgunWallet::from_wallet_signature(&sig1).unwrap();
    let wallet2 = RailgunWallet::from_wallet_signature(&sig2).unwrap();
    let wallet3 = RailgunWallet::from_wallet_signature(&sig3).unwrap();

    // Same signature = same wallet
    assert_eq!(wallet1.master_public_key, wallet2.master_public_key);

    // Different signature = different wallet
    assert_ne!(wallet1.master_public_key, wallet3.master_public_key);

    // Addresses should match for same wallet
    assert_eq!(wallet1.to_0zk_address(1), wallet2.to_0zk_address(1));
}

#[test]
fn test_0zk_address_roundtrip() {
    let sig = [0x12; 65];
    let wallet = RailgunWallet::from_wallet_signature(&sig).unwrap();

    // Test multiple chains
    for chain_id in [1u64, 137, 11155111, 42161] {
        let addr = wallet.to_0zk_address(chain_id);
        let (version, mpk, parsed_chain, vpk) = RailgunWallet::parse_0zk_address(&addr).unwrap();

        assert_eq!(version, 0x01);
        assert_eq!(mpk, wallet.master_public_key);
        assert_eq!(parsed_chain, chain_id);
        assert_eq!(&vpk, wallet.viewing.public.as_bytes());
    }
}
