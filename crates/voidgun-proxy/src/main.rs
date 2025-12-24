//! Voidgun RPC Proxy Server
//!
//! Usage:
//!   voidgun-proxy --upstream <RPC_URL> --chain-id <CHAIN_ID> [--port <PORT>] [--db <PATH>]
//!
//! Example:
//!   voidgun-proxy --upstream https://eth.llamarpc.com --chain-id 1 --port 8545

use std::env;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use voidgun_proxy::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            env::var("RUST_LOG").unwrap_or_else(|_| "info,voidgun_proxy=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args: Vec<String> = env::args().collect();

    let mut upstream_url = String::new();
    let mut chain_id: u64 = 1;
    let mut port: u16 = 8545;
    let mut db_path = String::from("voidgun.db");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--upstream" | "-u" => {
                i += 1;
                upstream_url = args.get(i).cloned().unwrap_or_default();
            }
            "--chain-id" | "-c" => {
                i += 1;
                chain_id = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(1);
            }
            "--port" | "-p" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(8545);
            }
            "--db" | "-d" => {
                i += 1;
                db_path = args.get(i).cloned().unwrap_or_else(|| "voidgun.db".into());
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    if upstream_url.is_empty() {
        upstream_url = env::var("UPSTREAM_RPC_URL")
            .or_else(|_| env::var("ETH_RPC_URL"))
            .or_else(|_| env::var("MAINNET_RPC_URL"))
            .unwrap_or_else(|_| "https://eth.llamarpc.com".into());
    }

    tracing::info!("Starting Voidgun RPC Proxy");
    tracing::info!("  Upstream: {}", upstream_url);
    tracing::info!("  Chain ID: {}", chain_id);
    tracing::info!("  Database: {}", db_path);
    tracing::info!("  Port: {}", port);

    let database_url = format!("sqlite://{}?mode=rwc", db_path);
    let server = Server::new(upstream_url, chain_id, &database_url).await?;

    let addr = format!("0.0.0.0:{}", port);
    server.run(&addr).await?;

    Ok(())
}

fn print_help() {
    println!(
        r#"Voidgun RPC Proxy Server

Privacy-via-proxy implementation based on the Nullmask research paper.
Intercepts wallet transactions and routes them through Railgun privacy pool.

USAGE:
    voidgun-proxy [OPTIONS]

OPTIONS:
    -u, --upstream <URL>    Upstream Ethereum RPC URL
                            Default: $ETH_RPC_URL or https://eth.llamarpc.com
    -c, --chain-id <ID>     Chain ID (1 = mainnet, 11155111 = sepolia)
                            Default: 1
    -p, --port <PORT>       Port to listen on
                            Default: 8545
    -d, --db <PATH>         SQLite database path
                            Default: voidgun.db
    -h, --help              Print help

ENVIRONMENT VARIABLES:
    UPSTREAM_RPC_URL, ETH_RPC_URL, MAINNET_RPC_URL
        Upstream RPC URL (if --upstream not specified)
    RUST_LOG
        Logging level (default: info,voidgun_proxy=debug)

EXAMPLE:
    # Start proxy for Ethereum mainnet
    voidgun-proxy --upstream https://eth.llamarpc.com --chain-id 1

    # Start proxy for Sepolia testnet
    voidgun-proxy --upstream https://sepolia.infura.io/v3/KEY --chain-id 11155111

WALLET SETUP:
    1. In your wallet, add a custom network with RPC URL: http://localhost:8545
    2. The proxy will prompt for a signature to derive your privacy keys
    3. Your wallet will now show your shielded balance
    4. Transactions will be automatically routed through Railgun

CUSTOM METHODS:
    voidgun_init            Initialize privacy wallet with signature
    voidgun_shieldedBalance Get shielded balance for a token
    voidgun_allBalances     Get all shielded balances
    voidgun_sync            Sync wallet state from chain
    voidgun_unshield        Withdraw tokens to public address
    voidgun_address         Get 0zk receiving address
"#
    );
}
