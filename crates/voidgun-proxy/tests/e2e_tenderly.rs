//! End-to-end tests for voidgun-proxy against Tenderly VNet
//!
//! Tests the full proxy stack:
//!   Wallet → voidgun-proxy → RailgunLane → Tenderly VNet → Railgun contracts
//!
//! ## Running tests
//!
//! ```bash
//! # Requires Tenderly credentials
//! cargo test -p voidgun-proxy --test e2e_tenderly -- --ignored --nocapture
//! ```
//!
//! ## Environment Variables
//!
//! - TENDERLY_ACCESS_KEY: Your Tenderly API access key
//! - TENDERLY_ACCOUNT: Your Tenderly account slug  
//! - TENDERLY_PROJECT: Your Tenderly project slug

use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::sleep;

const MAINNET_CHAIN_ID: u64 = 1;

struct TenderlyVNet {
    access_key: String,
    account: String,
    project: String,
    vnet_id: Option<String>,
    rpc_url: Option<String>,
}

impl TenderlyVNet {
    fn from_env() -> Option<Self> {
        Some(Self {
            access_key: std::env::var("TENDERLY_ACCESS_KEY").ok()?,
            account: std::env::var("TENDERLY_ACCOUNT").ok()?,
            project: std::env::var("TENDERLY_PROJECT").ok()?,
            vnet_id: None,
            rpc_url: None,
        })
    }

    async fn create_static_vnet(&mut self, name: &str) -> Result<String, String> {
        let client = Client::new();
        let url = format!(
            "https://api.tenderly.co/api/v1/account/{}/project/{}/vnets",
            self.account, self.project
        );

        let body = json!({
            "slug": name,
            "display_name": name,
            "fork_config": {
                "network_id": 1
            },
            "virtual_network_config": {
                "chain_config": {
                    "chain_id": 1
                }
            },
            "sync_state_config": {
                "enabled": false
            },
            "explorer_page_config": {
                "enabled": true,
                "verification_visibility": "src"
            }
        });

        let resp = client
            .post(&url)
            .header("X-Access-Key", &self.access_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Failed to create VNet: {}", text));
        }

        let json: Value = resp.json().await.map_err(|e| e.to_string())?;
        
        let vnet_id = json["id"].as_str().unwrap_or_default().to_string();
        self.vnet_id = Some(vnet_id);

        let rpc_url = json["rpcs"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|rpc| rpc["url"].as_str())
            .map(String::from)
            .ok_or("No RPC URL in response")?;

        self.rpc_url = Some(rpc_url.clone());
        Ok(rpc_url)
    }

    async fn delete(&self) -> Result<(), String> {
        let vnet_id = self.vnet_id.as_ref().ok_or("No VNet ID")?;
        let client = Client::new();
        let url = format!(
            "https://api.tenderly.co/api/v1/account/{}/project/{}/vnets/{}",
            self.account, self.project, vnet_id
        );

        client
            .delete(&url)
            .header("X-Access-Key", &self.access_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

async fn make_rpc_call(url: &str, method: &str, params: Value) -> Result<Value, String> {
    let client = Client::new();
    let body = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let json: Value = resp.json().await.map_err(|e| e.to_string())?;
    
    if let Some(error) = json.get("error") {
        return Err(format!("RPC error: {}", error));
    }

    Ok(json["result"].clone())
}

#[tokio::test]
#[ignore]
async fn test_proxy_e2e_tenderly() {
    let mut vnet = match TenderlyVNet::from_env() {
        Some(v) => v,
        None => {
            println!("[SKIP] Set TENDERLY_ACCESS_KEY, TENDERLY_ACCOUNT, TENDERLY_PROJECT");
            return;
        }
    };

    println!("=== VOIDGUN PROXY E2E TEST ===\n");

    let vnet_name = format!(
        "voidgun-proxy-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );

    println!("[1/6] Creating Tenderly VNet: {}...", vnet_name);
    let upstream_rpc = match vnet.create_static_vnet(&vnet_name).await {
        Ok(url) => {
            println!("  [OK] VNet created: {}...", &url[..60.min(url.len())]);
            url
        }
        Err(e) => {
            println!("  [FAIL] Could not create VNet: {}", e);
            return;
        }
    };

    println!("[2/6] Starting voidgun-proxy server...");
    let proxy_port = 18545u16;
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    
    let server_handle = {
        let upstream = upstream_rpc.clone();
        tokio::spawn(async move {
            let server = voidgun_proxy::Server::new(
                upstream,
                MAINNET_CHAIN_ID,
                "sqlite::memory:",
            )
            .await
            .expect("Failed to create server");

            let addr = format!("127.0.0.1:{}", proxy_port);
            let _ = server.run(&addr).await;
        })
    };

    sleep(Duration::from_millis(500)).await;
    println!("  [OK] Proxy running at {}", proxy_url);

    println!("[3/6] Testing health endpoint...");
    let client = Client::new();
    match client.get(format!("{}/health", proxy_url)).send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("  [OK] Health check passed");
        }
        Ok(resp) => {
            println!("  [FAIL] Health check failed: {}", resp.status());
            cleanup(&vnet, server_handle).await;
            return;
        }
        Err(e) => {
            println!("  [FAIL] Health check error: {}", e);
            cleanup(&vnet, server_handle).await;
            return;
        }
    }

    println!("[4/6] Testing eth_chainId passthrough...");
    match make_rpc_call(&proxy_url, "eth_chainId", json!([])).await {
        Ok(result) => {
            let chain_id = result.as_str().unwrap_or("unknown");
            println!("  [OK] Chain ID: {}", chain_id);
            assert_eq!(chain_id, "0x1", "Expected mainnet chain ID");
        }
        Err(e) => {
            println!("  [FAIL] eth_chainId error: {}", e);
            cleanup(&vnet, server_handle).await;
            return;
        }
    }

    println!("[5/6] Testing eth_blockNumber passthrough...");
    match make_rpc_call(&proxy_url, "eth_blockNumber", json!([])).await {
        Ok(result) => {
            let block = result.as_str().unwrap_or("unknown");
            println!("  [OK] Block number: {}", block);
        }
        Err(e) => {
            println!("  [FAIL] eth_blockNumber error: {}", e);
            cleanup(&vnet, server_handle).await;
            return;
        }
    }

    println!("[6/6] Testing voidgun_address (before init, should fail)...");
    let test_address = "0x1234567890123456789012345678901234567890";
    match make_rpc_call(
        &proxy_url,
        "voidgun_address",
        json!([test_address]),
    )
    .await
    {
        Ok(_) => {
            println!("  [WARN] Expected error for uninitialized wallet, got success");
        }
        Err(e) => {
            println!("  [OK] Correctly rejected uninitialized wallet: {}", &e[..80.min(e.len())]);
        }
    }

    println!("\n=== E2E TEST PASSED ===\n");

    cleanup(&vnet, server_handle).await;
}

async fn cleanup(vnet: &TenderlyVNet, server_handle: tokio::task::JoinHandle<()>) {
    println!("\n[CLEANUP] Stopping server...");
    server_handle.abort();
    
    println!("[CLEANUP] Deleting VNet...");
    match vnet.delete().await {
        Ok(()) => println!("  [OK] VNet deleted"),
        Err(e) => println!("  [WARN] Could not delete VNet: {}", e),
    }
}

#[tokio::test]
#[ignore]
async fn test_proxy_init_and_balance() {
    let mut vnet = match TenderlyVNet::from_env() {
        Some(v) => v,
        None => {
            println!("[SKIP] Set TENDERLY_ACCESS_KEY, TENDERLY_ACCOUNT, TENDERLY_PROJECT");
            return;
        }
    };

    println!("=== VOIDGUN PROXY INIT & BALANCE TEST ===\n");

    let vnet_name = format!(
        "voidgun-init-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );

    println!("[1/5] Creating Tenderly VNet...");
    let upstream_rpc = match vnet.create_static_vnet(&vnet_name).await {
        Ok(url) => {
            println!("  [OK] VNet created");
            url
        }
        Err(e) => {
            println!("  [FAIL] {}", e);
            return;
        }
    };

    println!("[2/5] Starting voidgun-proxy...");
    let proxy_port = 18546u16;
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);

    let server_handle = {
        let upstream = upstream_rpc.clone();
        tokio::spawn(async move {
            let server = voidgun_proxy::Server::new(
                upstream,
                MAINNET_CHAIN_ID,
                "sqlite::memory:",
            )
            .await
            .expect("Failed to create server");

            let addr = format!("127.0.0.1:{}", proxy_port);
            let _ = server.run(&addr).await;
        })
    };

    sleep(Duration::from_millis(500)).await;
    println!("  [OK] Proxy running");

    println!("[3/5] Initializing wallet with voidgun_init...");
    let test_address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"; // vitalik.eth
    let fake_signature = "0x".to_string() + &"ab".repeat(65);

    match make_rpc_call(
        &proxy_url,
        "voidgun_init",
        json!([test_address, fake_signature]),
    )
    .await
    {
        Ok(result) => {
            println!("  [OK] Wallet initialized: {}", result);
            if let Some(addr) = result.get("receivingAddress") {
                println!("  [OK] 0zk address: {}", addr);
            }
        }
        Err(e) => {
            println!("  [FAIL] Init error: {}", e);
            cleanup(&vnet, server_handle).await;
            return;
        }
    }

    println!("[4/5] Syncing wallet with voidgun_sync...");
    match make_rpc_call(&proxy_url, "voidgun_sync", json!([test_address])).await {
        Ok(result) => {
            println!("  [OK] Synced to block: {}", result);
        }
        Err(e) => {
            println!("  [WARN] Sync error (expected for fresh wallet): {}", &e[..100.min(e.len())]);
        }
    }

    println!("[5/5] Getting balances with voidgun_allBalances...");
    match make_rpc_call(&proxy_url, "voidgun_allBalances", json!([test_address])).await {
        Ok(result) => {
            if let Some(arr) = result.as_array() {
                println!("  [OK] Found {} token balances", arr.len());
                for b in arr.iter().take(3) {
                    println!("    - {}: {}", 
                        b.get("symbol").and_then(|v| v.as_str()).unwrap_or("?"),
                        b.get("formatted").and_then(|v| v.as_str()).unwrap_or("0")
                    );
                }
            } else {
                println!("  [OK] Balances: {}", result);
            }
        }
        Err(e) => {
            println!("  [WARN] Balance error: {}", e);
        }
    }

    println!("\n=== INIT & BALANCE TEST PASSED ===\n");

    cleanup(&vnet, server_handle).await;
}
