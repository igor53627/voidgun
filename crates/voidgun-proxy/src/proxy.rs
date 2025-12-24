//! Core RPC proxy logic
//!
//! Routes JSON-RPC calls to either:
//! - Custom Voidgun handlers (balance, transactions, key derivation)
//! - Upstream Ethereum node (everything else)

use std::sync::Arc;

use alloy_primitives::Address;
use serde_json::Value;

use crate::context::UserContextStore;
use crate::error::{ProxyError, ProxyResult};
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse};
use crate::methods;

pub struct RpcProxy {
    pub store: Arc<UserContextStore>,
    pub upstream_url: String,
    pub chain_id: u64,
    http_client: reqwest::Client,
}

impl RpcProxy {
    pub fn new(store: Arc<UserContextStore>, upstream_url: String, chain_id: u64) -> Self {
        Self {
            store,
            upstream_url,
            chain_id,
            http_client: reqwest::Client::new(),
        }
    }

    pub async fn handle(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let id = request.id.clone();

        match self.dispatch(&request).await {
            Ok(result) => JsonRpcResponse::success(id, result),
            Err(e) => JsonRpcResponse::from_error(id, e),
        }
    }

    async fn dispatch(&self, request: &JsonRpcRequest) -> ProxyResult<Value> {
        match request.method.as_str() {
            // === Voidgun custom methods (for debugging/explicit use) ===
            "voidgun_init" => methods::voidgun_init(self, request).await,
            "voidgun_shieldedBalance" => methods::voidgun_shielded_balance(self, request).await,
            "voidgun_allBalances" => methods::voidgun_all_balances(self, request).await,
            "voidgun_sync" => methods::voidgun_sync(self, request).await,
            "voidgun_unshield" => methods::voidgun_unshield(self, request).await,
            "voidgun_address" => methods::voidgun_address(self, request).await,

            // === Standard Ethereum methods with privacy interception ===
            "eth_getBalance" => methods::eth_get_balance(self, request).await,
            "eth_sendTransaction" => methods::eth_send_transaction(self, request).await,
            "personal_sign" => methods::personal_sign(self, request).await,

            // === Chain info (handle locally for consistency) ===
            "eth_chainId" => Ok(Value::String(format!("0x{:x}", self.chain_id))),
            "net_version" => Ok(Value::String(self.chain_id.to_string())),

            // === Forward everything else to upstream ===
            _ => self.forward_to_upstream(request).await,
        }
    }

    pub async fn forward_to_upstream(&self, request: &JsonRpcRequest) -> ProxyResult<Value> {
        let response = self
            .http_client
            .post(&self.upstream_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": &request.method,
                "params": &request.params,
                "id": &request.id
            }))
            .send()
            .await
            .map_err(|e| ProxyError::UpstreamRpc(e.to_string()))?;

        let json: Value = response
            .json()
            .await
            .map_err(|e| ProxyError::UpstreamRpc(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(ProxyError::UpstreamRpc(error.to_string()));
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| ProxyError::UpstreamRpc("No result in response".into()))
    }

    pub fn parse_address(value: &Value) -> ProxyResult<Address> {
        let s = value
            .as_str()
            .ok_or_else(|| ProxyError::InvalidAddress("Expected string".into()))?;
        s.parse()
            .map_err(|_| ProxyError::InvalidAddress(s.to_string()))
    }
}
