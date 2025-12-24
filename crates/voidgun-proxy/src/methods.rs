//! JSON-RPC method implementations
//!
//! Both custom voidgun_* methods and intercepted eth_* methods.

use alloy_primitives::{Address, U256};
use railgun_lane::PoolLane;
use serde_json::{json, Value};

use crate::error::{ProxyError, ProxyResult};
use crate::jsonrpc::JsonRpcRequest;
use crate::proxy::RpcProxy;

// === Voidgun Custom Methods ===

/// Initialize a wallet for privacy features
/// Params: [address, signature]
/// The signature should be over RAILGUN_DOMAIN_MESSAGE
pub async fn voidgun_init(proxy: &RpcProxy, request: &JsonRpcRequest) -> ProxyResult<Value> {
    let params = request.params_as_array()?;
    if params.len() < 2 {
        return Err(ProxyError::InvalidRequest(
            "Expected [address, signature]".into(),
        ));
    }

    let address = RpcProxy::parse_address(&params[0])?;
    let sig_hex = params[1]
        .as_str()
        .ok_or_else(|| ProxyError::InvalidRequest("Signature must be hex string".into()))?;

    let signature =
        hex::decode(sig_hex.trim_start_matches("0x")).map_err(|_| ProxyError::InvalidSignature)?;

    let ctx = proxy
        .store
        .init_from_signature(proxy.chain_id, address, &signature)
        .await?;

    let lane = ctx.lane.read().await;
    let receiving_addr = lane.receiving_address().unwrap_or_default();

    Ok(json!({
        "initialized": true,
        "address": format!("{:?}", address),
        "receivingAddress": receiving_addr
    }))
}

/// Get shielded balance for a token
/// Params: [address, token?]
/// token defaults to Address::ZERO (native ETH in pool)
pub async fn voidgun_shielded_balance(
    proxy: &RpcProxy,
    request: &JsonRpcRequest,
) -> ProxyResult<Value> {
    let params = request.params_as_array()?;
    if params.is_empty() {
        return Err(ProxyError::InvalidRequest("Expected [address]".into()));
    }

    let address = RpcProxy::parse_address(&params[0])?;
    let token = if params.len() > 1 {
        RpcProxy::parse_address(&params[1])?
    } else {
        Address::ZERO
    };

    let ctx = proxy
        .store
        .get(proxy.chain_id, address)
        .ok_or(ProxyError::NotInitialized)?;

    let balance = ctx
        .lane
        .read()
        .await
        .get_balance(token)
        .await
        .map_err(ProxyError::Lane)?;

    Ok(json!({
        "token": format!("{:?}", token),
        "balance": format!("0x{:x}", balance.balance),
        "formatted": balance.formatted_balance(),
        "symbol": balance.symbol(),
        "noteCount": balance.note_count
    }))
}

/// Get all shielded balances
/// Params: [address]
pub async fn voidgun_all_balances(
    proxy: &RpcProxy,
    request: &JsonRpcRequest,
) -> ProxyResult<Value> {
    let params = request.params_as_array()?;
    if params.is_empty() {
        return Err(ProxyError::InvalidRequest("Expected [address]".into()));
    }

    let address = RpcProxy::parse_address(&params[0])?;

    let ctx = proxy
        .store
        .get(proxy.chain_id, address)
        .ok_or(ProxyError::NotInitialized)?;

    let balances = ctx
        .lane
        .read()
        .await
        .get_all_balances()
        .await
        .map_err(ProxyError::Lane)?;

    let result: Vec<Value> = balances
        .iter()
        .map(|b| {
            json!({
                "token": format!("{:?}", b.token),
                "balance": format!("0x{:x}", b.balance),
                "formatted": b.formatted_balance(),
                "symbol": b.symbol(),
                "noteCount": b.note_count
            })
        })
        .collect();

    Ok(Value::Array(result))
}

/// Sync wallet state from on-chain events
/// Params: [address]
pub async fn voidgun_sync(proxy: &RpcProxy, request: &JsonRpcRequest) -> ProxyResult<Value> {
    let params = request.params_as_array()?;
    if params.is_empty() {
        return Err(ProxyError::InvalidRequest("Expected [address]".into()));
    }

    let address = RpcProxy::parse_address(&params[0])?;

    let ctx = proxy
        .store
        .get(proxy.chain_id, address)
        .ok_or(ProxyError::NotInitialized)?;

    let synced_block = ctx
        .lane
        .write()
        .await
        .sync_to_latest()
        .await
        .map_err(ProxyError::Lane)?;

    proxy
        .store
        .update_synced_block(proxy.chain_id, address, synced_block)
        .await?;

    Ok(json!({
        "syncedBlock": synced_block
    }))
}

/// Unshield (withdraw) tokens to a public address
/// Params: [from, to, amount, token?]
pub async fn voidgun_unshield(proxy: &RpcProxy, request: &JsonRpcRequest) -> ProxyResult<Value> {
    let params = request.params_as_array()?;
    if params.len() < 3 {
        return Err(ProxyError::InvalidRequest(
            "Expected [from, to, amount]".into(),
        ));
    }

    let from = RpcProxy::parse_address(&params[0])?;
    let to = RpcProxy::parse_address(&params[1])?;

    let amount_str = params[2]
        .as_str()
        .ok_or_else(|| ProxyError::InvalidRequest("Amount must be hex string".into()))?;
    let amount = U256::from_str_radix(amount_str.trim_start_matches("0x"), 16)
        .map_err(|_| ProxyError::InvalidRequest("Invalid amount".into()))?;

    let token = if params.len() > 3 {
        RpcProxy::parse_address(&params[3])?
    } else {
        Address::ZERO
    };

    let ctx = proxy
        .store
        .get(proxy.chain_id, from)
        .ok_or(ProxyError::NotInitialized)?;

    let result = ctx
        .lane
        .write()
        .await
        .unshield(token, amount, to)
        .await
        .map_err(ProxyError::Lane)?;

    Ok(json!({
        "txHash": result.tx_hash.map(hex::encode),
        "proofGenerated": result.proof.is_some(),
        "commitment": result.commitment.map(|c| format!("{:?}", c))
    }))
}

/// Get the 0zk receiving address for a wallet
/// Params: [address]
pub async fn voidgun_address(proxy: &RpcProxy, request: &JsonRpcRequest) -> ProxyResult<Value> {
    let params = request.params_as_array()?;
    if params.is_empty() {
        return Err(ProxyError::InvalidRequest("Expected [address]".into()));
    }

    let address = RpcProxy::parse_address(&params[0])?;

    let ctx = proxy
        .store
        .get(proxy.chain_id, address)
        .ok_or(ProxyError::NotInitialized)?;

    let receiving_addr = ctx
        .lane
        .read()
        .await
        .receiving_address()
        .unwrap_or_default();

    Ok(json!({
        "address": format!("{:?}", address),
        "receivingAddress": receiving_addr
    }))
}

// === Standard Ethereum Methods (with privacy interception) ===

/// eth_getBalance - returns shielded balance if wallet is initialized
/// Params: [address, blockTag]
pub async fn eth_get_balance(proxy: &RpcProxy, request: &JsonRpcRequest) -> ProxyResult<Value> {
    let params = request.params_as_array()?;
    if params.is_empty() {
        return Err(ProxyError::InvalidRequest("Expected [address]".into()));
    }

    let address = RpcProxy::parse_address(&params[0])?;

    // Check if this wallet has been initialized for privacy
    if let Some(ctx) = proxy.store.get(proxy.chain_id, address) {
        if ctx.is_initialized().await {
            // Return shielded balance (ETH in pool)
            let balance = ctx
                .lane
                .read()
                .await
                .get_balance(Address::ZERO)
                .await
                .map_err(ProxyError::Lane)?;

            return Ok(Value::String(format!("0x{:x}", balance.balance)));
        }
    }

    // Not a privacy wallet, forward to upstream
    proxy.forward_to_upstream(request).await
}

/// eth_sendTransaction - intercept and route through Railgun if applicable
/// Params: [{ from, to, value, data, ... }]
pub async fn eth_send_transaction(
    proxy: &RpcProxy,
    request: &JsonRpcRequest,
) -> ProxyResult<Value> {
    let params = request.params_as_array()?;
    if params.is_empty() {
        return Err(ProxyError::InvalidRequest("Expected [txObject]".into()));
    }

    let tx = &params[0];
    let from = tx
        .get("from")
        .ok_or_else(|| ProxyError::InvalidRequest("Missing 'from' field".into()))?;
    let from_addr = RpcProxy::parse_address(from)?;

    // Check if sender has initialized privacy
    let ctx = match proxy.store.get(proxy.chain_id, from_addr) {
        Some(c) if c.is_initialized().await => c,
        _ => {
            // Not a privacy wallet, forward normally
            return proxy.forward_to_upstream(request).await;
        }
    };

    // Parse transaction fields
    let to = tx.get("to").and_then(|v| v.as_str());
    let value_hex = tx.get("value").and_then(|v| v.as_str()).unwrap_or("0x0");
    let data = tx.get("data").and_then(|v| v.as_str()).unwrap_or("0x");

    // Determine if this is a simple ETH transfer (unshield candidate)
    let is_simple_transfer = data == "0x" || data.is_empty();

    if is_simple_transfer {
        if let Some(to_str) = to {
            if let Ok(to_addr) = to_str.parse::<Address>() {
                // Parse amount
                let amount = U256::from_str_radix(value_hex.trim_start_matches("0x"), 16)
                    .map_err(|_| ProxyError::InvalidRequest("Invalid value".into()))?;

                if amount > U256::ZERO {
                    // This is a simple ETH transfer from a privacy wallet
                    // Execute as unshield
                    tracing::info!(
                        "Intercepting transfer: {} -> {} ({} wei)",
                        from_addr,
                        to_addr,
                        amount
                    );

                    let result = ctx
                        .lane
                        .write()
                        .await
                        .unshield(Address::ZERO, amount, to_addr)
                        .await
                        .map_err(ProxyError::Lane)?;

                    return match result.tx_hash {
                        Some(h) => Ok(Value::String(format!("0x{}", hex::encode(h)))),
                        None => Err(ProxyError::TransactionFailed(
                            "Transaction proof generated but not submitted".into(),
                        )),
                    };
                }
            }
        }
    }

    // For non-simple transactions (contract calls, etc.), forward to upstream
    // In the future, we could handle:
    // - Shield: deposits to Railgun contract
    // - Private transfers: to 0zk addresses
    // - DEX swaps: through privacy-preserving routing
    tracing::warn!(
        "Non-simple transaction from privacy wallet, forwarding to upstream: {:?}",
        tx
    );
    proxy.forward_to_upstream(request).await
}

/// personal_sign - intercept domain message signing for key derivation
/// Params: [message, address]
pub async fn personal_sign(proxy: &RpcProxy, request: &JsonRpcRequest) -> ProxyResult<Value> {
    let params = request.params_as_array()?;
    if params.len() < 2 {
        return Err(ProxyError::InvalidRequest(
            "Expected [message, address]".into(),
        ));
    }

    let message = params[0]
        .as_str()
        .ok_or_else(|| ProxyError::InvalidRequest("Message must be string".into()))?;

    // Check if this is our domain message
    if message == railgun_lane::RAILGUN_DOMAIN_MESSAGE {
        let address = RpcProxy::parse_address(&params[1])?;

        // Forward to upstream to get actual signature
        let signature_result = proxy.forward_to_upstream(request).await?;

        let sig_hex = signature_result
            .as_str()
            .ok_or_else(|| ProxyError::UpstreamRpc("Expected signature string".into()))?;

        // Initialize the wallet with this signature
        let signature = hex::decode(sig_hex.trim_start_matches("0x"))
            .map_err(|_| ProxyError::InvalidSignature)?;

        proxy
            .store
            .init_from_signature(proxy.chain_id, address, &signature)
            .await?;

        tracing::info!("Initialized privacy wallet for {:?}", address);

        return Ok(signature_result);
    }

    // Not our domain message, forward normally
    proxy.forward_to_upstream(request).await
}
