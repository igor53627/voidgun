//! RPC client for fetching Railgun events
//!
//! This module provides async event fetching from Ethereum nodes.

use alloy_primitives::{Address, B256};
use alloy_rpc_types::Log;
use alloy_sol_types::SolEvent;
use ark_bn254::Fr as Field;
use ark_ff::PrimeField;
use thiserror::Error;

use crate::contracts::{
    Nullifiers, ParsedNullifierEvent, ParsedShieldCiphertext, ParsedShieldEvent,
    ParsedShieldPreimage, ParsedTransactEvent, RailgunAddresses, Shield, Transact,
};

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Event parsing failed: {0}")]
    ParseFailed(String),

    #[error("No provider configured")]
    NoProvider,

    #[error("Merkle tree error: {0}")]
    MerkleTreeError(String),
}

/// Railgun event types
#[derive(Clone, Debug)]
pub enum RailgunEvent {
    Shield(ParsedShieldEvent),
    Transact(ParsedTransactEvent),
    Nullifier(ParsedNullifierEvent),
}

/// Transaction receipt from eth_getTransactionReceipt
#[derive(Clone, Debug)]
pub struct TransactionReceipt {
    /// Transaction status (true = success, false = revert)
    pub status: bool,
    /// Block number (None if pending)
    pub block_number: Option<u64>,
    /// Gas used
    pub gas_used: u64,
    /// Transaction hash
    pub tx_hash: B256,
}

/// ERC20 token metadata
#[derive(Clone, Debug, Default)]
pub struct TokenMetadata {
    /// Token symbol (e.g., "USDC", "WETH")
    pub symbol: String,
    /// Token name (e.g., "USD Coin", "Wrapped Ether")
    pub name: String,
    /// Token decimals (usually 18, but 6 for USDC/USDT)
    pub decimals: u8,
    /// Optional USD price per token
    pub usd_price: Option<f64>,
}

impl TokenMetadata {
    /// Native ETH metadata
    pub fn eth() -> Self {
        Self {
            symbol: "ETH".into(),
            name: "Ether".into(),
            decimals: 18,
            usd_price: None,
        }
    }

    /// Format a raw balance with proper decimal places
    pub fn format_balance(&self, raw_balance: alloy_primitives::U256) -> String {
        if self.decimals == 0 {
            return raw_balance.to_string();
        }

        let divisor =
            alloy_primitives::U256::from(10u64).pow(alloy_primitives::U256::from(self.decimals));
        let whole = raw_balance / divisor;
        let remainder = raw_balance % divisor;

        if remainder.is_zero() {
            whole.to_string()
        } else {
            let remainder_str = format!("{:0>width$}", remainder, width = self.decimals as usize);
            let trimmed = remainder_str.trim_end_matches('0');
            format!("{}.{}", whole, trimmed)
        }
    }

    /// Calculate USD value of a raw balance
    pub fn usd_value(&self, raw_balance: alloy_primitives::U256) -> Option<f64> {
        let price = self.usd_price?;
        let balance_f64 = self.balance_as_f64(raw_balance);
        Some(balance_f64 * price)
    }

    /// Convert raw balance to f64 (for calculations)
    pub fn balance_as_f64(&self, raw_balance: alloy_primitives::U256) -> f64 {
        let divisor = 10f64.powi(self.decimals as i32);
        let balance_str = raw_balance.to_string();
        let balance_f64: f64 = balance_str.parse().unwrap_or(f64::MAX);
        balance_f64 / divisor
    }
}

/// RPC client for Railgun event fetching
pub struct RailgunRpcClient {
    /// RPC endpoint URL
    pub rpc_url: String,
    /// Contract addresses
    pub addresses: RailgunAddresses,
    /// Chain ID
    pub chain_id: u64,
}

impl RailgunRpcClient {
    /// Create new RPC client
    pub fn new(rpc_url: impl Into<String>, chain_id: u64) -> Result<Self, RpcError> {
        let addresses = RailgunAddresses::for_chain(chain_id).ok_or(RpcError::NoProvider)?;
        Ok(Self {
            rpc_url: rpc_url.into(),
            addresses,
            chain_id,
        })
    }

    /// Get current block number via eth_blockNumber
    pub async fn get_block_number(&self) -> Result<u64, RpcError> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1,
        });

        let client = reqwest::Client::new();
        let response = client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(RpcError::Transport(error.to_string()));
        }

        let result = json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::Transport("No result in response".into()))?;

        // Parse hex string (e.g., "0x1234abc")
        let block_num = u64::from_str_radix(result.trim_start_matches("0x"), 16)
            .map_err(|e| RpcError::ParseFailed(format!("Invalid block number: {}", e)))?;

        Ok(block_num)
    }

    /// Get current gas price via eth_gasPrice
    pub async fn get_gas_price(&self) -> Result<u128, RpcError> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_gasPrice",
            "params": [],
            "id": 1,
        });

        let client = reqwest::Client::new();
        let response = client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(RpcError::Transport(error.to_string()));
        }

        let result = json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::Transport("No result in response".into()))?;

        let gas_price = u128::from_str_radix(result.trim_start_matches("0x"), 16)
            .map_err(|e| RpcError::ParseFailed(format!("Invalid gas price: {}", e)))?;

        Ok(gas_price)
    }

    /// Estimate gas for a transaction via eth_estimateGas
    ///
    /// # Arguments
    /// * `from` - Sender address
    /// * `to` - Contract address
    /// * `data` - Calldata (hex encoded with 0x prefix or raw bytes)
    /// * `value` - Value in wei (optional)
    pub async fn estimate_gas(
        &self,
        from: Address,
        to: Address,
        data: &[u8],
        value: Option<alloy_primitives::U256>,
    ) -> Result<u64, RpcError> {
        use alloy_primitives::hex;

        let mut tx_obj = serde_json::json!({
            "from": format!("{:?}", from),
            "to": format!("{:?}", to),
            "data": format!("0x{}", hex::encode(data)),
        });

        if let Some(val) = value {
            tx_obj["value"] = serde_json::Value::String(format!("0x{:x}", val));
        }

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_estimateGas",
            "params": [tx_obj],
            "id": 1,
        });

        let client = reqwest::Client::new();
        let response = client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(RpcError::Transport(error.to_string()));
        }

        let result = json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::Transport("No result in response".into()))?;

        let gas = u64::from_str_radix(result.trim_start_matches("0x"), 16)
            .map_err(|e| RpcError::ParseFailed(format!("Invalid gas estimate: {}", e)))?;

        Ok(gas)
    }

    /// Get transaction count (nonce) for an address via eth_getTransactionCount
    pub async fn get_transaction_count(&self, address: Address) -> Result<u64, RpcError> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [format!("{:?}", address), "pending"],
            "id": 1,
        });

        let client = reqwest::Client::new();
        let response = client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(RpcError::Transport(error.to_string()));
        }

        let result = json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::Transport("No result in response".into()))?;

        let nonce = u64::from_str_radix(result.trim_start_matches("0x"), 16)
            .map_err(|e| RpcError::ParseFailed(format!("Invalid nonce: {}", e)))?;

        Ok(nonce)
    }

    /// Get max priority fee per gas via eth_maxPriorityFeePerGas (EIP-1559)
    pub async fn get_max_priority_fee(&self) -> Result<u128, RpcError> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_maxPriorityFeePerGas",
            "params": [],
            "id": 1,
        });

        let client = reqwest::Client::new();
        let response = client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(RpcError::Transport(error.to_string()));
        }

        let result = json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::Transport("No result in response".into()))?;

        let fee = u128::from_str_radix(result.trim_start_matches("0x"), 16)
            .map_err(|e| RpcError::ParseFailed(format!("Invalid priority fee: {}", e)))?;

        Ok(fee)
    }

    /// Send raw transaction via eth_sendRawTransaction
    ///
    /// Returns the transaction hash.
    pub async fn send_raw_transaction(&self, signed_tx: &[u8]) -> Result<B256, RpcError> {
        use alloy_primitives::hex;

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [format!("0x{}", hex::encode(signed_tx))],
            "id": 1,
        });

        let client = reqwest::Client::new();
        let response = client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(RpcError::Transport(error.to_string()));
        }

        let result = json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::Transport("No result in response".into()))?;

        // Parse 0x-prefixed hex hash
        let hash_bytes = hex::decode(result.trim_start_matches("0x"))
            .map_err(|e| RpcError::ParseFailed(format!("Invalid tx hash: {}", e)))?;

        if hash_bytes.len() != 32 {
            return Err(RpcError::ParseFailed("Invalid tx hash length".into()));
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);
        Ok(B256::from(hash))
    }

    /// Get transaction receipt via eth_getTransactionReceipt
    ///
    /// Returns None if transaction is still pending.
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> Result<Option<TransactionReceipt>, RpcError> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionReceipt",
            "params": [format!("{:?}", tx_hash)],
            "id": 1,
        });

        let client = reqwest::Client::new();
        let response = client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(RpcError::Transport(error.to_string()));
        }

        let result = json.get("result");
        if result.is_none() || result == Some(&serde_json::Value::Null) {
            return Ok(None);
        }

        let result = result.unwrap();

        // Parse receipt fields
        let status = result
            .get("status")
            .and_then(|v| v.as_str())
            .map(|s| s == "0x1")
            .unwrap_or(false);

        let block_number = result
            .get("blockNumber")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());

        let gas_used = result
            .get("gasUsed")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);

        Ok(Some(TransactionReceipt {
            status,
            block_number,
            gas_used,
            tx_hash,
        }))
    }

    /// Wait for transaction confirmation
    ///
    /// Polls eth_getTransactionReceipt until the transaction is confirmed.
    /// Returns the receipt on success, or error on timeout/failure.
    pub async fn wait_for_confirmation(
        &self,
        tx_hash: B256,
        timeout_secs: u64,
    ) -> Result<TransactionReceipt, RpcError> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        loop {
            if start.elapsed() > timeout {
                return Err(RpcError::Transport(format!(
                    "Transaction confirmation timeout after {}s",
                    timeout_secs
                )));
            }

            match self.get_transaction_receipt(tx_hash).await? {
                Some(receipt) => return Ok(receipt),
                None => {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    }

    /// Fetch ERC20 token metadata (symbol, name, decimals)
    ///
    /// Returns default metadata if calls fail (non-standard tokens).
    pub async fn get_token_metadata(&self, token: Address) -> Result<TokenMetadata, RpcError> {
        use alloy_primitives::hex;

        // Zero address = native ETH
        if token.is_zero() {
            return Ok(TokenMetadata::eth());
        }

        // ERC20 function selectors
        // symbol(): 0x95d89b41
        // name(): 0x06fdde03
        // decimals(): 0x313ce567
        let symbol_selector = hex::decode("95d89b41").unwrap();
        let name_selector = hex::decode("06fdde03").unwrap();
        let decimals_selector = hex::decode("313ce567").unwrap();

        let symbol = self
            .eth_call(token, &symbol_selector)
            .await
            .ok()
            .and_then(|data| decode_string_or_bytes32(&data))
            .unwrap_or_else(|| "???".into());

        let name = self
            .eth_call(token, &name_selector)
            .await
            .ok()
            .and_then(|data| decode_string_or_bytes32(&data))
            .unwrap_or_else(|| "Unknown Token".into());

        let decimals = self
            .eth_call(token, &decimals_selector)
            .await
            .ok()
            .and_then(|data| {
                if data.len() >= 32 {
                    Some(data[31])
                } else {
                    None
                }
            })
            .unwrap_or(18);

        Ok(TokenMetadata {
            symbol,
            name,
            decimals,
            usd_price: None,
        })
    }

    /// Fetch USD price for a token via CoinGecko API (free, no API key)
    ///
    /// Returns None if price lookup fails (unknown token, rate limited, etc.)
    pub async fn get_token_price(&self, token: Address) -> Option<f64> {
        // CoinGecko uses Ethereum contract addresses for price lookup
        // API: /simple/token_price/ethereum?contract_addresses=...&vs_currencies=usd
        let url = format!(
            "https://api.coingecko.com/api/v3/simple/token_price/ethereum?contract_addresses={:?}&vs_currencies=usd",
            token
        );

        let client = reqwest::Client::new();
        let response = client.get(&url).send().await.ok()?;
        let json: serde_json::Value = response.json().await.ok()?;

        // Response format: { "0x...": { "usd": 1.23 } }
        let addr_key = format!("{:?}", token).to_lowercase();
        json.get(&addr_key)?.get("usd")?.as_f64()
    }

    /// Fetch token metadata with USD price
    pub async fn get_token_metadata_with_price(
        &self,
        token: Address,
    ) -> Result<TokenMetadata, RpcError> {
        let mut metadata = self.get_token_metadata(token).await?;
        metadata.usd_price = self.get_token_price(token).await;
        Ok(metadata)
    }

    /// Make an eth_call to a contract
    async fn eth_call(&self, to: Address, data: &[u8]) -> Result<Vec<u8>, RpcError> {
        use alloy_primitives::hex;

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{
                "to": format!("{:?}", to),
                "data": format!("0x{}", hex::encode(data)),
            }, "latest"],
            "id": 1,
        });

        let client = reqwest::Client::new();
        let response = client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(RpcError::Transport(error.to_string()));
        }

        let result = json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::Transport("No result in response".into()))?;

        hex::decode(result.trim_start_matches("0x"))
            .map_err(|e| RpcError::ParseFailed(format!("Invalid hex: {}", e)))
    }

    /// Fetch Shield events in a block range
    ///
    /// Note: Shield events are emitted by the Relay contract, not SmartWallet
    pub async fn fetch_shield_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<ParsedShieldEvent>, RpcError> {
        let logs = self
            .fetch_logs(
                Shield::SIGNATURE_HASH,
                self.addresses.relay,
                from_block,
                to_block,
            )
            .await?;

        logs.into_iter()
            .map(|log| self.parse_shield_log(&log))
            .collect()
    }

    /// Fetch Transact events in a block range
    ///
    /// Note: Transact events are emitted by the Relay contract, not SmartWallet
    pub async fn fetch_transact_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<ParsedTransactEvent>, RpcError> {
        let logs = self
            .fetch_logs(
                Transact::SIGNATURE_HASH,
                self.addresses.relay,
                from_block,
                to_block,
            )
            .await?;

        logs.into_iter()
            .map(|log| self.parse_transact_log(&log))
            .collect()
    }

    /// Fetch Nullifier events in a block range
    pub async fn fetch_nullifier_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<ParsedNullifierEvent>, RpcError> {
        let logs = self
            .fetch_logs(
                Nullifiers::SIGNATURE_HASH,
                self.addresses.smart_wallet,
                from_block,
                to_block,
            )
            .await?;

        logs.into_iter()
            .map(|log| self.parse_nullifier_log(&log))
            .collect()
    }

    /// Fetch all Railgun events in a block range
    pub async fn fetch_all_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<RailgunEvent>, RpcError> {
        let (shields, transacts, nullifiers) = tokio::try_join!(
            self.fetch_shield_events(from_block, to_block),
            self.fetch_transact_events(from_block, to_block),
            self.fetch_nullifier_events(from_block, to_block),
        )?;

        let mut events: Vec<RailgunEvent> =
            Vec::with_capacity(shields.len() + transacts.len() + nullifiers.len());

        events.extend(shields.into_iter().map(RailgunEvent::Shield));
        events.extend(transacts.into_iter().map(RailgunEvent::Transact));
        events.extend(nullifiers.into_iter().map(RailgunEvent::Nullifier));

        // Sort by block number
        events.sort_by_key(|e| match e {
            RailgunEvent::Shield(s) => s.block_number,
            RailgunEvent::Transact(t) => t.block_number,
            RailgunEvent::Nullifier(n) => n.block_number,
        });

        Ok(events)
    }

    /// Internal: fetch logs via HTTP RPC
    async fn fetch_logs(
        &self,
        event_signature: B256,
        contract: Address,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Log>, RpcError> {
        let filter = serde_json::json!({
            "address": format!("{:?}", contract),
            "topics": [format!("{:?}", event_signature)],
            "fromBlock": format!("0x{:x}", from_block),
            "toBlock": format!("0x{:x}", to_block),
        });

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getLogs",
            "params": [filter],
            "id": 1,
        });

        let client = reqwest::Client::new();
        let response = client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(RpcError::Transport(error.to_string()));
        }

        let result = json
            .get("result")
            .ok_or_else(|| RpcError::Transport("No result in response".into()))?;

        let logs: Vec<Log> = serde_json::from_value(result.clone())
            .map_err(|e| RpcError::ParseFailed(e.to_string()))?;

        Ok(logs)
    }

    /// Parse Shield log to event
    ///
    /// The Shield event includes preimages (npk, token, value), not the commitments directly.
    /// We compute commitment = Poseidon(npk, tokenField, value) from each preimage.
    fn parse_shield_log(&self, log: &Log) -> Result<ParsedShieldEvent, RpcError> {
        let decoded = Shield::decode_log_data(&log.data())
            .map_err(|e| RpcError::ParseFailed(e.to_string()))?;

        let mut commitments = Vec::with_capacity(decoded.preimages.len());
        let mut preimages = Vec::with_capacity(decoded.preimages.len());

        for preimage in &decoded.preimages {
            let npk = Field::from_be_bytes_mod_order(preimage.npk.as_slice());

            let token_field = if preimage.token.tokenType == 0 {
                let mut bytes = [0u8; 32];
                bytes[12..32].copy_from_slice(preimage.token.tokenAddress.as_slice());
                Field::from_be_bytes_mod_order(&bytes)
            } else {
                use sha3::{Digest, Keccak256};
                let mut data = [0u8; 96];
                data[31] = preimage.token.tokenType;
                data[44..64].copy_from_slice(preimage.token.tokenAddress.as_slice());
                data[64..96].copy_from_slice(&preimage.token.tokenSubID.to_be_bytes::<32>());
                let hash = Keccak256::digest(&data);
                Field::from_be_bytes_mod_order(&hash)
            };

            let value = preimage.value.to::<u128>();
            let commitment = crate::poseidon::poseidon3(npk, token_field, Field::from(value));

            commitments.push(commitment);
            preimages.push(ParsedShieldPreimage {
                npk,
                token: token_field,
                token_address: preimage.token.tokenAddress,
                value,
            });
        }

        let ciphertexts: Vec<ParsedShieldCiphertext> = decoded
            .ciphertexts
            .iter()
            .map(|c| {
                let mut encrypted_bundle = [[0u8; 32]; 3];
                for (i, chunk) in c.encryptedBundle.iter().take(3).enumerate() {
                    encrypted_bundle[i].copy_from_slice(chunk.as_slice());
                }
                let mut shield_key = [0u8; 32];
                shield_key.copy_from_slice(c.shieldKey.as_slice());

                ParsedShieldCiphertext {
                    encrypted_bundle,
                    shield_key,
                }
            })
            .collect();

        Ok(ParsedShieldEvent {
            tree_number: decoded.treeNumber.try_into().unwrap_or(0),
            start_position: decoded.startPosition.try_into().unwrap_or(0),
            commitments,
            ciphertexts,
            preimages,
            block_number: log.block_number.unwrap_or(0),
            tx_hash: log.transaction_hash.unwrap_or_default(),
        })
    }

    /// Parse Transact log to event
    fn parse_transact_log(&self, log: &Log) -> Result<ParsedTransactEvent, RpcError> {
        let decoded = Transact::decode_log_data(&log.data())
            .map_err(|e| RpcError::ParseFailed(e.to_string()))?;

        let commitment_hashes: Vec<Field> = decoded
            .hash
            .iter()
            .map(|h| Field::from_be_bytes_mod_order(h.as_slice()))
            .collect();

        let ciphertexts: Vec<Vec<u8>> = decoded
            .ciphertext
            .iter()
            .map(|c| {
                let mut bytes = Vec::new();
                for chunk in &c.ciphertext {
                    bytes.extend_from_slice(chunk.as_slice());
                }
                bytes.extend_from_slice(c.ephemeralKey.as_slice());
                bytes.extend_from_slice(c.blindedSenderViewingKey.as_slice());
                bytes.extend_from_slice(&c.annotationData);
                bytes.extend_from_slice(&c.memo);
                bytes
            })
            .collect();

        Ok(ParsedTransactEvent {
            tree_number: decoded.treeNumber.try_into().unwrap_or(0),
            start_position: decoded.startPosition.try_into().unwrap_or(0),
            commitment_hashes,
            ciphertexts,
            block_number: log.block_number.unwrap_or(0),
            tx_hash: log.transaction_hash.unwrap_or_default(),
        })
    }

    /// Parse Nullifier log to event
    fn parse_nullifier_log(&self, log: &Log) -> Result<ParsedNullifierEvent, RpcError> {
        let decoded = Nullifiers::decode_log_data(&log.data())
            .map_err(|e| RpcError::ParseFailed(e.to_string()))?;

        let nullifiers: Vec<Field> = decoded
            .nullifiers
            .iter()
            .map(|n| Field::from_be_bytes_mod_order(n.as_slice()))
            .collect();

        Ok(ParsedNullifierEvent {
            tree_number: decoded.treeNumber.try_into().unwrap_or(0),
            nullifiers,
            block_number: log.block_number.unwrap_or(0),
            tx_hash: log.transaction_hash.unwrap_or_default(),
        })
    }
}

/// Sync state from on-chain events
pub struct EventSyncer {
    /// RPC client
    pub client: RailgunRpcClient,
    /// Last synced block
    pub last_block: u64,
    /// Batch size for fetching
    pub batch_size: u64,
}

impl EventSyncer {
    pub fn new(client: RailgunRpcClient, start_block: u64) -> Self {
        Self {
            client,
            last_block: start_block,
            batch_size: 10_000,
        }
    }

    /// Sync events up to the specified block
    pub async fn sync_to(&mut self, target_block: u64) -> Result<Vec<RailgunEvent>, RpcError> {
        let mut all_events = Vec::new();
        let mut current = self.last_block;

        while current < target_block {
            let end = (current + self.batch_size).min(target_block);
            tracing::info!("Syncing blocks {} to {}", current, end);

            let events = self.client.fetch_all_events(current, end).await?;
            all_events.extend(events);
            current = end + 1;
        }

        self.last_block = target_block;
        Ok(all_events)
    }

    /// Get current synced block
    pub fn synced_block(&self) -> u64 {
        self.last_block
    }

    /// Sync to the latest block
    pub async fn sync_to_latest(&mut self) -> Result<Vec<RailgunEvent>, RpcError> {
        let latest_block = self.client.get_block_number().await?;
        self.sync_to(latest_block).await
    }

    /// Sync events and build merkle tree for a specific tree number
    ///
    /// Returns the merkle tree with all commitments inserted in order.
    /// The tree can be used to generate proofs that will verify on-chain.
    pub async fn sync_merkle_tree(
        &mut self,
        target_block: u64,
        tree_number: u64,
        tree_depth: usize,
    ) -> Result<crate::notes::NoteMerkleTree, RpcError> {
        let events = self.sync_to(target_block).await?;

        let mut tree = crate::notes::NoteMerkleTree::new(tree_depth)
            .map_err(|e| RpcError::MerkleTreeError(e.to_string()))?;

        // Collect all commitments with their positions
        let mut commitments_with_pos: Vec<(u64, Field)> = Vec::new();

        for event in events {
            match event {
                RailgunEvent::Shield(shield) => {
                    if shield.tree_number == tree_number {
                        for (i, commitment) in shield.commitments.iter().enumerate() {
                            let pos = shield.start_position + i as u64;
                            commitments_with_pos.push((pos, *commitment));
                        }
                    }
                }
                RailgunEvent::Transact(transact) => {
                    if transact.tree_number == tree_number {
                        for (i, commitment) in transact.commitment_hashes.iter().enumerate() {
                            let pos = transact.start_position + i as u64;
                            commitments_with_pos.push((pos, *commitment));
                        }
                    }
                }
                RailgunEvent::Nullifier(_) => {
                    // Nullifiers don't add to the tree
                }
            }
        }

        // Sort by position (should already be sorted by block, but positions might interleave)
        commitments_with_pos.sort_by_key(|(pos, _)| *pos);

        // Verify positions are contiguous and insert
        for (expected_idx, (pos, commitment)) in commitments_with_pos.iter().enumerate() {
            if *pos != expected_idx as u64 {
                tracing::warn!(
                    "Gap in commitments: expected index {}, got position {}",
                    expected_idx,
                    pos
                );
            }
            tree.insert(*commitment)
                .map_err(|e| RpcError::MerkleTreeError(e.to_string()))?;
        }

        tracing::info!("Built merkle tree with {} leaves", tree.leaves.len());

        Ok(tree)
    }
}

#[allow(dead_code)]
fn field_to_bytes(f: &Field) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    let be_bytes = f.into_bigint().to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
    bytes
}

fn decode_string_or_bytes32(data: &[u8]) -> Option<String> {
    if data.len() < 32 {
        return None;
    }

    // Check if it's an ABI-encoded dynamic string
    // First 32 bytes are the offset (usually 0x20 = 32)
    // Next 32 bytes are the length
    // Following bytes are the string data
    if data.len() >= 64 {
        let offset = u64::from_be_bytes(data[24..32].try_into().ok()?);
        if offset == 32 && data.len() >= 96 {
            let length = u64::from_be_bytes(data[56..64].try_into().ok()?) as usize;
            if length <= data.len() - 64 {
                let s = String::from_utf8_lossy(&data[64..64 + length]);
                let trimmed = s.trim_end_matches('\0').to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }
    }

    // Fallback: treat as bytes32 (e.g., MKR uses this)
    let s = String::from_utf8_lossy(&data[..32]);
    let trimmed = s.trim_end_matches('\0').to_string();
    if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return Some(trimmed);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_client_creation() {
        let client = RailgunRpcClient::new("https://eth.llamarpc.com", 1);
        assert!(client.is_ok());

        let client = RailgunRpcClient::new("https://example.com", 99999);
        assert!(client.is_err());
    }

    #[test]
    fn test_event_syncer_creation() {
        let client = RailgunRpcClient::new("https://eth.llamarpc.com", 1).unwrap();
        let syncer = EventSyncer::new(client, 18_000_000);
        assert_eq!(syncer.synced_block(), 18_000_000);
    }

    #[test]
    fn test_token_metadata_eth() {
        let meta = TokenMetadata::eth();
        assert_eq!(meta.symbol, "ETH");
        assert_eq!(meta.decimals, 18);
        assert!(meta.usd_price.is_none());
    }

    #[test]
    fn test_token_metadata_format_balance() {
        let meta = TokenMetadata {
            symbol: "USDC".into(),
            name: "USD Coin".into(),
            decimals: 6,
            usd_price: Some(1.0),
        };

        // 1.5 USDC = 1_500_000 raw
        let raw = alloy_primitives::U256::from(1_500_000u64);
        assert_eq!(meta.format_balance(raw), "1.5");

        // 1 USDC exactly
        let raw = alloy_primitives::U256::from(1_000_000u64);
        assert_eq!(meta.format_balance(raw), "1");

        // 0.000001 USDC
        let raw = alloy_primitives::U256::from(1u64);
        assert_eq!(meta.format_balance(raw), "0.000001");
    }

    #[test]
    fn test_token_metadata_usd_value() {
        let meta = TokenMetadata {
            symbol: "ETH".into(),
            name: "Ether".into(),
            decimals: 18,
            usd_price: Some(2000.0),
        };

        // 1 ETH = 2000 USD
        let one_eth = alloy_primitives::U256::from(1_000_000_000_000_000_000u128);
        let usd = meta.usd_value(one_eth).unwrap();
        assert!((usd - 2000.0).abs() < 0.01);
    }

    #[test]
    fn test_decode_string_or_bytes32_abi() {
        // ABI-encoded "USDC" string
        // offset (32) + length (4) + "USDC" padded
        let mut data = vec![0u8; 96];
        data[31] = 32; // offset = 32
        data[63] = 4; // length = 4
        data[64..68].copy_from_slice(b"USDC");

        let result = decode_string_or_bytes32(&data);
        assert_eq!(result, Some("USDC".into()));
    }

    #[test]
    fn test_decode_string_or_bytes32_bytes32() {
        // bytes32 "MKR\0\0\0..." (like MakerDAO uses)
        let mut data = [0u8; 32];
        data[0..3].copy_from_slice(b"MKR");

        let result = decode_string_or_bytes32(&data);
        assert_eq!(result, Some("MKR".into()));
    }
}
