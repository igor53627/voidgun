//! WebSocket client for real-time Ethereum event streaming
//!
//! This module provides WebSocket-based event subscription using `eth_subscribe`.

use alloy_primitives::{Address, B256};
use futures_util::{SinkExt, StreamExt};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::contracts::{Nullifiers, RailgunAddresses, Shield, Transact};

#[derive(Debug, Error)]
pub enum WsError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Subscription failed: {0}")]
    SubscriptionFailed(String),

    #[error("Message parse error: {0}")]
    ParseError(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Invalid WebSocket URL")]
    InvalidUrl,

    #[error("Chain not supported")]
    UnsupportedChain,
}

/// Event types to subscribe to
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventFilter {
    /// Shield events only
    Shield,
    /// Transact events only
    Transact,
    /// Nullifier events only
    Nullifier,
    /// All Railgun events
    All,
}

/// Raw log event from WebSocket subscription
#[derive(Clone, Debug)]
pub struct RawLogEvent {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
    pub block_number: u64,
    pub transaction_hash: B256,
    pub log_index: u64,
}

/// Subscription handle for managing the WebSocket connection
pub struct EventSubscription {
    /// Receiver for incoming events
    pub receiver: mpsc::UnboundedReceiver<Result<RawLogEvent, WsError>>,
    /// Handle to stop the subscription
    cancel_tx: mpsc::Sender<()>,
}

impl EventSubscription {
    /// Stop the subscription and close the WebSocket connection
    pub async fn unsubscribe(self) {
        let _ = self.cancel_tx.send(()).await;
    }

    /// Get the next event (async)
    pub async fn next(&mut self) -> Option<Result<RawLogEvent, WsError>> {
        self.receiver.recv().await
    }
}

/// WebSocket client for Ethereum event streaming
pub struct RailgunWsClient {
    /// WebSocket URL (wss://...)
    ws_url: String,
    /// Contract addresses for the chain
    addresses: RailgunAddresses,
    /// Chain ID
    chain_id: u64,
}

impl RailgunWsClient {
    /// Create a new WebSocket client
    ///
    /// The URL should be a WebSocket endpoint (wss://... or ws://...)
    pub fn new(ws_url: impl Into<String>, chain_id: u64) -> Result<Self, WsError> {
        let addresses = RailgunAddresses::for_chain(chain_id).ok_or(WsError::UnsupportedChain)?;

        let ws_url = ws_url.into();
        if !ws_url.starts_with("ws://") && !ws_url.starts_with("wss://") {
            return Err(WsError::InvalidUrl);
        }

        Ok(Self {
            ws_url,
            addresses,
            chain_id,
        })
    }

    /// Convert HTTP URL to WebSocket URL
    pub fn http_to_ws(http_url: &str) -> String {
        if http_url.starts_with("https://") {
            http_url.replacen("https://", "wss://", 1)
        } else if http_url.starts_with("http://") {
            http_url.replacen("http://", "ws://", 1)
        } else {
            http_url.to_string()
        }
    }

    /// Get the contract addresses
    pub fn addresses(&self) -> &RailgunAddresses {
        &self.addresses
    }

    /// Subscribe to Railgun events
    ///
    /// Returns an EventSubscription that yields RawLogEvent as they arrive.
    pub async fn subscribe(&self, filter: EventFilter) -> Result<EventSubscription, WsError> {
        use alloy_sol_types::SolEvent;

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);

        let ws_url = self.ws_url.clone();
        let relay_addr = self.addresses.relay;
        let smart_wallet_addr = self.addresses.smart_wallet;

        // Build topic filters based on event type
        let subscriptions = match filter {
            EventFilter::Shield => vec![(relay_addr, Shield::SIGNATURE_HASH)],
            EventFilter::Transact => vec![(relay_addr, Transact::SIGNATURE_HASH)],
            EventFilter::Nullifier => vec![(smart_wallet_addr, Nullifiers::SIGNATURE_HASH)],
            EventFilter::All => vec![
                (relay_addr, Shield::SIGNATURE_HASH),
                (relay_addr, Transact::SIGNATURE_HASH),
                (smart_wallet_addr, Nullifiers::SIGNATURE_HASH),
            ],
        };

        let event_tx_clone = event_tx.clone();

        tokio::spawn(async move {
            if let Err(e) =
                run_subscription(ws_url, subscriptions, event_tx_clone, &mut cancel_rx).await
            {
                tracing::error!("WebSocket subscription error: {}", e);
            }
        });

        Ok(EventSubscription {
            receiver: event_rx,
            cancel_tx,
        })
    }

    /// Subscribe with automatic reconnection
    ///
    /// If the connection drops, it will attempt to reconnect after the specified delay.
    pub async fn subscribe_with_reconnect(
        &self,
        filter: EventFilter,
        reconnect_delay_ms: u64,
    ) -> Result<EventSubscription, WsError> {
        use alloy_sol_types::SolEvent;

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);

        let ws_url = self.ws_url.clone();
        let relay_addr = self.addresses.relay;
        let smart_wallet_addr = self.addresses.smart_wallet;

        let subscriptions = match filter {
            EventFilter::Shield => vec![(relay_addr, Shield::SIGNATURE_HASH)],
            EventFilter::Transact => vec![(relay_addr, Transact::SIGNATURE_HASH)],
            EventFilter::Nullifier => vec![(smart_wallet_addr, Nullifiers::SIGNATURE_HASH)],
            EventFilter::All => vec![
                (relay_addr, Shield::SIGNATURE_HASH),
                (relay_addr, Transact::SIGNATURE_HASH),
                (smart_wallet_addr, Nullifiers::SIGNATURE_HASH),
            ],
        };

        let event_tx_clone = event_tx.clone();

        tokio::spawn(async move {
            loop {
                match run_subscription(
                    ws_url.clone(),
                    subscriptions.clone(),
                    event_tx_clone.clone(),
                    &mut cancel_rx,
                )
                .await
                {
                    Ok(()) => break, // Cancelled normally
                    Err(e) => {
                        tracing::warn!(
                            "WebSocket disconnected: {}. Reconnecting in {}ms...",
                            e,
                            reconnect_delay_ms
                        );

                        // Check if we should cancel before reconnecting
                        tokio::select! {
                            _ = cancel_rx.recv() => break,
                            _ = tokio::time::sleep(std::time::Duration::from_millis(reconnect_delay_ms)) => {}
                        }
                    }
                }
            }
        });

        Ok(EventSubscription {
            receiver: event_rx,
            cancel_tx,
        })
    }
}

/// Run the WebSocket subscription loop
async fn run_subscription(
    ws_url: String,
    subscriptions: Vec<(Address, B256)>,
    event_tx: mpsc::UnboundedSender<Result<RawLogEvent, WsError>>,
    cancel_rx: &mut mpsc::Receiver<()>,
) -> Result<(), WsError> {
    let (ws_stream, _) = connect_async(&ws_url)
        .await
        .map_err(|e| WsError::ConnectionFailed(e.to_string()))?;

    let (mut write, mut read) = ws_stream.split();

    // Subscribe to logs for each (address, topic) pair
    let mut subscription_ids: Vec<String> = Vec::new();

    for (i, (address, topic)) in subscriptions.iter().enumerate() {
        let subscribe_msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": i + 1,
            "method": "eth_subscribe",
            "params": [
                "logs",
                {
                    "address": format!("{:?}", address),
                    "topics": [format!("{:?}", topic)]
                }
            ]
        });

        write
            .send(Message::Text(subscribe_msg.to_string().into()))
            .await
            .map_err(|e| WsError::SubscriptionFailed(e.to_string()))?;
    }

    // Read subscription confirmations
    for _ in 0..subscriptions.len() {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
                                subscription_ids.push(result.to_string());
                                tracing::debug!("Subscribed with ID: {}", result);
                            } else if let Some(error) = json.get("error") {
                                return Err(WsError::SubscriptionFailed(error.to_string()));
                            }
                        }
                    }
                    Some(Err(e)) => return Err(WsError::ConnectionFailed(e.to_string())),
                    None => return Err(WsError::ConnectionClosed),
                    _ => {}
                }
            }
            _ = cancel_rx.recv() => {
                return Ok(());
            }
        }
    }

    tracing::info!(
        "WebSocket subscribed to {} event types",
        subscription_ids.len()
    );

    // Main event loop
    loop {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                            // Check if this is a subscription notification
                            if json.get("method").and_then(|m| m.as_str()) == Some("eth_subscription") {
                                if let Some(params) = json.get("params") {
                                    if let Some(result) = params.get("result") {
                                        match parse_log_event(result) {
                                            Ok(event) => {
                                                if event_tx.send(Ok(event)).is_err() {
                                                    return Ok(()); // Receiver dropped
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!("Failed to parse log: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = write.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) => {
                        return Err(WsError::ConnectionClosed);
                    }
                    Some(Err(e)) => {
                        return Err(WsError::ConnectionFailed(e.to_string()));
                    }
                    None => {
                        return Err(WsError::ConnectionClosed);
                    }
                    _ => {}
                }
            }
            _ = cancel_rx.recv() => {
                // Send unsubscribe messages
                for (i, sub_id) in subscription_ids.iter().enumerate() {
                    let unsub_msg = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 100 + i,
                        "method": "eth_unsubscribe",
                        "params": [sub_id]
                    });
                    let _ = write.send(Message::Text(unsub_msg.to_string().into())).await;
                }
                return Ok(());
            }
        }
    }
}

/// Parse a JSON log object into RawLogEvent
fn parse_log_event(json: &serde_json::Value) -> Result<RawLogEvent, WsError> {
    use alloy_primitives::hex;

    let address_str = json
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WsError::ParseError("Missing address".into()))?;

    let address: Address = address_str
        .parse()
        .map_err(|e| WsError::ParseError(format!("Invalid address: {}", e)))?;

    let topics: Vec<B256> = json
        .get("topics")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.as_str())
                .filter_map(|s| s.parse().ok())
                .collect()
        })
        .unwrap_or_default();

    let data_str = json.get("data").and_then(|v| v.as_str()).unwrap_or("0x");

    let data = hex::decode(data_str.trim_start_matches("0x"))
        .map_err(|e| WsError::ParseError(format!("Invalid data: {}", e)))?;

    let block_number = json
        .get("blockNumber")
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);

    let tx_hash_str = json
        .get("transactionHash")
        .and_then(|v| v.as_str())
        .unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");

    let transaction_hash: B256 = tx_hash_str.parse().unwrap_or_default();

    let log_index = json
        .get("logIndex")
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);

    Ok(RawLogEvent {
        address,
        topics,
        data,
        block_number,
        transaction_hash,
        log_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_client_creation() {
        let client = RailgunWsClient::new("wss://eth-mainnet.ws.alchemyapi.io", 1);
        assert!(client.is_ok());

        let client = RailgunWsClient::new("https://eth.llamarpc.com", 1);
        assert!(client.is_err()); // Not a WebSocket URL
    }

    #[test]
    fn test_http_to_ws_conversion() {
        assert_eq!(
            RailgunWsClient::http_to_ws("https://eth.llamarpc.com"),
            "wss://eth.llamarpc.com"
        );
        assert_eq!(
            RailgunWsClient::http_to_ws("http://localhost:8545"),
            "ws://localhost:8545"
        );
    }

    #[test]
    fn test_parse_log_event() {
        let json = serde_json::json!({
            "address": "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9",
            "topics": [
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ],
            "data": "0x1234",
            "blockNumber": "0x1234",
            "transactionHash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "logIndex": "0x1"
        });

        let event = parse_log_event(&json).unwrap();
        assert_eq!(event.block_number, 0x1234);
        assert_eq!(event.log_index, 1);
        assert_eq!(event.data, vec![0x12, 0x34]);
    }
}
