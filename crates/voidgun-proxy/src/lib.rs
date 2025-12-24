//! Voidgun RPC Proxy Server
//!
//! Privacy-via-proxy implementation based on the Nullmask research paper.
//! This server acts as an Ethereum JSON-RPC endpoint that wallets connect to,
//! intercepting transactions to route them through the Railgun privacy pool.
//!
//! # Architecture
//!
//! ```text
//! Wallet (MetaMask, Rainbow, etc.)
//!    |
//!    | JSON-RPC / WebSocket
//!    v
//! +------------------+
//! | Voidgun Proxy    |
//! |------------------|
//! | - Session mgmt   |  <-- UserContext per (chain_id, address)
//! | - Balance query  |  <-- Shielded balance from synced notes
//! | - Tx intercept   |  <-- Shield/Transfer/Unshield via Railgun
//! | - Key derivation |  <-- From wallet signature
//! +------------------+
//!    |
//!    | Uses railgun-lane for:
//!    | - Proof generation
//!    | - Event syncing
//!    | - Tx submission
//!    v
//! +------------------+
//! | Upstream RPC     |  <-- Ethereum node (Infura, Alchemy, etc.)
//! +------------------+
//! ```
//!
//! # User Flow
//!
//! 1. User adds "Voidgun" network to wallet (custom RPC URL pointing here)
//! 2. Proxy prompts for signature to derive viewing key (RAILGUN_DOMAIN_MESSAGE)
//! 3. Proxy syncs shielded balance from on-chain events
//! 4. User sends tx normally, proxy intercepts and shields via Railgun
//! 5. Wallet shows shielded balance

pub mod context;
pub mod db;
pub mod error;
pub mod jsonrpc;
pub mod methods;
pub mod proxy;
pub mod server;

pub use context::{UserContext, UserContextStore};
pub use db::Database;
pub use error::{ProxyError, ProxyResult};
pub use jsonrpc::{JsonRpcRequest, JsonRpcResponse};
pub use proxy::RpcProxy;
pub use server::Server;

// Some native dependencies (e.g., wasmer) expect the standard stack probe
// symbol to be available during linking. Provide a lightweight definition to
// avoid toolchain-specific linker errors in test builds.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[no_mangle]
pub extern "C" fn __rust_probestack() {}
