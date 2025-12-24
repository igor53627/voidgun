# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **voidgun-proxy crate**: RPC proxy server for privacy-via-proxy (closes #46)
  - New crate `crates/voidgun-proxy` implementing Nullmask-style privacy via proxy
  - JSON-RPC server with axum for HTTP and WebSocket connections
  - User context management with SQLite persistence (survives restarts)
  - Key derivation from wallet signature (RAILGUN_DOMAIN_MESSAGE)
  - Custom methods for explicit privacy operations:
    - `voidgun_init` - Initialize privacy wallet with signature
    - `voidgun_shieldedBalance` - Get shielded balance for a token
    - `voidgun_allBalances` - Get all shielded balances
    - `voidgun_sync` - Sync wallet state from chain events
    - `voidgun_unshield` - Withdraw tokens to public address
    - `voidgun_address` - Get 0zk receiving address
  - Standard Ethereum method interception:
    - `eth_getBalance` returns shielded balance for initialized wallets
    - `eth_sendTransaction` intercepts simple transfers as unshield operations
    - `personal_sign` triggers key derivation when signing domain message
  - Binary `voidgun-proxy` with CLI for running standalone server
- `RailgunLane::for_chain()` convenience constructor with default paths and chain-specific addresses
- WebSocket event streaming for real-time updates (closes #45)
  - New `ws` module with `RailgunWsClient` for WebSocket connections
  - `EventSubscription` stream type for receiving `RawLogEvent` as they arrive
  - `EventFilter` enum to subscribe to Shield, Transact, Nullifier, or All events
  - `RailgunWsClient::subscribe()` - subscribe to Railgun events via `eth_subscribe`
  - `RailgunWsClient::subscribe_with_reconnect()` - auto-reconnect on connection drop
  - `RailgunLane::subscribe_events()` - convenience method using RPC URL
  - `RailgunLane::subscribe_events_with_reconnect()` - with automatic reconnection
  - Helper `RailgunWsClient::http_to_ws()` converts HTTP URLs to WebSocket URLs
- Multi-token balance tracking with metadata (closes #44)
  - `TokenMetadata` struct with symbol, name, decimals, and optional USD price
  - `TokenMetadataCache` for caching token metadata to avoid repeated RPC calls
  - `RailgunRpcClient::get_token_metadata()` fetches ERC20 metadata via eth_call
  - `RailgunRpcClient::get_token_price()` fetches USD price via CoinGecko API
  - `RailgunRpcClient::get_token_metadata_with_price()` combines both
  - `PoolBalance` enhanced with metadata, formatted balance, and USD value display
  - `RailgunLane::get_token_metadata()` with caching
  - `RailgunLane::refresh_token_metadata()` fetches metadata for all owned tokens
  - `RailgunLane::get_all_balances_with_metadata()` returns balances with metadata
  - `RailgunLane::get_all_balances_with_prices()` includes USD pricing
  - Helper `decode_string_or_bytes32()` handles non-standard tokens like MKR
- Complete event parsing for mainnet sync (closes #41)
  - `EventScanner::parse_shield_event()` now fully parses Shield events using ABI decoding
  - `EventScanner::parse_nullifier_event()` now fully parses Nullifier events
  - Computes commitments from preimages: `Poseidon(npk, tokenField, value)`
  - Supports ERC20 and ERC721/ERC1155 token types
- 0zk address parsing in transfer flow
  - `RailgunLane::transfer()` now accepts 0zk addresses (e.g., `0zk1...`) in addition to hex addresses
  - Extracts recipient's master public key and viewing public key from Bech32m-encoded address
  - Output notes are encrypted with recipient's viewing public key
- Gas estimation for transactions (closes #36)
  - `RailgunRpcClient::get_gas_price()` fetches current gas price via `eth_gasPrice`
  - `RailgunRpcClient::estimate_gas()` estimates gas for arbitrary calldata
  - `RailgunLane::estimate_shield_gas()` estimates shield transaction costs
  - `RailgunLane::estimate_transfer_gas()` estimates private transfer costs (~450k gas)
  - `RailgunLane::estimate_unshield_gas()` estimates unshield/withdraw costs
  - New `GasEstimate` struct with gas units, gas price, and total cost in wei
- JIT circuit artifact downloading (closes #34)
  - `ArtifactStore::get_artifacts()` auto-downloads missing artifacts from IPFS
  - `ArtifactStore::download_variant()` for explicit pre-downloading
  - Progress callbacks for UI integration via `DownloadProgress`
- Sepolia testnet integration tests (closes #32)
  - `sepolia_integration.rs` test suite for Sepolia Railgun contracts
  - Tests for event syncing, gas estimation, wallet addresses, and proof generation
  - Contract addresses: Proxy 0x942D5026b421cf2705363A525897576cFAdA5964, Delegator 0x464a0c9e62534b3b160c35638DD7d5cf761f429e
- On-chain transaction submission (closes #42)
  - New `tx` module with EIP-1559 transaction building and signing
  - `RailgunLane::submit_shield()` - shield tokens into Railgun pool
  - `RailgunLane::submit_transact()` - submit private transfer with proof
  - `RailgunLane::submit_unshield()` - withdraw tokens from pool
  - `RailgunLane::wait_for_confirmation()` - poll for tx confirmation
  - `RailgunRpcClient` additions: `get_transaction_count()`, `get_max_priority_fee()`, `send_raw_transaction()`, `get_transaction_receipt()`, `wait_for_confirmation()`
  - New types: `Eip1559Tx`, `SubmitResult`, `TransactionReceipt`

### Security
- **VULN-001/002**: `NoteMerkleTree::new()` now validates depth <= 16 and returns `Result`
- **VULN-001/002**: `NoteMerkleTree::insert()` now checks capacity and returns `Result` to prevent panics
- **VULN-003**: Added `validate_transact_witness()` to validate Merkle proof shapes before circuit invocation
- **VULN-004**: Witness padding now only allows diff of 1; larger mismatches return explicit errors

### Changed
- Updated documentation and added protocol visualization
- `NoteMerkleTree::new()` and `insert()` now return `Result` types (breaking API change)

## [0.2.0] - 2024-12-19

### Changed
- **Major refactor**: Removed original Voidgun pool, now using Railgun protocol exclusively

### Removed
- **voidgun-core**: Original Voidgun pool core types (replaced by railgun-lane)
- **voidgun-prover**: Noir/Barretenberg proving stack (replaced by ark-circom + Railgun artifacts)
- **voidgun-contracts**: VoidgunPool Rust bindings (railgun-lane has own contract types)
- **reth-plugin**: Reth ExEx integration (removed - now standalone proxy)
- **circuits/**: Noir circuit sources for original Voidgun pool
- **circuits-bin/**: Compiled Noir artifacts
- **contracts/**: VoidgunPool Solidity contracts and verifiers

### Security
- Upgraded `aes-gcm` to 0.10.3 to fix CVE-2023-42811
- Fixed nullifier computation to use `joinsplit_nullifier(nk, leafIndex)` formula
- Added explicit error handling in G1/G2 point parsing (fail-fast on malformed data)

### Improved
- Streaming downloads with incremental progress reporting for large circuit artifacts

### Added
- `railgun-lane` crate: Complete Railgun protocol implementation
  - EdDSA signature generation compatible with circomlib's Poseidon-based EdDSA
  - Baby Jubjub curve operations with arkworks <-> circomlib coordinate transformation
  - Groth16 proof generation using ark-circom with Railgun's trusted setup
  - Merkle tree syncing from on-chain Shield/Transact events
  - Trial decryption for Shield events (AES-GCM) and Transact events (ChaCha20-Poly1305)
  - Circuit artifact management with IPFS download and caching
  - End-to-end proof verification using VKEY JSON artifacts

### Fixed
- **EdDSA signature verification**: Fixed critical bug where `BabyJubjubScalar::from_le_bytes_mod_order()` 
  was reducing the pruned secret scalar modulo the Baby Jubjub scalar field order
  - Changed `SpendingKey.secret` to raw bytes to preserve the full 256-bit pruned value
  - Signature arithmetic now uses `BigUint` for `S = r + hm * s (mod subOrder)`
  - Public key derivation uses `BigUint` bit-shifting before converting to scalar
