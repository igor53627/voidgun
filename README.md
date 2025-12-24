# voidgun

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/igor53627/voidgun)
[![Demo App](https://img.shields.io/badge/Demo-App-84cc16)](https://igor53627.github.io/voidgun/)
[![Visualization](https://img.shields.io/badge/Protocol-Visualization-6366f1)](https://igor53627.github.io/voidgun/protocol-visualization.html)

Privacy-via-proxy architecture for Ethereum using Railgun protocol integration.

## Overview

Voidgun provides privacy pool access through a proxy model where:
- Your wallet retains full spending authority via wallet signatures
- The proxy derives deterministic keys from your wallet signature
- All privacy operations use Railgun's battle-tested Groth16 circuits
- Shield/unshield through existing Railgun contracts on mainnet

## Architecture

```
┌─────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   Wallet    │────▶│   Voidgun Proxy      │────▶│  Railgun Pool   │
│  (signs)    │     │   (key derivation)   │     │  (L1 contracts) │
└─────────────┘     └──────────────────────┘     └─────────────────┘
       │                      │
       │ Signs domain         │ Derives EdDSA keys
       │ message              │ from signature
       │                      │
       ▼                      ▼
  ECDSA signature       ┌──────────────────┐
  for key derivation    │ Baby Jubjub Keys │
                        │ - Spending key   │
                        │ - Viewing key    │
                        │ - Nullifying key │
                        └──────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │ Groth16 Proofs   │
                        │ via ark-circom   │
                        └──────────────────┘
```

## How It Works

### 1. Key Derivation (one-time)
1. Sign a domain-specific message with your wallet
2. Derive 128-bit entropy from signature hash
3. Generate BIP39 mnemonic → BIP32 Baby Jubjub keys
4. Keys enable Railgun protocol operations

### 2. Shield Funds
1. Deposit ETH/tokens to Railgun contracts
2. Your balance becomes a shielded Note in the UTXO pool
3. Notes are encrypted with your viewing key

### 3. Transact Privately
1. Build transfer witness with input/output notes
2. Generate Groth16 proof using Railgun's trusted setup
3. Submit transaction with proof to Railgun contracts
4. Recipient gets a new Note, you get change

### 4. Unshield
1. Create withdrawal proof for your note
2. Specify recipient address and amount
3. Funds are released from Railgun pool

## Components

```
crates/
├── railgun-lane/          # Complete Railgun protocol implementation
│   ├── artifacts.rs       # Circuit artifact management (IPFS download)
│   ├── bip32.rs          # BIP32 key derivation for Baby Jubjub
│   ├── contracts.rs      # Railgun contract ABIs and addresses
│   ├── event_loader.rs   # Shield/Transact event parsing
│   ├── keys.rs           # EdDSA keys (SpendingKey, ViewingKey)
│   ├── lane.rs           # PoolLane trait implementation
│   ├── notes.rs          # Note encryption/decryption
│   ├── poseidon.rs       # Circomlib-compatible Poseidon hash
│   ├── prover.rs         # Groth16 proof generation/verification
│   └── rpc.rs            # Ethereum RPC client
└── voidgun-proxy/         # RPC proxy server for privacy-via-proxy
    ├── main.rs            # CLI entry point
    ├── server.rs          # Axum HTTP/WebSocket server
    ├── proxy.rs           # JSON-RPC routing and dispatch
    ├── methods.rs         # Custom voidgun_* and eth_* handlers
    ├── context.rs         # Per-user wallet context management
    ├── db.rs              # SQLite persistence
    ├── jsonrpc.rs         # JSON-RPC request/response types
    └── error.rs           # Error handling
```

## Supported Chains

| Chain | Chain ID | Relay Contract | Status |
|-------|----------|----------------|--------|
| Ethereum Mainnet | 1 | `0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9` | Production |
| Polygon | 137 | `0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9` | Production |
| Sepolia Testnet | 11155111 | `0x464a0c9e62534b3b160c35638DD7d5cf761f429e` | Testing |

## Quick Start

```rust
use railgun_lane::{RailgunLane, RailgunWallet, PoolLane};
use alloy_primitives::Address;

#[tokio::main]
async fn main() {
    // 1. Create lane with RPC
    let contract: Address = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9".parse().unwrap();
    let mut lane = RailgunLane::with_rpc(
        1, // Ethereum mainnet
        contract,
        "./artifacts",
        "https://eth.llamarpc.com"
    );

    // 2. Initialize with wallet signature (from MetaMask, etc.)
    let signature = [0u8; 65]; // Your ECDSA signature
    lane.init(&signature).await.unwrap();

    // 3. Get your 0zk receiving address
    let address = lane.receiving_address().unwrap();
    println!("Send funds to: {}", address); // 0zk1...

    // 4. Sync on-chain state
    lane.sync_to_latest().await.unwrap();

    // 5. Check balances
    let balances = lane.get_all_balances().await.unwrap();
    for b in balances {
        println!("{}: {} ({} notes)", b.token, b.balance, b.note_count);
    }
}
```

## RPC Proxy Server

The `voidgun-proxy` crate provides a privacy-via-proxy RPC server that sits between your wallet and the Ethereum network. It intercepts JSON-RPC calls and routes privacy-related operations through the Railgun pool.

`voidgun-proxy` is a **standalone binary**. It works with **any Ethereum-compatible JSON-RPC endpoint** (public providers, self-hosted nodes, or Tenderly VNet) via the `--upstream` flag. There is no dependency on reth or any execution-layer plugin.

### Usage

```bash
# Start the proxy server
voidgun-proxy --upstream https://eth.llamarpc.com --chain-id 1 --port 8545 --db voidgun.db

# Or with environment variables (precedence: UPSTREAM_RPC_URL > ETH_RPC_URL > MAINNET_RPC_URL)
UPSTREAM_RPC_URL=https://eth.llamarpc.com voidgun-proxy --chain-id 1
```

Wallet state is persisted to SQLite and restored on restart.

### Wallet Setup

Configure your wallet (MetaMask, Rainbow, etc.) to use the proxy:
- Network RPC URL: `http://localhost:8545`
- Chain ID: Same as upstream (e.g., 1 for mainnet)

On first transaction, the proxy will request a signature to derive your privacy keys.

### Custom Methods

| Method | Description |
|--------|-------------|
| `voidgun_init` | Initialize privacy wallet with signature |
| `voidgun_shieldedBalance` | Get shielded balance for a token |
| `voidgun_allBalances` | Get all shielded balances |
| `voidgun_sync` | Sync wallet state from chain |
| `voidgun_unshield` | Withdraw tokens to public address |
| `voidgun_address` | Get 0zk receiving address |

### Intercepted Methods

The proxy intercepts standard Ethereum methods to provide seamless privacy:

- **`eth_getBalance`** - For initialized privacy wallets, returns shielded ETH balance (Railgun pool). Non-initialized wallets see their public L1 balance.
- **`eth_sendTransaction`** - For initialized wallets, simple ETH transfers (nonzero `value`, no `data`) are executed as unshield operations. Contract calls are forwarded unchanged.
- **`personal_sign`** - When called with the Railgun domain message, uses the signature to derive privacy keys and initialize the wallet. Other signatures are forwarded unchanged.

All other methods are forwarded to the upstream RPC unchanged.

### Endpoints

- `POST /` - JSON-RPC over HTTP
- `GET /` - JSON-RPC over WebSocket
- `GET /health` - Health check (returns `200 OK`)

## Building

```bash
# Build the Rust crate
cargo build -p railgun-lane --release

# Build proxy server
cargo build -p voidgun-proxy --release

# Run proxy
cargo run -p voidgun-proxy -- --upstream https://eth.llamarpc.com --chain-id 1

# Run tests
cargo test -p railgun-lane
cargo test -p voidgun-proxy
```

## Testing

### Unit Tests
```bash
cargo test -p railgun-lane
cargo test -p voidgun-proxy
```

### Proof Generation (requires circuit artifacts)
```bash
# Downloads artifacts from IPFS automatically
cargo test -p railgun-lane --test proof_generation -- --ignored --nocapture
```

### Sepolia Testnet
```bash
# Test against Sepolia Railgun contracts
SEPOLIA_RPC_URL="https://sepolia.infura.io/v3/YOUR_KEY" \
  cargo test -p railgun-lane --test sepolia_integration -- --ignored --nocapture
```

### End-to-End with Tenderly
```bash
# Requires Tenderly VNet setup:
#   export TENDERLY_ACCESS_KEY="your-key"
#   export TENDERLY_ACCOUNT="your-account"
#   export TENDERLY_PROJECT="your-project"

# Test railgun-lane protocol
cargo test -p railgun-lane --test onchain_verification test_e2e_auto_vnet -- --ignored --nocapture

# Test voidgun-proxy full stack
cargo test -p voidgun-proxy --test e2e_tenderly -- --ignored --nocapture
```

## Protocol Visualization

See [docs/protocol-visualization.html](docs/protocol-visualization.html) for an interactive visualization of the Railgun protocol flow.

## Key Concepts

### EdDSA on Baby Jubjub
- Uses circomlib's Poseidon-based EdDSA variant
- Signing: `S = r + H(R, A, M) * s (mod subOrder)`
- Verification: `S * Base8 == R8 + 8 * H(R, A, M) * A`

### Note Structure
```
Note = {
  npk: Poseidon(mpk, random),   // Note public key (from master public key + random)
  token: tokenAddress,
  value: amount,
  random: randomness
}
Commitment = Poseidon(npk, token, value)   // 3-input Poseidon
Nullifier  = Poseidon(nullifyingKey, leafIndex)
```

### Merkle Tree
- Depth: 16 levels (MAX_MERKLE_DEPTH constant)
- Capacity: 65,536 leaves per tree
- Hash: Poseidon with BN254 scalar field
- Synced from on-chain Shield/Transact events
- Validated: Depth and capacity checks prevent panics

### Circuit Variants
Named by input/output counts:
- `01x01`: 1 input, 1 output (simple transfer)
- `02x02`: 2 inputs, 2 outputs (with change)
- `08x02`: 8 inputs, 2 outputs (consolidation)

## License

MIT OR Apache-2.0

---

## Acknowledgments

- [Railgun](https://railgun.org/) for the privacy protocol and trusted setup
- [Nullmask](https://nullmask.io/) for the privacy-via-proxy concept
- [arkworks](https://arkworks.rs/) for the Groth16 implementation
