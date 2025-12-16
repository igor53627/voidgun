# Voidgun

Privacy-via-proxy architecture for Ethereum. Transact privately from any multi-chain wallet.

## Overview

Voidgun implements a "proxy without spending authority" model where:
- Your wallet retains full spending authority via ECDSA signatures
- The proxy cannot steal funds - only wallet-signed transactions authorize spends
- All privacy operations are verified in zero-knowledge using Noir circuits

## Architecture

```
┌─────────┐     ┌──────────────────────┐     ┌─────────────────┐
│  Wallet │────▶│  reth + voidgun      │────▶│  VoidgunPool    │
│  (signs)│     │  (RPC proxy + ExEx)  │     │  (L1 contract)  │
└─────────┘     └──────────────────────┘     └─────────────────┘
                         │
                         │ Noir circuit proves:
                         │ - ECDSA signature valid
                         │ - tx.to matches recipient
                         │ - tx.amount matches transfer
                         │ - Merkle proof valid
                         │ - Nullifiers correct
                         ▼
                   Zero-knowledge proof
```

## How It Works (User Flow)

### 1. Setup (one-time, ~30 seconds)
1. Connect your existing wallet to the Voidgun app
2. Add "Voidgun" as a custom RPC network in your wallet
3. Sign a message to derive your privacy keys (no new seed phrase needed)
4. Keys are registered with the key server

### 2. Shield Funds
1. Deposit ETH/tokens to the VoidgunPool contract
2. Compliance check runs (rejects illicit funds per Privacy Pools model)
3. Your balance becomes a shielded "Note" in the UTXO pool

### 3. Transact Privately
1. Use your wallet normally (connected to Voidgun network)
2. The local proxy intercepts your transaction
3. ZK proof is generated proving your signature authorizes the spend
4. Relayer submits the shielded tx on-chain
5. Recipient gets a new Note, you get change

After setup, everything is transparent - just use your wallet as usual.

## Security Model

Unlike other privacy protocols where the app holds spending keys, Voidgun:
1. Verifies wallet ECDSA signatures inside the zk circuit
2. Binds transaction fields (to, amount) to shielded outputs
3. Uses transaction nullifiers to prevent replay attacks

The proxy can view transactions but **cannot authorize spends**.

## Components

- `circuits/` - Noir circuits for transfer verification
- `crates/core/` - Rust types for keys, notes, merkle trees
- `crates/prover/` - Noir/Barretenberg proving integration
- `crates/contracts/` - VoidgunPool Solidity + Rust bindings
- `crates/reth-plugin/` - reth RPC middleware + ExEx

## Building

```bash
# Install Noir
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup

# Build circuits
cd circuits && nargo compile

# Build Rust
cargo build --release
```

## Status

🚧 **Under Development** - See [Issues](../../issues) for progress tracking.

## License

MIT OR Apache-2.0

---

## Acknowledgments

A huge thank you to the [Nullmask](https://nullmask.io/) team for their groundbreaking research and inspiration. The Voidgun architecture is based on their paper "Nullmask: transact privately from any multi-chain wallet" which introduced the privacy-via-proxy concept and the security models that make this project possible.
