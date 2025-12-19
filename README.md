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
└── railgun-lane/          # Complete Railgun protocol implementation
    ├── artifacts.rs       # Circuit artifact management (IPFS download)
    ├── bip32.rs          # BIP32 key derivation for Baby Jubjub
    ├── contracts.rs      # Railgun contract ABIs and addresses
    ├── event_loader.rs   # Shield/Transact event parsing
    ├── keys.rs           # EdDSA keys (SpendingKey, ViewingKey)
    ├── lane.rs           # PoolLane trait implementation
    ├── notes.rs          # Note encryption/decryption
    ├── poseidon.rs       # Circomlib-compatible Poseidon hash
    ├── prover.rs         # Groth16 proof generation/verification
    └── rpc.rs            # Ethereum RPC client
```

## Building

```bash
# Build the Rust crate
cargo build -p railgun-lane --release

# Run tests
cargo test -p railgun-lane
```

## Testing

### Unit Tests
```bash
cargo test -p railgun-lane
```

### Proof Generation (requires circuit artifacts)
```bash
# Downloads artifacts from IPFS automatically
cargo test -p railgun-lane --test proof_generation -- --ignored --nocapture
```

### End-to-End with Tenderly
```bash
# Requires Tenderly VNet setup:
#   export TENDERLY_ACCESS_KEY="your-key"
#   export TENDERLY_ACCOUNT="your-account"
#   export TENDERLY_PROJECT="your-project"
cargo test -p railgun-lane --test onchain_verification test_e2e_auto -- --ignored --nocapture
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
  npk: Poseidon(nullifyingKey, leafIndex),  // Note public key
  token: tokenAddress,
  value: amount,
  random: randomness
}
Commitment = Poseidon(npk, token, value, random)
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
