# Voidgun Project Knowledge

## Architecture Overview

Voidgun is a privacy-via-proxy implementation using Railgun protocol integration:

```
voidgun monorepo (~/pse/voidgun)
├── crates/
│   └── railgun-lane/     # Complete Railgun protocol implementation
├── docs/
│   └── protocol-visualization.html  # Interactive protocol docs
└── scripts/              # Build utilities
```

## Railgun Lane Crate

Location: `crates/railgun-lane/`

Self-contained Railgun protocol implementation with:

### Modules
- `artifacts.rs` - Circuit artifact management (IPFS download, caching)
- `bip32.rs` - BIP32 key derivation for Baby Jubjub curve
- `contracts.rs` - Railgun contract ABIs and addresses
- `event_loader.rs` - Shield/Transact event parsing, Merkle tree building
- `keys.rs` - EdDSA keys (SpendingKey, ViewingKey, RailgunWallet)
- `lane.rs` - PoolLane trait with sync and transfer methods
- `notes.rs` - Note encryption/decryption (ChaCha20-Poly1305, AES-GCM)
- `poseidon.rs` - Circomlib-compatible Poseidon hash
- `prover.rs` - Groth16 proof generation/verification via ark-circom
- `rpc.rs` - Ethereum RPC client for event syncing

### Key Types
- `RailgunWallet` - Complete wallet with spending/viewing/nullifying keys
- `RailgunNote` - Shielded note with commitment and nullifier
- `RailgunProver` - Groth16 proof generator using WASM/ZKEY artifacts
- `RailgunLane` - PoolLane implementation with sync and transfer

## Build Commands

```bash
# Build
cargo build -p railgun-lane --release

# Test (unit tests)
cargo test -p railgun-lane

# Test (proof generation, requires artifacts)
cargo test -p railgun-lane --test proof_generation -- --ignored --nocapture

# Test (e2e with Tenderly)
cargo test -p railgun-lane --test onchain_verification test_e2e_auto -- --ignored --nocapture
```

## Testing Preferences

- **Use Tenderly for testnet testing** - NOT Anvil or local forks
- Environment variables:
  - `TENDERLY_ACCESS_KEY` - Tenderly API key
  - `TENDERLY_ACCOUNT` - Account name
  - `TENDERLY_PROJECT` - Project name
  - `MAINNET_RPC_URL` or `ETH_RPC_URL` - For read-only mainnet tests

## Key Derivation Flow

1. User signs domain message with wallet (ECDSA)
2. Extract entropy: `keccak256(signature)[0:16]`
3. Generate BIP39 mnemonic (12 words)
4. Derive BIP32 master on Baby Jubjub curve
5. Spending key: `m/44'/1984'/0'/0'`
6. Viewing key: `m/420'/1984'/0'/0'`

## Circuit Variants

Named by inputs x outputs:
- `01x01` - Simple transfer (1 in, 1 out)
- `02x02` - Standard with change (2 in, 2 out)
- `08x02` - Consolidation (8 in, 2 out)

Artifacts downloaded from IPFS:
- WASM (~5 MB) - Witness calculation
- ZKEY (~50-200 MB) - Proving key
- VKEY (~5 KB) - Verification key

## EdDSA on Baby Jubjub

Circomlib-compatible Poseidon-based EdDSA:

```
Signing:   S = r + H(R, A, M) * s (mod subOrder)
Verify:    S * Base8 == R8 + 8 * H(R, A, M) * A
Key:       A = Base8 * (s >> 3)
Transform: x_ark = sqrt(168700) * x_circ
```

## Note Structure

```
Note = {
  npk: Poseidon(nk, leafIndex),   // Note public key
  token: address,                  // Token contract
  value: amount,                   // Hidden value
  random: blinding                 // Randomness
}
Commitment = Poseidon(npk, token, value, random)
Nullifier = Poseidon(nullifyingKey, leafIndex)
```

## Merkle Tree

- Depth: 16 levels
- Hash: Poseidon (BN254 scalar field)
- Capacity: 65,536 commitments per tree
- Synced from on-chain Shield/Transact events

## Recent Changes

### v0.2.0 (2024-12-19)
- Removed original Voidgun pool (core, prover, contracts, reth-plugin, circuits)
- Now using Railgun protocol exclusively via `railgun-lane` crate
- Fixed CVE-2023-42811 (aes-gcm upgrade)
- Fixed nullifier computation (joinsplit formula)
- Added streaming download progress for large artifacts
