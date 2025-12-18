# Voidgun Project Knowledge

## Architecture Overview

Voidgun is a privacy pool implementation with two main integration points:

```
voidgun monorepo (~/pse/voidgun)
├── crates/
│   ├── core/           # Crypto primitives, Merkle tree, notes, keys
│   ├── prover/         # ZK proof generation via bb CLI
│   ├── contracts/      # Solidity bindings, event types
│   └── reth-plugin/    # Reth-agnostic engine (see below)
├── circuits/           # Noir circuit source
├── circuits-bin/       # Compiled circuit artifacts
└── contracts/          # Solidity contracts

PSE reth fork (~/pse/pse/vendor/reth)
└── crates/voidgun/     # Thin reth adapter
```

## Two-Crate Architecture

### voidgun-reth-plugin (monorepo)
Location: `crates/reth-plugin/`

**No reth dependencies** - can be tested independently.

Key components:
- `VoidgunEngine` - Sync core state machine (`&mut self` API)
  - `begin_block()` / `end_block()` - Block processing
  - `handle_deposit()` / `handle_transfer()` / `handle_withdrawal()` - Event processing
  - `revert_block()` / `revert_to_block()` - Reorg handling
- `VoidgunExEx` - Async wrapper with `tokio::sync::Mutex`
- `VoidgunRpc` - Full JSON-RPC with `void_*` namespace
- `VoidgunStorage` - Sled-backed persistence

### reth-voidgun (PSE reth fork)
Location: `~/pse/pse/vendor/reth/crates/voidgun/`

**Thin adapter** (~200 lines) that:
- Imports `voidgun-reth-plugin` as dependency
- Translates reth's `Log` type to `RawLog`
- Connects `ExExContext` notifications to `VoidgunEngine`
- Exposes node-level RPC methods

## Build Requirements

- **nargo**: 1.0.0-beta.16 (Noir compiler)
- **bb**: Custom build from aztec-packages `next` branch (fixes ECDSA bigfield bug)

Install:
```bash
noirup --version 1.0.0-beta.16
./scripts/build-bb.sh --install  # Builds bb from source with ECDSA fix
```

## Testing Preferences

- **Use Tenderly for testnet testing** - NOT Anvil or local forks
- Tenderly RPC URL configured in `contracts/foundry.toml` as `${TENDERLY_RPC_URL}`
- Set `TENDERLY_RPC_URL` env var before running forge scripts

## Key Commands

```bash
# Build monorepo
cargo build -p voidgun-reth-plugin

# Test monorepo
cargo test -p voidgun-reth-plugin -p voidgun-prover

# Build reth fork crate
cd ~/pse/pse/vendor/reth && cargo check -p reth-voidgun

# Compile Noir circuit
cd circuits-bin/transfer && nargo compile
```

## RPC Methods

### Full RPC (voidgun-reth-plugin)
- `void_initAccount(address, signature)` - Initialize from wallet signature
- `void_isInitialized(address)` - Check account status
- `void_getReceivingKey(address)` - Get receiving key for sending
- `void_sendTransaction(rawTx)` - Build shielded transfer with ZK proof
- `void_getBalance(address, token?)` - Get shielded balance
- `void_listNotes(address)` - List unspent notes

### Node RPC (reth-voidgun)
- `void_getRoot()` - Current Merkle root
- `void_getLeafCount()` - Number of commitments
- `void_isKnownRoot(root)` - Check root validity
- `void_getMerklePath(leafIndex)` - Get Merkle proof path

## Event Types

From `VoidgunPool.sol`:
- `Deposit(commitment, value, token, ciphertext, leafIndex, newRoot)`
- `Transfer(nfNote, nfTx, cmOut, cmChange, newRoot, ciphertextOut, ciphertextChange)`
- `Withdrawal(nfNote, nfTx, to, value, token)`

## Storage Keys (sled)

- `vk:{address}` - Viewing keys
- `pk:{address}` - Secp256k1 public keys (x,y)
- `note:{address}:{merkle_index}` - Decrypted notes
- `root:{hex}` - Known Merkle roots
- `nf_note:{hex}` - Note nullifiers
- `nf_tx:{hex}` - Transaction nullifiers
- `revert:{block_number}` - Revert operations for reorg handling
- `last_block` - Last processed block number

## Integration Pattern

```rust
// In reth node builder:
use voidgun_reth_plugin::{VoidgunConfig, VoidgunEngine, VoidgunStorage};
use reth_voidgun::VoidgunExEx;

let storage = Arc::new(VoidgunStorage::open(&config.db_path)?);
let engine = Arc::new(Mutex::new(VoidgunEngine::new(config, storage)));
let exex = VoidgunExEx::with_engine(config, engine.clone());

builder
    .install_exex("voidgun", |ctx| Ok(exex.run(ctx)))
    .extend_rpc_modules(|ctx| {
        ctx.modules.merge(VoidgunRpc::new(engine).into_rpc())?;
        Ok(())
    })
```
