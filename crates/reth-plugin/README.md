# voidgun-reth-plugin

Reth-agnostic voidgun engine and event processing library.

## Architecture

This crate provides the core voidgun functionality that can be used by reth's ExEx framework:

- **VoidgunEngine**: Core state machine for processing pool events (sync API with `&mut self`)
- **VoidgunExEx**: Async wrapper with `tokio::sync::Mutex` for ExEx integration
- **VoidgunRpc**: JSON-RPC server with `void_*` namespace
- **VoidgunStorage**: Sled-backed persistent storage for viewing keys, notes, and revert ops

## Integration with reth fork

The PSE reth fork at `~/pse/pse/vendor/reth/crates/voidgun/` should use this crate as follows:

### 1. Add dependency

In the reth fork's `Cargo.toml`:

```toml
[dependencies]
voidgun-reth-plugin = { path = "../../../../voidgun/crates/reth-plugin" }
```

### 2. Create engine and ExEx

```rust
use voidgun_reth_plugin::{VoidgunConfig, VoidgunStorage, VoidgunEngine, VoidgunExEx};
use std::sync::Arc;
use tokio::sync::Mutex;

// Create storage
let storage = Arc::new(VoidgunStorage::open(&config.db_path)?);

// Create engine
let engine = Arc::new(Mutex::new(VoidgunEngine::new(config.clone(), storage.clone())));

// Create ExEx with shared engine
let exex = VoidgunExEx::with_engine(config.clone(), engine.clone());
```

### 3. Process ExEx notifications

```rust
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use voidgun_reth_plugin::exex::RawLog;

async fn run_exex<Node: FullNodeComponents>(
    exex: VoidgunExEx,
    mut ctx: ExExContext<Node>,
) -> eyre::Result<()> {
    while let Some(notification) = ctx.notifications.try_next().await? {
        match &notification {
            ExExNotification::ChainCommitted { new } => {
                let execution_outcome = new.execution_outcome();
                
                for (block_idx, block_receipts) in execution_outcome.receipts.iter().enumerate() {
                    let block_number = execution_outcome.first_block + block_idx as u64;
                    
                    // Convert reth logs to RawLog
                    let logs: Vec<RawLog> = block_receipts
                        .iter()
                        .flat_map(|r| r.logs())
                        .map(|log| RawLog::new(
                            log.address,
                            log.topics().iter().map(|t| t.0).collect(),
                            log.data.data.to_vec(),
                        ))
                        .collect();
                    
                    exex.process_block(block_number, logs).await?;
                }
            }
            ExExNotification::ChainReorged { old, new } => {
                let target = new.first_block.saturating_sub(1);
                exex.revert_to_block(target).await?;
            }
            ExExNotification::ChainReverted { old } => {
                for block in old.range().rev() {
                    exex.revert_block(block.number).await?;
                }
            }
        }
        
        if let Some(committed_chain) = notification.committed_chain() {
            ctx.events.send(ExExEvent::FinishedHeight(committed_chain.tip().num_hash()))?;
        }
    }
    Ok(())
}
```

### 4. Wire up RPC

```rust
use voidgun_reth_plugin::{VoidgunRpc, VoidgunRpcApiServer};

// Create RPC with shared engine
let rpc = VoidgunRpc::new(config, storage, engine);

// Register with jsonrpsee server
let module = rpc.into_rpc();
```

## RPC Methods

- `void_initAccount(address, signature)` - Initialize account from wallet signature
- `void_isInitialized(address)` - Check if account is initialized
- `void_getReceivingKey(address)` - Get receiving key for sending to this account
- `void_sendTransaction(rawTx)` - Build shielded transfer with ZK proof
- `void_getBalance(address, token?)` - Get shielded balance
- `void_listNotes(address)` - List unspent notes

## Requirements

- nargo 1.0.0-beta.16 (for circuit compilation)
- bb 3.0.0-rc.4 (Barretenberg CLI for proof generation)

Install with:
```bash
noirup --version 1.0.0-beta.16
bbup -v 3.0.0-rc.4
```
