//! Example showing how to integrate VoidgunEngine with reth's ExEx framework
//!
//! This is a reference implementation for the PSE reth fork crate.
//! It demonstrates the proper pattern for:
//! - Creating shared VoidgunEngine
//! - Processing ExEx notifications
//! - Handling reorgs
//! - Wiring up RPC
//!
//! Note: This example cannot be compiled directly from the monorepo because
//! it requires reth dependencies. It serves as documentation for the reth fork.

/*
use futures::TryStreamExt;
use reth_ethereum::{
    chainspec::EthereumHardforks,
    exex::{ExExContext, ExExEvent, ExExNotification},
    node::{
        api::{FullNodeComponents, NodeTypes},
        EthereumNode,
    },
};
use reth_tracing::tracing::{info, warn};
use std::sync::Arc;
use tokio::sync::Mutex;

use voidgun_reth_plugin::{
    VoidgunConfig, VoidgunEngine, VoidgunRpc, VoidgunRpcApiServer, VoidgunStorage,
    exex::RawLog,
};

/// Convert reth Log to RawLog for engine processing
fn log_to_raw_log(log: &alloy_primitives::Log) -> RawLog {
    RawLog::new(
        log.address,
        log.topics().iter().map(|t| t.0).collect(),
        log.data.data.to_vec(),
    )
}

/// Voidgun ExEx that wraps VoidgunEngine
async fn voidgun_exex<Node: FullNodeComponents>(
    mut ctx: ExExContext<Node>,
    config: VoidgunConfig,
    engine: Arc<Mutex<VoidgunEngine>>,
) -> eyre::Result<()> {
    info!(
        pool_address = %config.pool_address,
        "Voidgun ExEx started"
    );

    while let Some(notification) = ctx.notifications.try_next().await? {
        match &notification {
            ExExNotification::ChainCommitted { new } => {
                let execution_outcome = new.execution_outcome();

                for (block_idx, block_receipts) in execution_outcome.receipts.iter().enumerate() {
                    let block_number = execution_outcome.first_block + block_idx as u64;

                    // Collect logs from this block
                    let logs: Vec<RawLog> = block_receipts
                        .iter()
                        .flat_map(|r| r.logs())
                        .filter(|log| log.address == config.pool_address)
                        .map(log_to_raw_log)
                        .collect();

                    // Process block with engine
                    let mut engine = engine.lock().await;
                    engine.begin_block(block_number);

                    for log in logs {
                        if log.topics.is_empty() {
                            continue;
                        }

                        // Decode and handle events
                        // The engine handles Deposit, Transfer, Withdrawal events
                        // This is simplified - in practice use the VoidgunExEx wrapper
                    }

                    engine.end_block(block_number)?;
                }
            }
            ExExNotification::ChainReorged { old, new } => {
                warn!(
                    from_chain = ?old.range(),
                    to_chain = ?new.range(),
                    "Chain reorg detected"
                );

                let mut engine = engine.lock().await;
                let target = new.first_block.saturating_sub(1);
                engine.revert_to_block(target)?;
            }
            ExExNotification::ChainReverted { old } => {
                warn!(
                    reverted_chain = ?old.range(),
                    "Chain reverted"
                );

                let mut engine = engine.lock().await;
                for block in old.range().rev() {
                    engine.revert_block(block.number)?;
                }
            }
        }

        if let Some(committed_chain) = notification.committed_chain() {
            ctx.events.send(ExExEvent::FinishedHeight(committed_chain.tip().num_hash()))?;
        }
    }

    Ok(())
}

fn main() -> eyre::Result<()> {
    // This is the pattern for wiring up voidgun in the reth fork:
    //
    // 1. Load config from environment or CLI
    let config = VoidgunConfig::from_env();

    // 2. Open storage
    let storage = Arc::new(VoidgunStorage::open(&config.db_path)?);

    // 3. Create shared engine
    let engine = Arc::new(Mutex::new(VoidgunEngine::new(config.clone(), storage.clone())));

    // 4. Create RPC with shared engine
    let rpc = VoidgunRpc::new(config.clone(), storage.clone(), engine.clone());

    // 5. In the reth node builder:
    //
    // reth_ethereum::cli::Cli::parse_args().run(|builder, _| {
    //     Box::pin(async move {
    //         let handle = builder
    //             .node(EthereumNode::default())
    //             .install_exex("voidgun", async move |ctx| {
    //                 Ok(voidgun_exex(ctx, config, engine))
    //             })
    //             .extend_rpc_modules(move |ctx| {
    //                 ctx.modules.merge(rpc.into_rpc())?;
    //                 Ok(())
    //             })
    //             .launch()
    //             .await?;
    //
    //         handle.wait_for_node_exit().await
    //     })
    // })

    Ok(())
}
*/

fn main() {
    println!("This is a documentation example for reth integration.");
    println!("It cannot be compiled directly - see crates/reth-plugin/README.md");
}
