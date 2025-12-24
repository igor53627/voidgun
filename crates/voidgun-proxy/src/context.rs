//! User context management
//!
//! Each wallet address that has signed the domain message gets a UserContext
//! containing their RailgunLane instance for balance queries and transactions.

use std::sync::Arc;

use alloy_primitives::Address;
use dashmap::DashMap;
use railgun_lane::{PoolLane, RailgunLane};
use tokio::sync::RwLock;

use crate::db::Database;
use crate::error::{ProxyError, ProxyResult};

pub struct UserContext {
    pub address: Address,
    pub chain_id: u64,
    pub lane: RwLock<RailgunLane>,
    pub last_synced_block: u64,
}

impl UserContext {
    pub fn new(address: Address, chain_id: u64, lane: RailgunLane) -> Self {
        Self {
            address,
            chain_id,
            lane: RwLock::new(lane),
            last_synced_block: 0,
        }
    }

    pub async fn is_initialized(&self) -> bool {
        self.lane.read().await.is_initialized()
    }
}

pub struct UserContextStore {
    contexts: DashMap<(u64, Address), Arc<UserContext>>,
    db: Arc<Database>,
    rpc_url: String,
}

impl UserContextStore {
    pub fn new(db: Arc<Database>, rpc_url: String) -> Self {
        Self {
            contexts: DashMap::new(),
            db,
            rpc_url,
        }
    }

    pub fn get(&self, chain_id: u64, address: Address) -> Option<Arc<UserContext>> {
        self.contexts.get(&(chain_id, address)).map(|r| r.clone())
    }

    pub async fn init_from_signature(
        &self,
        chain_id: u64,
        address: Address,
        signature: &[u8],
    ) -> ProxyResult<Arc<UserContext>> {
        let signature_entropy = Self::derive_entropy(signature);
        let mut lane = RailgunLane::for_chain(chain_id, Some(self.rpc_url.clone()))
            .map_err(ProxyError::Lane)?;

        lane.init(&signature_entropy)
            .await
            .map_err(ProxyError::Lane)?;
        self.db
            .save_context(chain_id, address, &signature_entropy, 0)
            .await?;

        let ctx = Arc::new(UserContext::new(address, chain_id, lane));
        self.contexts.insert((chain_id, address), ctx.clone());

        Ok(ctx)
    }

    pub async fn restore_from_db(&self, chain_id: u64) -> ProxyResult<usize> {
        let contexts = self.db.list_contexts(chain_id).await?;
        let mut restored = 0;

        for (address, last_block) in contexts {
            if let Some((entropy, _)) = self.db.load_context(chain_id, address).await? {
                if let Ok(lane) = RailgunLane::for_chain(chain_id, Some(self.rpc_url.clone())) {
                    let mut ctx = UserContext::new(address, chain_id, lane);
                    ctx.last_synced_block = last_block;

                    if ctx.lane.write().await.init(&entropy).await.is_ok() {
                        self.contexts.insert((chain_id, address), Arc::new(ctx));
                        restored += 1;
                    }
                }
            }
        }

        Ok(restored)
    }

    pub async fn update_synced_block(
        &self,
        chain_id: u64,
        address: Address,
        block: u64,
    ) -> ProxyResult<()> {
        self.db.update_synced_block(chain_id, address, block).await
    }

    fn derive_entropy(signature: &[u8]) -> Vec<u8> {
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(signature);
        let mut entropy = Vec::with_capacity(64);
        entropy.extend_from_slice(&hash);
        entropy.extend_from_slice(&hash);
        entropy
    }
}
