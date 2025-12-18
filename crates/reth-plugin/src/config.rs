use alloy_primitives::{Address, B256};
use std::path::PathBuf;

/// Voidgun plugin configuration
#[derive(Clone, Debug)]
pub struct VoidgunConfig {
    /// Enable the voidgun plugin
    pub enabled: bool,

    /// VoidgunPool contract address
    pub pool_address: Address,

    /// Verifier contract address
    pub verifier_address: Address,

    /// Chain ID
    pub chain_id: u64,

    /// Relayer private key (for submitting pool transactions)
    pub relayer_key: Option<B256>,

    /// Local database path for notes and keys
    pub db_path: PathBuf,

    /// Merkle tree depth
    pub tree_depth: u32,

    /// Key server URL (optional)
    pub key_server_url: Option<String>,
}

impl Default for VoidgunConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pool_address: Address::ZERO,
            verifier_address: Address::ZERO,
            chain_id: 1,
            relayer_key: None,
            db_path: PathBuf::from("./voidgun-data"),
            tree_depth: 20,
            key_server_url: None,
        }
    }
}

impl VoidgunConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(val) = std::env::var("VOIDGUN_ENABLED") {
            config.enabled = val.parse().unwrap_or(false);
        }

        if let Ok(val) = std::env::var("VOIDGUN_POOL_ADDRESS") {
            if let Ok(addr) = val.parse() {
                config.pool_address = addr;
            }
        }

        if let Ok(val) = std::env::var("VOIDGUN_CHAIN_ID") {
            if let Ok(id) = val.parse() {
                config.chain_id = id;
            }
        }

        if let Ok(val) = std::env::var("VOIDGUN_DB_PATH") {
            config.db_path = PathBuf::from(val);
        }

        config
    }
}
