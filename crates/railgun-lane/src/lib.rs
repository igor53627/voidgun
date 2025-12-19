//! Railgun Lane - Pure Rust implementation of Railgun privacy pool integration
//!
//! This crate provides a Railgun-compatible privacy pool lane for Voidgun's
//! multi-pool proxy architecture. It enables users to access Railgun's liquidity
//! while using their standard Ethereum wallets.
//!
//! # Architecture
//!
//! ```text
//! Wallet Signature
//!        │
//!        ▼
//! ┌──────────────────┐
//! │ Entropy Derivation│  keccak256(sig)[0:16]
//! └──────────────────┘
//!        │
//!        ▼
//! ┌──────────────────┐
//! │ BIP39 Mnemonic   │  12 words from entropy
//! └──────────────────┘
//!        │
//!        ▼
//! ┌──────────────────┐
//! │ BIP32 Derivation │  Baby Jubjub curve
//! │ m/44'/1984'/...  │  Spending keys
//! │ m/420'/1984'/... │  Viewing keys
//! └──────────────────┘
//!        │
//!        ▼
//! ┌──────────────────┐
//! │ Railgun Wallet   │  MPK, 0zk address, keys
//! └──────────────────┘
//! ```
//!
//! # Key Components
//!
//! - [`keys`] - BIP32 key derivation for Baby Jubjub curve
//! - [`poseidon`] - Railgun-compatible Poseidon hash (circomlibjs params)
//! - [`notes`] - Note structure and encryption
//! - [`prover`] - Groth16 proof generation via ark-circom
//! - [`lane`] - PoolLane trait implementation

pub mod artifacts;
pub mod bip32;
pub mod contracts;
pub mod event_loader;
pub mod keys;
pub mod lane;
pub mod notes;
pub mod poseidon;
pub mod prover;
pub mod rpc;

pub use artifacts::{
    ArtifactStore, CircuitArtifact, CircuitVariant, DownloadProgress, ProgressCallback,
};
pub use event_loader::{
    append_commitments_to_tree, build_merkle_tree_from_files,
    build_merkle_tree_from_files_with_info, load_shield_events, load_transact_events,
    TreeBuildResult,
};
pub use keys::{EddsaSignature, RailgunWallet, SpendingKey, ViewingKey};
pub use lane::{PoolLane, PoolType, RailgunLane, TransferRequest, TransferResult};
pub use notes::{EncryptedNote, NoteMerkleTree, NoteError, RailgunNote, ShieldCiphertext, MAX_MERKLE_DEPTH};
pub use prover::{CommitmentCiphertextData, RailgunProof, RailgunProver, TransactWitness};
pub use rpc::{EventSyncer, RailgunEvent, RailgunRpcClient};

/// Domain separator for deriving Railgun keys from wallet signature
pub const RAILGUN_DOMAIN_MESSAGE: &str = 
    "Authorize Railgun privacy pool access via Voidgun proxy.\n\nThis signature will be used to derive your Railgun wallet keys deterministically.";

/// Railgun's BIP44 coin type
pub const RAILGUN_COIN_TYPE: u32 = 1984;

/// Railgun's viewing key purpose (non-standard BIP44)
pub const RAILGUN_VIEWING_PURPOSE: u32 = 420;
