//! Shared test utilities for railgun-lane tests

use ark_bn254::Fr as Field;
use railgun_lane::{ArtifactStore, RailgunProver, RailgunWallet};
use std::sync::Arc;

pub const ARTIFACTS_PATH: &str = "crates/railgun-lane/artifacts";

pub fn setup_prover() -> RailgunProver {
    let store = Arc::new(ArtifactStore::new(ARTIFACTS_PATH, false));
    RailgunProver::new(store)
}

pub fn setup_wallet() -> RailgunWallet {
    let sig = [0x42u8; 65];
    RailgunWallet::from_wallet_signature(&sig).expect("wallet creation")
}

pub fn compute_message_hash(
    merkle_root: Field,
    bound_params_hash: Field,
    nullifiers: &[Field],
    commitments: &[Field],
) -> Field {
    let mut inputs = vec![merkle_root, bound_params_hash];
    inputs.extend(nullifiers.iter().copied());
    inputs.extend(commitments.iter().copied());
    railgun_lane::poseidon::poseidon_var(&inputs)
}
