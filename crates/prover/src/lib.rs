//! Voidgun Prover - Zero-knowledge proof generation using Barretenberg backend
//!
//! This crate provides proving and verification functionality for the Voidgun
//! shielded transfer circuit using the Barretenberg proving system via the `bb` CLI.
//!
//! # Requirements
//!
//! - `nargo` version 1.0.0-beta.16 (Noir compiler)
//! - `bb` version 3.0.0-rc.4 or compatible (Barretenberg CLI)
//!
//! Install bb with: `bbup -v 3.0.0-rc.4`
//!
//! # Example
//!
//! ```no_run
//! use voidgun_prover::{TransferWitness, prove_transfer, verify_transfer};
//! use ark_bn254::Fr as Field;
//! use ark_ff::Zero;
//!
//! let witness = TransferWitness {
//!     // ... fill in witness fields
//!     # root: Field::zero(),
//!     # cm_out: Field::zero(),
//!     # cm_change: Field::zero(),
//!     # nf_note: Field::zero(),
//!     # nf_tx: Field::zero(),
//!     # gas_tip: Field::zero(),
//!     # gas_fee_cap: Field::zero(),
//!     # token_type: Field::zero(),
//!     # pool_id: Field::zero(),
//!     # tx_hash: [0u8; 32],
//!     # tx_chain_id: 1,
//!     # tx_nonce: 0,
//!     # tx_to: [0u8; 20],
//!     # tx_value: Field::zero(),
//!     # tx_max_priority_fee: Field::zero(),
//!     # tx_max_fee: Field::zero(),
//!     # signature: [0u8; 64],
//!     # pub_key_x: [0u8; 32],
//!     # pub_key_y: [0u8; 32],
//!     # note_in_rk_hash: Field::zero(),
//!     # note_in_value: Field::zero(),
//!     # note_in_token: Field::zero(),
//!     # note_in_r: Field::zero(),
//!     # note_out_rk_hash: Field::zero(),
//!     # note_out_value: Field::zero(),
//!     # note_out_r: Field::zero(),
//!     # note_change_rk_hash: Field::zero(),
//!     # note_change_value: Field::zero(),
//!     # note_change_r: Field::zero(),
//!     # merkle_path: vec![Field::zero(); 20],
//!     # merkle_index: 0,
//!     # nk: Field::zero(),
//!     # recipient_pk_x: [0u8; 32],
//!     # recipient_pk_y: [0u8; 32],
//! };
//!
//! let proof = prove_transfer(witness)?;
//! let is_valid = verify_transfer(&proof)?;
//! # Ok::<(), voidgun_prover::ProverError>(())
//! ```

use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField};
use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use thiserror::Error;

/// Path to the compiled transfer circuit ACIR artifact (set by build.rs)
pub const TRANSFER_CIRCUIT_PATH: &str = env!("TRANSFER_CIRCUIT_PATH");

/// Cached circuit context
static CIRCUIT_CONTEXT: Lazy<Mutex<Option<CircuitContext>>> = Lazy::new(|| Mutex::new(None));

/// Circuit context with precomputed verification key
struct CircuitContext {
    circuit_path: PathBuf,
    vk: Vec<u8>,
}

/// Witness data for the transfer circuit
#[derive(Clone, Debug)]
pub struct TransferWitness {
    // Public inputs (9 elements matching VoidgunPool.sol)
    pub root: Field,
    pub cm_out: Field,
    pub cm_change: Field,
    pub nf_note: Field,
    pub nf_tx: Field,
    pub gas_tip: Field,
    pub gas_fee_cap: Field,
    pub token_type: Field,
    pub pool_id: Field,
    
    // Transaction data (private)
    pub tx_hash: [u8; 32],
    pub tx_chain_id: u64,
    pub tx_nonce: u64,
    pub tx_to: [u8; 20],
    pub tx_value: Field,
    pub tx_max_priority_fee: Field,
    pub tx_max_fee: Field,
    
    // ECDSA signature (private)
    pub signature: [u8; 64],
    pub pub_key_x: [u8; 32],
    pub pub_key_y: [u8; 32],
    
    // Input note (private)
    pub note_in_rk_hash: Field,
    pub note_in_value: Field,
    pub note_in_token: Field,
    pub note_in_r: Field,
    
    // Output note (private)
    pub note_out_rk_hash: Field,
    pub note_out_value: Field,
    pub note_out_r: Field,
    
    // Change note (private)
    pub note_change_rk_hash: Field,
    pub note_change_value: Field,
    pub note_change_r: Field,
    
    // Merkle proof (private)
    pub merkle_path: Vec<Field>,
    pub merkle_index: u64,
    
    // Nullifying key (private)
    pub nk: Field,
    
    // Recipient public key (private)
    pub recipient_pk_x: [u8; 32],
    pub recipient_pk_y: [u8; 32],
}

/// Generated proof
#[derive(Clone, Debug)]
pub struct TransferProof {
    /// Raw proof bytes
    pub proof: Vec<u8>,
    /// Public inputs as bytes (each field is 32 bytes BE)
    pub public_inputs: Vec<[u8; 32]>,
}

impl TransferProof {
    /// Get public inputs as Field elements
    pub fn public_inputs_fields(&self) -> Vec<Field> {
        self.public_inputs
            .iter()
            .map(|b| Field::from_be_bytes_mod_order(b))
            .collect()
    }
}

/// Prover errors
#[derive(Debug, Error, Clone)]
pub enum ProverError {
    #[error("Circuit compilation failed")]
    CompilationFailed,
    
    #[error("Witness generation failed: {0}")]
    WitnessGenerationFailed(String),
    
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
    
    #[error("Barretenberg backend error: {0}")]
    BackendError(String),
    
    #[error("bb CLI not found - install with: bbup")]
    BbNotFound,
    
    #[error("IO error: {0}")]
    IoError(String),
}

/// Check if bb CLI is available
fn check_bb_available() -> Result<(), ProverError> {
    Command::new("bb")
        .arg("--version")
        .output()
        .map_err(|_| ProverError::BbNotFound)?;
    Ok(())
}

/// Initialize the circuit context (loads VK once)
fn init_circuit_context() -> Result<CircuitContext, ProverError> {
    check_bb_available()?;
    
    let circuit_path = PathBuf::from(TRANSFER_CIRCUIT_PATH);
    if !circuit_path.exists() {
        return Err(ProverError::CompilationFailed);
    }
    
    tracing::info!("Generating verification key for transfer circuit...");
    
    let temp_dir = tempfile::tempdir()
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    let vk_dir = temp_dir.path().join("vk_out");
    
    // Generate VK using bb CLI (writes to directory containing vk file)
    let output = Command::new("bb")
        .args([
            "write_vk",
            "--oracle_hash", "keccak",
            "-b", circuit_path.to_str().unwrap(),
            "-o", vk_dir.to_str().unwrap(),
        ])
        .output()
        .map_err(|e| ProverError::BackendError(format!("Failed to run bb write_vk: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ProverError::BackendError(format!("bb write_vk failed: {}", stderr)));
    }
    
    // bb write_vk creates a directory with vk file inside
    let vk_path = vk_dir.join("vk");
    let vk = std::fs::read(&vk_path)
        .map_err(|e| ProverError::IoError(format!("Failed to read VK: {}", e)))?;
    
    tracing::info!("Verification key generated ({} bytes)", vk.len());
    
    Ok(CircuitContext {
        circuit_path,
        vk,
    })
}

/// Get or initialize circuit context
fn get_circuit_context() -> Result<CircuitContext, ProverError> {
    let mut guard = CIRCUIT_CONTEXT.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(init_circuit_context()?);
    }
    Ok(guard.as_ref().unwrap().clone())
}

impl Clone for CircuitContext {
    fn clone(&self) -> Self {
        CircuitContext {
            circuit_path: self.circuit_path.clone(),
            vk: self.vk.clone(),
        }
    }
}

/// Convert witness to Prover.toml format for nargo
fn witness_to_toml(witness: &TransferWitness) -> String {
    let mut lines = Vec::new();
    
    // Public inputs
    lines.push(format!("root = \"{}\"", field_to_hex(witness.root)));
    lines.push(format!("cm_out = \"{}\"", field_to_hex(witness.cm_out)));
    lines.push(format!("cm_change = \"{}\"", field_to_hex(witness.cm_change)));
    lines.push(format!("nf_note = \"{}\"", field_to_hex(witness.nf_note)));
    lines.push(format!("nf_tx = \"{}\"", field_to_hex(witness.nf_tx)));
    lines.push(format!("gas_tip = \"{}\"", field_to_hex(witness.gas_tip)));
    lines.push(format!("gas_fee_cap = \"{}\"", field_to_hex(witness.gas_fee_cap)));
    lines.push(format!("token_type = \"{}\"", field_to_hex(witness.token_type)));
    lines.push(format!("pool_id = \"{}\"", field_to_hex(witness.pool_id)));
    
    // Transaction data
    lines.push(format!("tx_hash = {}", bytes_to_toml_array(&witness.tx_hash)));
    lines.push(format!("tx_chain_id = \"{}\"", witness.tx_chain_id));
    lines.push(format!("tx_nonce = \"{}\"", witness.tx_nonce));
    lines.push(format!("tx_to = {}", bytes_to_toml_array(&witness.tx_to)));
    lines.push(format!("tx_value = \"{}\"", field_to_hex(witness.tx_value)));
    lines.push(format!("tx_max_priority_fee = \"{}\"", field_to_hex(witness.tx_max_priority_fee)));
    lines.push(format!("tx_max_fee = \"{}\"", field_to_hex(witness.tx_max_fee)));
    
    // ECDSA signature
    lines.push(format!("signature = {}", bytes_to_toml_array(&witness.signature)));
    lines.push(format!("pub_key_x = {}", bytes_to_toml_array(&witness.pub_key_x)));
    lines.push(format!("pub_key_y = {}", bytes_to_toml_array(&witness.pub_key_y)));
    
    // Input note
    lines.push(format!("note_in_rk_hash = \"{}\"", field_to_hex(witness.note_in_rk_hash)));
    lines.push(format!("note_in_value = \"{}\"", field_to_hex(witness.note_in_value)));
    lines.push(format!("note_in_token = \"{}\"", field_to_hex(witness.note_in_token)));
    lines.push(format!("note_in_r = \"{}\"", field_to_hex(witness.note_in_r)));
    
    // Output note
    lines.push(format!("note_out_rk_hash = \"{}\"", field_to_hex(witness.note_out_rk_hash)));
    lines.push(format!("note_out_value = \"{}\"", field_to_hex(witness.note_out_value)));
    lines.push(format!("note_out_r = \"{}\"", field_to_hex(witness.note_out_r)));
    
    // Change note
    lines.push(format!("note_change_rk_hash = \"{}\"", field_to_hex(witness.note_change_rk_hash)));
    lines.push(format!("note_change_value = \"{}\"", field_to_hex(witness.note_change_value)));
    lines.push(format!("note_change_r = \"{}\"", field_to_hex(witness.note_change_r)));
    
    // Merkle proof
    let merkle_path_strs: Vec<String> = witness.merkle_path
        .iter()
        .map(|f| format!("\"{}\"", field_to_hex(*f)))
        .collect();
    lines.push(format!("merkle_path = [{}]", merkle_path_strs.join(", ")));
    lines.push(format!("merkle_index = \"{}\"", witness.merkle_index));
    
    // Nullifying key
    lines.push(format!("nk = \"{}\"", field_to_hex(witness.nk)));
    
    // Recipient public key
    lines.push(format!("recipient_pk_x = {}", bytes_to_toml_array(&witness.recipient_pk_x)));
    lines.push(format!("recipient_pk_y = {}", bytes_to_toml_array(&witness.recipient_pk_y)));
    
    lines.join("\n")
}

fn field_to_hex(f: Field) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    format!("0x{}", hex::encode(bytes))
}

fn bytes_to_toml_array(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("\"0x{:02x}\"", b)).collect();
    format!("[{}]", strs.join(", "))
}

/// Generate a transfer proof using bb CLI
pub fn prove_transfer(witness: TransferWitness) -> Result<TransferProof, ProverError> {
    tracing::info!("Generating transfer proof...");
    
    check_bb_available()?;
    
    let circuit_path = PathBuf::from(TRANSFER_CIRCUIT_PATH);
    if !circuit_path.exists() {
        return Err(ProverError::CompilationFailed);
    }
    
    // Create temp directory for witness and proof files
    let temp_dir = tempfile::tempdir()
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    
    // Write Prover.toml
    let prover_toml = witness_to_toml(&witness);
    let prover_toml_path = temp_dir.path().join("Prover.toml");
    std::fs::write(&prover_toml_path, &prover_toml)
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    
    // Copy circuit to temp dir for nargo execute
    let circuit_dir = temp_dir.path().join("circuit");
    std::fs::create_dir_all(&circuit_dir.join("target"))
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    std::fs::create_dir_all(&circuit_dir.join("src"))
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    
    // Copy circuit artifact
    std::fs::copy(&circuit_path, circuit_dir.join("target").join("transfer.json"))
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    
    // Copy Prover.toml
    std::fs::copy(&prover_toml_path, circuit_dir.join("Prover.toml"))
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    
    // Create minimal Nargo.toml
    let nargo_toml = r#"[package]
name = "transfer"
type = "bin"
"#;
    std::fs::write(circuit_dir.join("Nargo.toml"), nargo_toml)
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    
    // Create minimal main.nr (just for nargo to be happy)
    std::fs::write(circuit_dir.join("src").join("main.nr"), "fn main() {}")
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    
    // Execute to generate witness
    tracing::info!("Executing circuit to generate witness...");
    let output = Command::new("nargo")
        .args(["execute", "--package", "transfer"])
        .current_dir(&circuit_dir)
        .output()
        .map_err(|e| ProverError::WitnessGenerationFailed(e.to_string()))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ProverError::WitnessGenerationFailed(stderr.to_string()));
    }
    
    let witness_path = circuit_dir.join("target").join("transfer.gz");
    if !witness_path.exists() {
        return Err(ProverError::WitnessGenerationFailed("Witness file not created".into()));
    }
    
    // Generate proof using bb
    let proof_path = temp_dir.path().join("proof");
    tracing::info!("Generating proof with bb...");
    
    let output = Command::new("bb")
        .args([
            "prove",
            "--oracle_hash", "keccak",
            "-b", circuit_dir.join("target").join("transfer.json").to_str().unwrap(),
            "-w", witness_path.to_str().unwrap(),
            "-o", proof_path.to_str().unwrap(),
        ])
        .output()
        .map_err(|e| ProverError::ProofGenerationFailed(e.to_string()))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ProverError::ProofGenerationFailed(stderr.to_string()));
    }
    
    let proof = std::fs::read(&proof_path)
        .map_err(|e| ProverError::IoError(format!("Failed to read proof: {}", e)))?;
    
    // Extract public inputs as bytes (9 elements matching VoidgunPool.sol)
    let public_inputs = vec![
        field_to_bytes(witness.root),
        field_to_bytes(witness.cm_out),
        field_to_bytes(witness.cm_change),
        field_to_bytes(witness.nf_note),
        field_to_bytes(witness.nf_tx),
        field_to_bytes(witness.gas_tip),
        field_to_bytes(witness.gas_fee_cap),
        field_to_bytes(witness.token_type),
        field_to_bytes(witness.pool_id),
    ];
    
    tracing::info!("Proof generated successfully ({} bytes)", proof.len());
    
    Ok(TransferProof {
        proof,
        public_inputs,
    })
}

/// Verify a transfer proof using bb CLI
pub fn verify_transfer(proof: &TransferProof) -> Result<bool, ProverError> {
    tracing::info!("Verifying transfer proof...");
    
    let ctx = get_circuit_context()?;
    
    let temp_dir = tempfile::tempdir()
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    
    // Write proof and vk to temp files
    let proof_path = temp_dir.path().join("proof");
    let vk_path = temp_dir.path().join("vk");
    
    std::fs::write(&proof_path, &proof.proof)
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    std::fs::write(&vk_path, &ctx.vk)
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    
    // Verify using bb
    let output = Command::new("bb")
        .args([
            "verify",
            "-p", proof_path.to_str().unwrap(),
            "-k", vk_path.to_str().unwrap(),
        ])
        .output()
        .map_err(|e| ProverError::BackendError(e.to_string()))?;
    
    let is_valid = output.status.success();
    tracing::info!("Proof verification result: {}", is_valid);
    
    Ok(is_valid)
}

/// Get the verification key bytes for contract deployment
pub fn verification_key() -> Result<Vec<u8>, ProverError> {
    let ctx = get_circuit_context()?;
    Ok(ctx.vk)
}

/// Generate Solidity verifier contract
pub fn generate_solidity_verifier() -> Result<String, ProverError> {
    tracing::info!("Generating Solidity verifier contract...");
    
    let ctx = get_circuit_context()?;
    
    let temp_dir = tempfile::tempdir()
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    
    let vk_path = temp_dir.path().join("vk");
    let sol_path = temp_dir.path().join("verifier.sol");
    
    std::fs::write(&vk_path, &ctx.vk)
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    
    let output = Command::new("bb")
        .args([
            "write_solidity_verifier",
            "-k", vk_path.to_str().unwrap(),
            "-o", sol_path.to_str().unwrap(),
            "-t", "evm",
        ])
        .output()
        .map_err(|e| ProverError::BackendError(e.to_string()))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ProverError::BackendError(format!("bb write_solidity_verifier failed: {}", stderr)));
    }
    
    let sol = std::fs::read_to_string(&sol_path)
        .map_err(|e| ProverError::IoError(e.to_string()))?;
    
    Ok(sol)
}

fn field_to_bytes(f: Field) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut arr = [0u8; 32];
    let start = 32 - bytes.len().min(32);
    arr[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    
    #[test]
    fn test_circuit_path() {
        assert!(!TRANSFER_CIRCUIT_PATH.is_empty());
        let path = std::path::Path::new(TRANSFER_CIRCUIT_PATH);
        if !path.exists() {
            println!("Circuit artifact not found at {} - nargo may not be installed", TRANSFER_CIRCUIT_PATH);
            return;
        }
        assert!(path.exists());
    }
    
    #[test]
    fn test_bb_available() {
        // This test will fail if bb is not installed
        if check_bb_available().is_ok() {
            println!("bb CLI is available");
        } else {
            println!("bb CLI not found - install with: bbup");
        }
    }
    
    #[test]
    fn test_witness_to_toml() {
        let witness = TransferWitness {
            root: Field::zero(),
            cm_out: Field::zero(),
            cm_change: Field::zero(),
            nf_note: Field::zero(),
            nf_tx: Field::zero(),
            gas_tip: Field::zero(),
            gas_fee_cap: Field::zero(),
            token_type: Field::zero(),
            pool_id: Field::zero(),
            tx_hash: [0u8; 32],
            tx_chain_id: 1,
            tx_nonce: 0,
            tx_to: [0u8; 20],
            tx_value: Field::zero(),
            tx_max_priority_fee: Field::zero(),
            tx_max_fee: Field::zero(),
            signature: [0u8; 64],
            pub_key_x: [0u8; 32],
            pub_key_y: [0u8; 32],
            note_in_rk_hash: Field::zero(),
            note_in_value: Field::zero(),
            note_in_token: Field::zero(),
            note_in_r: Field::zero(),
            note_out_rk_hash: Field::zero(),
            note_out_value: Field::zero(),
            note_out_r: Field::zero(),
            note_change_rk_hash: Field::zero(),
            note_change_value: Field::zero(),
            note_change_r: Field::zero(),
            merkle_path: vec![Field::zero(); 20],
            merkle_index: 0,
            nk: Field::zero(),
            recipient_pk_x: [0u8; 32],
            recipient_pk_y: [0u8; 32],
        };
        
        let toml = witness_to_toml(&witness);
        assert!(toml.contains("root = "));
        assert!(toml.contains("merkle_path = "));
        println!("Generated TOML:\n{}", toml);
    }
    
    #[test]
    #[ignore] // Run with: cargo test -p voidgun-prover -- --ignored test_verification_key
    fn test_verification_key() {
        if check_bb_available().is_err() {
            println!("Skipping test: bb CLI not available");
            return;
        }
        
        let vk = verification_key().expect("Failed to generate VK");
        assert!(!vk.is_empty(), "VK should not be empty");
        println!("Generated VK: {} bytes", vk.len());
    }
    
    #[test]
    #[ignore] // Run with: cargo test -p voidgun-prover -- --ignored test_solidity_verifier
    fn test_solidity_verifier() {
        if check_bb_available().is_err() {
            println!("Skipping test: bb CLI not available");
            return;
        }
        
        let sol = generate_solidity_verifier().expect("Failed to generate Solidity verifier");
        assert!(sol.contains("pragma solidity"), "Should contain Solidity pragma");
        assert!(sol.contains("HonkVerificationKey"), "Should contain verification key library");
        println!("Generated Solidity verifier: {} chars", sol.len());
    }
}
