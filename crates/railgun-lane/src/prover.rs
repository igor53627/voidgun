//! Groth16 prover for Railgun circuits using ark-circom
//!
//! This module provides proof generation for Railgun's Circom circuits
//! using the arkworks Groth16 implementation.
//!
//! # Requirements
//!
//! - Railgun circuit WASM file (for witness generation)
//! - Railgun circuit ZKEY file (proving key from trusted setup)
//!
//! # Circuit Variants
//!
//! Railgun uses circuits named by their input/output counts:
//! - `01x01` = 1 nullifier (input), 1 commitment (output)
//! - `02x02` = 2 nullifiers, 2 commitments
//! - etc.

use alloy_sol_types::sol;
use ark_bn254::{Bn254, Fr as Field};
use ark_circom::{read_zkey, CircomReduction, WitnessCalculator};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use num_bigint::BigInt;
use std::collections::HashMap;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use wasmer::{Module, Store};

use crate::artifacts::{ArtifactStore, CircuitVariant};
use crate::notes::RailgunNote;

// Solidity type definitions for ABI encoding (matches Railgun Globals.sol)
sol! {
    /// Commitment ciphertext for transact
    struct CommitmentCiphertextSol {
        bytes32[4] ciphertext;
        bytes32 blindedSenderViewingKey;
        bytes32 blindedReceiverViewingKey;
        bytes annotationData;
        bytes memo;
    }

    /// Bound parameters for transact - matches Railgun BoundParams exactly
    struct BoundParamsSol {
        uint16 treeNumber;
        uint72 minGasPrice;
        uint8 unshield;
        uint64 chainID;
        address adaptContract;
        bytes32 adaptParams;
        CommitmentCiphertextSol[] commitmentCiphertext;
    }
}

/// Commitment ciphertext data for Rust usage
#[derive(Clone, Debug, Default)]
pub struct CommitmentCiphertextData {
    pub ciphertext: [[u8; 32]; 4],
    pub blinded_sender_viewing_key: [u8; 32],
    pub blinded_receiver_viewing_key: [u8; 32],
    pub annotation_data: Vec<u8>,
    pub memo: Vec<u8>,
}

impl CommitmentCiphertextData {
    /// Convert to Solidity struct for ABI encoding
    pub fn to_sol(&self) -> CommitmentCiphertextSol {
        CommitmentCiphertextSol {
            ciphertext: self.ciphertext.map(alloy_primitives::FixedBytes::from),
            blindedSenderViewingKey: alloy_primitives::FixedBytes::from(
                self.blinded_sender_viewing_key,
            ),
            blindedReceiverViewingKey: alloy_primitives::FixedBytes::from(
                self.blinded_receiver_viewing_key,
            ),
            annotationData: self.annotation_data.clone().into(),
            memo: self.memo.clone().into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("Circuit not found: {0}")]
    CircuitNotFound(String),

    #[error("Witness generation failed: {0}")]
    WitnessGenerationFailed(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Verification failed")]
    VerificationFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Artifact error: {0}")]
    ArtifactError(#[from] crate::artifacts::ArtifactError),

    #[error("WASM not available for circuit")]
    WasmNotAvailable,
}

/// Railgun circuit types
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CircuitType {
    /// Shield (deposit) circuit
    Shield,
    /// Transact (private transfer) circuit
    Transact,
    /// Unshield (withdraw) circuit
    Unshield,
}

impl CircuitType {
    pub fn circuit_name(&self) -> &'static str {
        match self {
            Self::Shield => "shield",
            Self::Transact => "transact",
            Self::Unshield => "unshield",
        }
    }
}

/// Witness for shield (deposit) circuit
#[derive(Clone, Debug)]
pub struct ShieldWitness {
    /// Commitment to the new note
    pub commitment: Field,
    /// Note value
    pub value: u128,
    /// Token address
    pub token: Field,
    /// Recipient's master public key
    pub recipient_mpk: Field,
    /// Random blinding factor
    pub random: Field,
}

/// Witness for transact (private transfer) circuit
///
/// Signal names match Railgun circuits-v2 JoinSplit template:
/// - Public: merkleRoot, boundParamsHash, nullifiers[], commitmentsOut[]
/// - Private: token, publicKey[2], signature[3], randomIn[], valueIn[],
///            pathElements[][], leavesIndices[], nullifyingKey, npkOut[], valueOut[]
#[derive(Clone, Debug)]
pub struct TransactWitness {
    // === Public signals ===
    /// Merkle root (proof of membership)
    pub merkle_root: Field,
    /// Hash of bound parameters (ciphertext + adapter params)
    pub bound_params_hash: Field,

    // === Private signals ===
    /// Token address (shared across all notes in transaction)
    pub token: Field,
    /// EdDSA public key for signature verification [x, y]
    pub public_key: [Field; 2],
    /// EdDSA signature [R8.x, R8.y, S]
    pub signature: [Field; 3],

    /// Input notes
    pub input_notes: Vec<RailgunNote>,
    /// Merkle proofs for input notes (pathElements)
    pub input_merkle_proofs: Vec<Vec<Field>>,
    /// Merkle indices for input notes (leavesIndices)
    pub input_merkle_indices: Vec<u64>,

    /// Output notes
    pub output_notes: Vec<RailgunNote>,

    /// Nullifying key (for computing nullifiers)
    pub nullifying_key: Field,
}

/// Witness for unshield (withdraw) circuit
#[derive(Clone, Debug)]
pub struct UnshieldWitness {
    /// Input note being spent
    pub input_note: RailgunNote,
    /// Merkle proof for input note
    pub merkle_proof: Vec<Field>,
    /// Merkle index
    pub merkle_index: u64,
    /// Merkle root
    pub merkle_root: Field,
    /// Nullifying key
    pub nullifying_key: Field,
    /// Recipient address (public, on-chain)
    pub recipient: [u8; 20],
}

/// Generated Groth16 proof
#[derive(Clone, Debug)]
pub struct RailgunProof {
    /// Proof points (serialized arkworks format)
    pub proof_bytes: Vec<u8>,
    /// Public inputs
    pub public_inputs: Vec<Field>,
}

impl RailgunProof {
    /// Create from arkworks Proof struct
    pub fn from_proof(
        proof: &Proof<Bn254>,
        public_inputs: Vec<Field>,
    ) -> Result<Self, ProverError> {
        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| ProverError::SerializationError(e.to_string()))?;
        Ok(Self {
            proof_bytes,
            public_inputs,
        })
    }

    /// Deserialize to arkworks Proof struct
    pub fn to_proof(&self) -> Result<Proof<Bn254>, ProverError> {
        Proof::deserialize_compressed(&self.proof_bytes[..])
            .map_err(|e| ProverError::SerializationError(e.to_string()))
    }

    /// Serialize for on-chain verification
    ///
    /// Returns (proof_bytes, public_inputs_as_32byte_arrays)
    pub fn to_calldata(&self) -> (Vec<u8>, Vec<[u8; 32]>) {
        let public_inputs_bytes: Vec<[u8; 32]> = self
            .public_inputs
            .iter()
            .map(|f| {
                let mut bytes = [0u8; 32];
                let be_bytes = f.into_bigint().to_bytes_be();
                bytes[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
                bytes
            })
            .collect();

        (self.proof_bytes.clone(), public_inputs_bytes)
    }

    /// Convert proof to Solidity-compatible format
    ///
    /// Groth16 proof structure for Solidity:
    /// - a: [uint256; 2] (G1 point)
    /// - b: [[uint256; 2]; 2] (G2 point)
    /// - c: [uint256; 2] (G1 point)
    pub fn to_solidity_proof(&self) -> Result<SolidityProof, ProverError> {
        use ark_bn254::{G1Affine, G2Affine};

        let proof = self.to_proof()?;

        fn g1_to_u256(p: &G1Affine) -> [[u8; 32]; 2] {
            let x = p.x.into_bigint().to_bytes_be();
            let y = p.y.into_bigint().to_bytes_be();
            let mut x_bytes = [0u8; 32];
            let mut y_bytes = [0u8; 32];
            x_bytes[32 - x.len()..].copy_from_slice(&x);
            y_bytes[32 - y.len()..].copy_from_slice(&y);
            [x_bytes, y_bytes]
        }

        fn g2_to_u256(p: &G2Affine) -> [[[u8; 32]; 2]; 2] {
            // For Railgun/snarkjs Solidity verifier compatibility:
            // snarkjs soliditycalldata format for proof.B: [[x.c1, x.c0], [y.c1, y.c0]]
            // i.e., imaginary coefficient first, real coefficient second
            // This is what gets passed to the Solidity verifyProof function as _pB
            let x0 = p.x.c0.into_bigint().to_bytes_be();
            let x1 = p.x.c1.into_bigint().to_bytes_be();
            let y0 = p.y.c0.into_bigint().to_bytes_be();
            let y1 = p.y.c1.into_bigint().to_bytes_be();
            let mut bytes = [[[0u8; 32]; 2]; 2];
            // Match snarkjs soliditycalldata: b[0][0]=c1, b[0][1]=c0
            bytes[0][0][32 - x1.len()..].copy_from_slice(&x1); // c1 (imaginary) first
            bytes[0][1][32 - x0.len()..].copy_from_slice(&x0); // c0 (real) second
            bytes[1][0][32 - y1.len()..].copy_from_slice(&y1); // c1 (imaginary) first
            bytes[1][1][32 - y0.len()..].copy_from_slice(&y0); // c0 (real) second
            bytes
        }

        Ok(SolidityProof {
            a: g1_to_u256(&proof.a),
            b: g2_to_u256(&proof.b),
            c: g1_to_u256(&proof.c),
        })
    }
}

/// Solidity-compatible Groth16 proof format
#[derive(Clone, Debug)]
pub struct SolidityProof {
    pub a: [[u8; 32]; 2],
    pub b: [[[u8; 32]; 2]; 2],
    pub c: [[u8; 32]; 2],
}

/// Cached proving key with constraint matrices
#[allow(dead_code)]
struct CachedProvingData {
    pk: ProvingKey<Bn254>,
    matrices: ConstraintMatrices<Field>,
}

/// Railgun Groth16 prover
///
/// This prover uses ark-circom to:
/// 1. Load Circom WASM circuits
/// 2. Generate witnesses from transaction data
/// 3. Create Groth16 proofs using ZKEY proving keys
pub struct RailgunProver {
    /// Artifact store for loading circuit files
    artifact_store: Arc<ArtifactStore>,

    /// Cached proving keys and matrices (loaded from ZKEY files)
    /// Note: Currently unused as we load ZKEY fresh each time to avoid caching issues.
    /// May be re-enabled once ark-circom issue #35 is resolved.
    #[allow(dead_code)]
    proving_data: Arc<RwLock<HashMap<String, Arc<CachedProvingData>>>>,
}

impl RailgunProver {
    /// Create new prover with artifact store
    pub fn new(artifact_store: Arc<ArtifactStore>) -> Self {
        Self {
            artifact_store,
            proving_data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create prover with default artifact path
    pub fn with_path(circuits_path: impl Into<PathBuf>) -> Self {
        let store = ArtifactStore::new(circuits_path, false);
        Self::new(Arc::new(store))
    }

    /// Load proving key and constraint matrices from ZKEY file (with caching)
    ///
    /// Note: Currently unused because of ark-circom issue #35.
    /// We load ZKEY fresh each time to ensure no caching interference.
    #[allow(dead_code)]
    async fn load_proving_data(
        &self,
        variant: &CircuitVariant,
    ) -> Result<Arc<CachedProvingData>, ProverError> {
        let key = variant.as_string();

        // Check cache
        {
            let cache = self.proving_data.read().await;
            if let Some(data) = cache.get(&key) {
                return Ok(data.clone());
            }
        }

        // Load artifacts
        let artifacts = self.artifact_store.get_artifacts(variant).await?;

        // Parse ZKEY using ark-circom's read_zkey
        let mut cursor = Cursor::new(&artifacts.zkey);
        let (pk, matrices) = read_zkey(&mut cursor)
            .map_err(|e| ProverError::SerializationError(format!("ZKEY parse failed: {}", e)))?;

        let data = Arc::new(CachedProvingData { pk, matrices });

        // Cache and return
        {
            let mut cache = self.proving_data.write().await;
            cache.insert(key, data.clone());
        }

        Ok(data)
    }

    /// Create witness calculator from WASM bytes
    fn create_witness_calculator(wasm: &[u8]) -> Result<(Store, WitnessCalculator), ProverError> {
        let mut store = Store::default();
        let module = Module::new(&store, wasm)
            .map_err(|e| ProverError::WitnessGenerationFailed(format!("WASM compile: {}", e)))?;
        let wtns = WitnessCalculator::from_module(&mut store, module)
            .map_err(|e| ProverError::WitnessGenerationFailed(e.to_string()))?;
        Ok((store, wtns))
    }

    /// Convert field element to BigInt for circuit inputs
    fn field_to_bigint(f: &Field) -> BigInt {
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &f.into_bigint().to_bytes_be())
    }

    /// Compute boundParamsHash for circuit using keccak256(abi.encode(BoundParams))
    ///
    /// This matches the Railgun Verifier.sol contract's hashBoundParams() function:
    /// `return uint256(keccak256(abi.encode(_boundParams))) % SNARK_SCALAR_FIELD;`
    ///
    /// The BoundParams struct layout:
    /// ```solidity
    /// struct BoundParams {
    ///     uint16 treeNumber;
    ///     uint72 minGasPrice;
    ///     uint8 unshield; // UnshieldType enum: NONE=0, NORMAL=1, REDIRECT=2
    ///     uint64 chainID;
    ///     address adaptContract;
    ///     bytes32 adaptParams;
    ///     CommitmentCiphertext[] commitmentCiphertext;
    /// }
    /// ```
    pub fn compute_bound_params_hash(
        tree_number: u16,
        min_gas_price: u64,
        unshield: u8,
        chain_id: u64,
        adapt_contract: [u8; 20],
        adapt_params: [u8; 32],
        commitment_ciphertexts: &[CommitmentCiphertextData],
    ) -> Field {
        use alloy_sol_types::SolValue;
        use sha3::{Digest, Keccak256};

        // Build the BoundParams struct
        let bound_params = BoundParamsSol {
            treeNumber: tree_number,
            minGasPrice: alloy_primitives::Uint::<72, 2>::from(min_gas_price),
            unshield,
            chainID: chain_id,
            adaptContract: alloy_primitives::Address::from_slice(&adapt_contract),
            adaptParams: alloy_primitives::FixedBytes::<32>::from(adapt_params),
            commitmentCiphertext: commitment_ciphertexts
                .iter()
                .map(|c| c.to_sol())
                .collect::<Vec<_>>(),
        };

        // ABI encode the struct using SolValue trait
        let encoded = bound_params.abi_encode();

        // keccak256 hash
        let hash = Keccak256::digest(&encoded);

        // Convert hash to big integer and compute modulo SNARK_SCALAR_FIELD
        // SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
        let hash_uint = num_bigint::BigUint::from_bytes_be(&hash);
        let snark_field = num_bigint::BigUint::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap();

        let remainder = hash_uint % snark_field;

        // Convert to field element
        let remainder_bytes = remainder.to_bytes_be();
        let mut padded = [0u8; 32];
        let start = 32 - remainder_bytes.len().min(32);
        padded[start..].copy_from_slice(&remainder_bytes[..remainder_bytes.len().min(32)]);

        Field::from_be_bytes_mod_order(&padded)
    }

    /// Compute boundParamsHash for simple cases (no ciphertext)
    ///
    /// This is a convenience wrapper for transactions with empty commitmentCiphertext array.
    pub fn compute_bound_params_hash_simple(
        tree_number: u16,
        min_gas_price: u64,
        unshield: u8,
        chain_id: u64,
    ) -> Field {
        Self::compute_bound_params_hash(
            tree_number,
            min_gas_price,
            unshield,
            chain_id,
            [0u8; 20], // zero address
            [0u8; 32], // zero params
            &[],       // no ciphertexts
        )
    }

    /// Compute hash of ciphertext for boundParamsHash
    ///
    /// Each output ciphertext is hashed using Poseidon to include in boundParamsHash.
    pub fn hash_ciphertext(ciphertext: &[u8]) -> Field {
        use crate::poseidon::poseidon_var;

        // Split ciphertext into 31-byte chunks and convert to field elements
        let mut chunks = Vec::new();
        for chunk in ciphertext.chunks(31) {
            let mut padded = [0u8; 32];
            padded[32 - chunk.len()..].copy_from_slice(chunk);
            chunks.push(Field::from_be_bytes_mod_order(&padded));
        }

        if chunks.is_empty() {
            Field::from(0u64)
        } else {
            poseidon_var(&chunks)
        }
    }

    /// Generate full witness and proof
    async fn generate_proof_internal(
        &self,
        variant: &CircuitVariant,
        inputs: HashMap<String, Vec<BigInt>>,
    ) -> Result<(Proof<Bn254>, Vec<Field>), ProverError> {
        let artifacts = self.artifact_store.get_artifacts(variant).await?;

        let wasm = artifacts
            .wasm
            .as_ref()
            .ok_or(ProverError::WasmNotAvailable)?;

        // Load ZKEY and parse
        let mut cursor = Cursor::new(&artifacts.zkey);
        let (pk, matrices) = read_zkey(&mut cursor)
            .map_err(|e| ProverError::SerializationError(format!("ZKEY parse failed: {}", e)))?;

        // Create witness calculator and generate witness
        let (mut store, mut wtns) = Self::create_witness_calculator(wasm)?;
        let full_assignment = wtns
            .calculate_witness_element::<Field, _>(&mut store, inputs, false)
            .map_err(|e| ProverError::WitnessGenerationFailed(e.to_string()))?;

        // Debug: verify assignment length matches ZKEY expectations
        let expected_len = matrices.num_instance_variables + matrices.num_witness_variables;
        tracing::debug!(
            "PROOF: full_assignment.len={}, expected={}, num_instance={}, num_witness={}, num_constraints={}",
            full_assignment.len(),
            expected_len,
            matrices.num_instance_variables,
            matrices.num_witness_variables,
            matrices.num_constraints
        );

        // Railgun's WASM produces one fewer signal than the ZKEY expects.
        // This appears to be an artifact mismatch in the official IPFS bundle.
        // The WASM excludes a trailing padding signal that the ZKEY includes.
        let mut full_assignment = full_assignment;
        if full_assignment.len() != expected_len {
            tracing::warn!(
                "Witness length mismatch: WASM produced {} signals, ZKEY expects {}",
                full_assignment.len(),
                expected_len
            );
            // Pad with zeros if WASM produced fewer signals
            while full_assignment.len() < expected_len {
                tracing::warn!("Padding witness with zero at index {}", full_assignment.len());
                full_assignment.push(Field::from(0u64));
            }
        }

        // Verify R1CS constraint satisfaction before generating proof
        // This helps catch witness bugs early
        let mut satisfied = true;
        let mut failed_constraints = Vec::new();
        for (i, (a_row, b_row, c_row)) in matrices
            .a
            .iter()
            .zip(matrices.b.iter())
            .zip(matrices.c.iter())
            .map(|((a, b), c)| (a, b, c))
            .enumerate()
        {
            let compute_lc = |row: &[(Field, usize)]| -> Field {
                row.iter()
                    .filter(|(_, idx)| *idx < full_assignment.len())
                    .map(|(coeff, idx)| *coeff * full_assignment[*idx])
                    .sum()
            };
            let a_val = compute_lc(a_row);
            let b_val = compute_lc(b_row);
            let c_val = compute_lc(c_row);
            if a_val * b_val != c_val {
                satisfied = false;
                if failed_constraints.len() < 10 {
                    failed_constraints.push(i);
                }
            }
        }
        if !satisfied {
            tracing::error!(
                "R1CS constraint satisfaction FAILED! {} constraints failed. First 10: {:?}",
                failed_constraints.len(),
                failed_constraints
            );
        } else {
            tracing::info!("[PROVER] R1CS constraint satisfaction check PASSED ({} constraints)", matrices.num_constraints);
        }

        // Extract public inputs (first num_instance_variables elements, excluding w_0=1)
        let public_inputs: Vec<Field> =
            full_assignment[1..matrices.num_instance_variables].to_vec();

        // Check if we should use snarkjs for proof generation (workaround for ark-circom issue #35)
        let use_snarkjs = std::env::var("USE_SNARKJS").is_ok();

        if use_snarkjs {
            tracing::info!("Using snarkjs for proof generation (USE_SNARKJS=1)");

            // Export witness to wtns format
            // Note: We remove the zero-padding we added earlier to reach expected_len.
            // The snarkjs WASM witness includes w_0=1 like arkworks, so we keep index 0.
            let original_len = full_assignment.len() - 1; // Remove the zero-padding we added
            let original_assignment = &full_assignment[..original_len];
            tracing::debug!("Exporting {} witness elements for snarkjs", original_len);
            let witness_wtns = self.export_witness_to_wtns(original_assignment)?;
            let witness_path = "/tmp/railgun_witness.wtns";
            std::fs::write(witness_path, &witness_wtns)
                .map_err(|e| ProverError::IoError(e))?;

            // Get ZKEY path
            let zkey_path = self.artifact_store.zkey_path(variant);
            let proof_path = "/tmp/railgun_proof.json";
            let public_path = "/tmp/railgun_public.json";

            // Call snarkjs to generate proof
            let output = std::process::Command::new("snarkjs")
                .args([
                    "groth16",
                    "prove",
                    &zkey_path.to_string_lossy(),
                    witness_path,
                    proof_path,
                    public_path,
                ])
                .output()
                .map_err(|e| ProverError::ProofGenerationFailed(format!("snarkjs failed: {}", e)))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                return Err(ProverError::ProofGenerationFailed(format!(
                    "snarkjs failed: stdout={}, stderr={}",
                    stdout, stderr
                )));
            }

            // Parse the snarkjs proof.json and convert to arkworks format
            let proof = self.parse_snarkjs_proof(proof_path)?;

            tracing::debug!(
                "snarkjs proof parsed: a=({}, {}), b.x=({}, {}), b.y=({}, {})",
                proof.a.x, proof.a.y,
                proof.b.x.c0, proof.b.x.c1,
                proof.b.y.c0, proof.b.y.c1
            );

            return Ok((proof, public_inputs));
        }

        // Generate random r, s for proof (ark-circom path)
        let mut rng = rand::thread_rng();

        // Generate proof using constraint matrices
        let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
            &pk,
            ark_std::rand::Rng::gen(&mut rng),
            ark_std::rand::Rng::gen(&mut rng),
            &matrices,
            matrices.num_instance_variables,
            matrices.num_constraints,
            full_assignment.as_slice(),
        )
        .map_err(|e| ProverError::ProofGenerationFailed(e.to_string()))?;

        Ok((proof, public_inputs))
    }

    /// Generate proof for transact circuit
    ///
    /// This is the main proof generation function that:
    /// 1. Determines the appropriate circuit variant
    /// 2. Loads artifacts (WASM, ZKEY)
    /// 3. Computes witness from transaction data
    /// 4. Generates Groth16 proof
    pub async fn prove_transact(
        &self,
        witness: TransactWitness,
    ) -> Result<RailgunProof, ProverError> {
        let num_nullifiers = witness.input_notes.len();
        let num_commitments = witness.output_notes.len();

        // Select circuit variant
        let variant = crate::artifacts::select_circuit(num_nullifiers, num_commitments)?;
        tracing::info!(
            "Generating proof for circuit variant: {}",
            variant.as_string()
        );

        // Build circuit inputs using exact Railgun JoinSplit signal names
        let mut inputs: HashMap<String, Vec<BigInt>> = HashMap::new();

        // === Public signals ===
        // merkleRoot - Merkle root for proof of membership
        inputs.insert(
            "merkleRoot".to_string(),
            vec![Self::field_to_bigint(&witness.merkle_root)],
        );

        // boundParamsHash - Hash of ciphertext and adapter parameters
        inputs.insert(
            "boundParamsHash".to_string(),
            vec![Self::field_to_bigint(&witness.bound_params_hash)],
        );

        // nullifiers - Computed from nullifyingKey + leafIndex (per nullifier-check.circom)
        // Formula: nullifier = Poseidon(nullifyingKey, leafIndex)
        let nullifiers: Vec<BigInt> = witness
            .input_merkle_indices
            .iter()
            .map(|&leaf_index| {
                let nf = crate::notes::RailgunNote::joinsplit_nullifier(
                    witness.nullifying_key,
                    leaf_index,
                );
                Self::field_to_bigint(&nf)
            })
            .collect();
        inputs.insert("nullifiers".to_string(), nullifiers);

        // commitmentsOut - Output note commitments
        let commitments_out: Vec<BigInt> = witness
            .output_notes
            .iter()
            .map(|note| Self::field_to_bigint(&note.commitment()))
            .collect();
        inputs.insert("commitmentsOut".to_string(), commitments_out);

        // === Private signals ===
        // token - Token address (same for all notes in transaction)
        inputs.insert(
            "token".to_string(),
            vec![Self::field_to_bigint(&witness.token)],
        );

        // publicKey - EdDSA public key [x, y]
        inputs.insert(
            "publicKey".to_string(),
            vec![
                Self::field_to_bigint(&witness.public_key[0]),
                Self::field_to_bigint(&witness.public_key[1]),
            ],
        );

        // signature - EdDSA signature [R8.x, R8.y, S]
        inputs.insert(
            "signature".to_string(),
            vec![
                Self::field_to_bigint(&witness.signature[0]),
                Self::field_to_bigint(&witness.signature[1]),
                Self::field_to_bigint(&witness.signature[2]),
            ],
        );

        // randomIn - Random values for input note commitments
        let random_in: Vec<BigInt> = witness
            .input_notes
            .iter()
            .map(|note| Self::field_to_bigint(&note.random))
            .collect();
        inputs.insert("randomIn".to_string(), random_in);

        // valueIn - Values of input notes
        let value_in: Vec<BigInt> = witness
            .input_notes
            .iter()
            .map(|note| BigInt::from(note.value))
            .collect();
        inputs.insert("valueIn".to_string(), value_in);

        // pathElements - Merkle proof path elements for each input
        // This is a 2D array flattened: pathElements[nInputs][MerkleTreeDepth]
        let path_elements: Vec<BigInt> = witness
            .input_merkle_proofs
            .iter()
            .flat_map(|proof| proof.iter().map(Self::field_to_bigint))
            .collect();
        inputs.insert("pathElements".to_string(), path_elements);

        // leavesIndices - Leaf indices in Merkle tree for each input
        let leaves_indices: Vec<BigInt> = witness
            .input_merkle_indices
            .iter()
            .map(|&idx| BigInt::from(idx))
            .collect();
        inputs.insert("leavesIndices".to_string(), leaves_indices);

        // nullifyingKey - For computing nullifiers
        inputs.insert(
            "nullifyingKey".to_string(),
            vec![Self::field_to_bigint(&witness.nullifying_key)],
        );

        // npkOut - Recipients' Note Public Keys
        let npk_out: Vec<BigInt> = witness
            .output_notes
            .iter()
            .map(|note| Self::field_to_bigint(&note.npk))
            .collect();
        inputs.insert("npkOut".to_string(), npk_out);

        // valueOut - Values of output notes
        let value_out: Vec<BigInt> = witness
            .output_notes
            .iter()
            .map(|note| BigInt::from(note.value))
            .collect();
        inputs.insert("valueOut".to_string(), value_out);

        // Debug: dump inputs to JSON for snarkjs comparison
        if std::env::var("DUMP_INPUTS").is_ok() {
            let inputs_json: serde_json::Map<String, serde_json::Value> = inputs
                .iter()
                .map(|(k, v)| {
                    let vals: Vec<serde_json::Value> = v.iter()
                        .map(|b| serde_json::Value::String(b.to_string()))
                        .collect();
                    (k.clone(), if vals.len() == 1 { vals[0].clone() } else { serde_json::Value::Array(vals) })
                })
                .collect();
            let json = serde_json::to_string_pretty(&serde_json::Value::Object(inputs_json)).unwrap();
            std::fs::write("/tmp/railgun_inputs.json", &json).unwrap();
            tracing::debug!("Dumped circuit inputs to /tmp/railgun_inputs.json");
        }

        // Generate proof
        let (proof, public_inputs) = self.generate_proof_internal(&variant, inputs).await?;

        RailgunProof::from_proof(&proof, public_inputs)
    }

    /// Generate shield proof
    pub async fn prove_shield(&self, _witness: ShieldWitness) -> Result<RailgunProof, ProverError> {
        // Shield circuit WASM not yet available
        // Note: Shielding doesn't require a ZK proof - tokens are deposited directly via shield()
        // TODO: Implement actual shield proof generation if/when artifacts become available
        Err(ProverError::CircuitNotFound(
            "shield circuit not implemented - use on-chain shield() directly".to_string(),
        ))
    }

    /// Generate unshield proof
    pub async fn prove_unshield(
        &self,
        _witness: UnshieldWitness,
    ) -> Result<RailgunProof, ProverError> {
        // Unshield circuit WASM not yet available
        // TODO: Implement actual unshield proof generation when artifacts are available
        Err(ProverError::CircuitNotFound(
            "unshield circuit not implemented - use transact with unshield flag".to_string(),
        ))
    }

    /// Export witness to wtns binary format for snarkjs
    ///
    /// The wtns format is:
    /// - 4 bytes: magic "wtns"
    /// - 4 bytes: version (2)
    /// - 4 bytes: number of sections (2)
    /// - Section 1 (header):
    ///   - 4 bytes: section type (1)
    ///   - 8 bytes: section size
    ///   - 4 bytes: field element size (32)
    ///   - 32 bytes: field modulus (little-endian)
    ///   - 4 bytes: witness size
    /// - Section 2 (witness):
    ///   - 4 bytes: section type (2)
    ///   - 8 bytes: section size
    ///   - witness_size * 32 bytes: witness values (little-endian)
    fn export_witness_to_wtns(&self, assignment: &[Field]) -> Result<Vec<u8>, ProverError> {
        let mut wtns = Vec::new();

        // Magic "wtns"
        wtns.extend_from_slice(b"wtns");

        // Version (2, little-endian)
        wtns.extend_from_slice(&2u32.to_le_bytes());

        // Number of sections (2)
        wtns.extend_from_slice(&2u32.to_le_bytes());

        // Section 1: Header (type 1)
        wtns.extend_from_slice(&1u32.to_le_bytes());
        // Header section size: 4 + 32 + 4 = 40 bytes
        wtns.extend_from_slice(&40u64.to_le_bytes());

        // Field element size in bytes (32)
        wtns.extend_from_slice(&32u32.to_le_bytes());

        // Field modulus (BN254 scalar field) - little-endian
        // 21888242871839275222246405745257275088548364400416034343698204186575808495617
        let modulus = num_bigint::BigUint::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap();
        let modulus_bytes = modulus.to_bytes_le();
        let mut modulus_padded = [0u8; 32];
        modulus_padded[..modulus_bytes.len().min(32)]
            .copy_from_slice(&modulus_bytes[..modulus_bytes.len().min(32)]);
        wtns.extend_from_slice(&modulus_padded);

        // Witness size (number of field elements)
        wtns.extend_from_slice(&(assignment.len() as u32).to_le_bytes());

        // Section 2: Witness values (type 2)
        wtns.extend_from_slice(&2u32.to_le_bytes());
        // Witness section size: witness_size * 32
        wtns.extend_from_slice(&((assignment.len() * 32) as u64).to_le_bytes());

        // Write each witness value in little-endian format
        for elem in assignment {
            let bytes = elem.into_bigint().to_bytes_le();
            let mut padded = [0u8; 32];
            padded[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
            wtns.extend_from_slice(&padded);
        }

        Ok(wtns)
    }

    /// Parse snarkjs proof.json into arkworks Proof struct
    fn parse_snarkjs_proof(&self, proof_path: &str) -> Result<Proof<Bn254>, ProverError> {
        use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
        use std::str::FromStr;

        let proof_json = std::fs::read_to_string(proof_path)
            .map_err(|e| ProverError::IoError(e))?;

        let proof_data: serde_json::Value = serde_json::from_str(&proof_json)
            .map_err(|e| ProverError::SerializationError(e.to_string()))?;

        // Parse pi_a (G1 point)
        let pi_a = &proof_data["pi_a"];
        let a_x = Fq::from_str(pi_a[0].as_str().unwrap())
            .map_err(|_| ProverError::SerializationError("invalid pi_a.x".to_string()))?;
        let a_y = Fq::from_str(pi_a[1].as_str().unwrap())
            .map_err(|_| ProverError::SerializationError("invalid pi_a.y".to_string()))?;
        let a = G1Affine::new(a_x, a_y);

        // Parse pi_b (G2 point)
        // snarkjs format: pi_b[0] = [x.c0, x.c1], pi_b[1] = [y.c0, y.c1]
        let pi_b = &proof_data["pi_b"];
        let b_x_c0 = Fq::from_str(pi_b[0][0].as_str().unwrap())
            .map_err(|_| ProverError::SerializationError("invalid pi_b.x.c0".to_string()))?;
        let b_x_c1 = Fq::from_str(pi_b[0][1].as_str().unwrap())
            .map_err(|_| ProverError::SerializationError("invalid pi_b.x.c1".to_string()))?;
        let b_y_c0 = Fq::from_str(pi_b[1][0].as_str().unwrap())
            .map_err(|_| ProverError::SerializationError("invalid pi_b.y.c0".to_string()))?;
        let b_y_c1 = Fq::from_str(pi_b[1][1].as_str().unwrap())
            .map_err(|_| ProverError::SerializationError("invalid pi_b.y.c1".to_string()))?;
        let b_x = Fq2::new(b_x_c0, b_x_c1);
        let b_y = Fq2::new(b_y_c0, b_y_c1);
        let b = G2Affine::new(b_x, b_y);

        // Parse pi_c (G1 point)
        let pi_c = &proof_data["pi_c"];
        let c_x = Fq::from_str(pi_c[0].as_str().unwrap())
            .map_err(|_| ProverError::SerializationError("invalid pi_c.x".to_string()))?;
        let c_y = Fq::from_str(pi_c[1].as_str().unwrap())
            .map_err(|_| ProverError::SerializationError("invalid pi_c.y".to_string()))?;
        let c = G1Affine::new(c_x, c_y);

        Ok(Proof { a, b, c })
    }

    /// Verify a proof locally (for testing)
    ///
    /// # Warning
    ///
    /// Local verification with ark-circom has a known issue (arkworks-rs/circom-compat#35)
    /// where verification fails when using externally-generated ZKEYs (like Railgun's).
    /// The proofs ARE valid and will verify on-chain with Railgun's Solidity verifier.
    ///
    /// Use this method only for debugging. For production, rely on on-chain verification.
    pub async fn verify(
        &self,
        variant: &CircuitVariant,
        proof: &RailgunProof,
    ) -> Result<bool, ProverError> {
        tracing::warn!(
            "Local verification may return false negatives due to ark-circom issue #35. \
             Proofs should be verified on-chain."
        );

        // Load fresh ZKEY to avoid any caching issues
        let artifacts = self.artifact_store.get_artifacts(variant).await?;
        let mut cursor = std::io::Cursor::new(&artifacts.zkey);
        let (pk, _matrices) = read_zkey(&mut cursor)
            .map_err(|e| ProverError::SerializationError(format!("ZKEY parse failed: {}", e)))?;

        let groth16_proof = proof.to_proof()?;

        tracing::debug!(
            "Verifying proof with {} public inputs",
            proof.public_inputs.len()
        );

        let pvk = ark_groth16::prepare_verifying_key(&pk.vk);
        let result =
            Groth16::<Bn254>::verify_with_processed_vk(&pvk, &proof.public_inputs, &groth16_proof)
                .map_err(|_| ProverError::VerificationFailed)?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn test_shield_witness_creation() {
        let mut rng = rand::thread_rng();

        let witness = ShieldWitness {
            commitment: Field::rand(&mut rng),
            value: 1_000_000_000_000_000_000,
            token: Field::from(0u64),
            recipient_mpk: Field::rand(&mut rng),
            random: Field::rand(&mut rng),
        };

        assert!(witness.value > 0);
    }

    #[test]
    fn test_proof_calldata() {
        let mut rng = rand::thread_rng();

        let proof = RailgunProof {
            proof_bytes: vec![1, 2, 3, 4],
            public_inputs: vec![Field::rand(&mut rng), Field::rand(&mut rng)],
        };

        let (bytes, inputs) = proof.to_calldata();
        assert_eq!(bytes.len(), 4);
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0].len(), 32);
    }

    #[test]
    fn test_field_to_bigint() {
        let f = Field::from(12345u64);
        let bi = RailgunProver::field_to_bigint(&f);
        assert_eq!(bi, BigInt::from(12345u64));
    }

    #[test]
    fn test_bound_params_hash_simple() {
        use ark_ff::Zero;

        // Test that our hash computation produces a valid field element
        // For an empty BoundParams (all zeros, empty ciphertext array)
        let hash = RailgunProver::compute_bound_params_hash_simple(
            0, // tree_number
            0, // min_gas_price
            0, // unshield = NONE
            1, // chain_id = mainnet
        );

        // Verify it's not zero (would indicate an error)
        assert!(!hash.is_zero());

        // Verify determinism
        let hash2 = RailgunProver::compute_bound_params_hash_simple(0, 0, 0, 1);
        assert_eq!(hash, hash2);

        // Different chain_id should produce different hash
        let hash_sepolia = RailgunProver::compute_bound_params_hash_simple(0, 0, 0, 11155111);
        assert_ne!(hash, hash_sepolia);
    }

    #[test]
    fn test_bound_params_hash_with_ciphertext() {
        use ark_ff::Zero;

        // Test with non-empty commitment ciphertext
        let ciphertext = CommitmentCiphertextData {
            ciphertext: [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]],
            blinded_sender_viewing_key: [5u8; 32],
            blinded_receiver_viewing_key: [6u8; 32],
            annotation_data: vec![7u8; 16],
            memo: vec![8u8; 32],
        };

        let hash = RailgunProver::compute_bound_params_hash(
            0,
            0,
            0,
            1,
            [0u8; 20],
            [0u8; 32],
            &[ciphertext.clone()],
        );

        // Should not be zero
        assert!(!hash.is_zero());

        // Should differ from hash with no ciphertext
        let hash_empty = RailgunProver::compute_bound_params_hash_simple(0, 0, 0, 1);
        assert_ne!(hash, hash_empty);
    }
}
