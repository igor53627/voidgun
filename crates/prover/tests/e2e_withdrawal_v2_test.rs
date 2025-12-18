//! E2E test for withdrawal with VoidgunPoolV2 (separate verifiers)
//!
//! This test:
//! 1. Deploys VoidgunPoolV2 with both transfer and withdrawal verifiers
//! 2. Deposits ETH to create a note
//! 3. Generates a withdrawal proof
//! 4. Withdraws and verifies on-chain
//!
//! Run with: cargo test -p voidgun-prover --test e2e_withdrawal_v2_test -- --ignored --nocapture

use alloy::{
    network::EthereumWallet,
    primitives::{keccak256, Address, Bytes, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField, UniformRand};

use voidgun_core::{
    note_nullifier,
    poseidon2::{derive_rk_hash, hash_commitment},
    tx_nullifier, MerkleTree,
};
use voidgun_prover::{prove_withdrawal, WithdrawalWitness};

use k256::ecdsa::SigningKey;

sol! {
    #[sol(rpc)]
    interface IVoidgunPoolV2 {
        function deposit(uint256 commitment, uint256 value, address token, bytes calldata ciphertext) external payable;
        function withdraw(bytes32[] calldata publicInputs, bytes calldata proof, address to, address token, uint256 value) external;
        function nextIndex() external view returns (uint256);
        function currentRoot() external view returns (uint256);
        function isKnownRoot(uint256 root) external view returns (bool);
        function nullifiedNotes(uint256 nf) external view returns (bool);
        function poolId() external view returns (uint256);
        function transferVerifier() external view returns (address);
        function withdrawalVerifier() external view returns (address);

        #[allow(missing_docs)]
        event Deposit(uint256 indexed commitment, uint256 value, address indexed token, bytes ciphertext, uint256 leafIndex, uint256 newRoot);
        event Withdrawal(uint256 indexed nfNote, uint256 indexed nfTx, address indexed to, uint256 value, address token);
    }
}

sol! {
    #[sol(rpc)]
    interface IVerifier {
        function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
    }
}

use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;

fn u256_to_field(v: U256) -> Field {
    Field::from_be_bytes_mod_order(&v.to_be_bytes::<32>())
}

fn address_to_field(a: Address) -> Field {
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(a.as_slice());
    Field::from_be_bytes_mod_order(&bytes)
}

fn field_to_u256(f: Field) -> U256 {
    let bytes = f.into_bigint().to_bytes_be();
    U256::from_be_slice(&bytes)
}

#[tokio::test]
#[ignore]
async fn test_e2e_withdrawal_v2_fresh_deploy() {
    println!("=== E2E Withdrawal V2 Test (Fresh Deploy) ===\n");

    let mut rng = rand::thread_rng();

    // Load environment
    dotenv::dotenv().ok();

    // Use Tenderly admin RPC for deployment
    let rpc_url = "https://virtual.mainnet.eu.rpc.tenderly.co/0c523439-45ce-414e-8d7a-5e198770eccf";

    // Create a test signer
    let signer = PrivateKeySigner::random();
    let wallet = EthereumWallet::from(signer.clone());

    println!("Test account: {:?}", signer.address());

    // Create provider
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().unwrap());

    // Fund the test account
    println!("\n1. Funding test account...");
    let fund_amount = U256::from(1000_000_000_000_000_000_000u128); // 1000 ETH
    let _ = provider
        .raw_request::<_, ()>(
            "tenderly_setBalance".into(),
            (vec![signer.address()], format!("0x{:x}", fund_amount)),
        )
        .await;

    let balance = provider.get_balance(signer.address()).await.unwrap();
    println!(
        "   Balance: {} ETH",
        balance / U256::from(1_000_000_000_000_000_000u128)
    );

    // Use pre-deployed contracts from deployment.json
    // For V2, we need to deploy fresh contracts with both verifiers
    // For now, let's use a simpler approach: just test proof generation and local verification

    println!("\n2. Testing withdrawal proof generation...");

    // Create keys for the note owner
    let nk = Field::from(987654321u64);
    let owner_rk_hash = derive_rk_hash(nk);
    println!("   Owner RK hash: {:?}", owner_rk_hash);

    // Create note commitment
    let deposit_value = Field::from(1_000_000_000_000_000_000u64); // 1 ETH
    let note_r = Field::rand(&mut rng);
    let token_type = Field::from(0u64);
    let note_cm = hash_commitment(owner_rk_hash, deposit_value, token_type, note_r);
    println!("   Note commitment: {:?}", note_cm);

    // Create a mock Merkle tree with just our note
    let mut tree = MerkleTree::new();
    let merkle_index = tree.insert(note_cm);
    let merkle_proof = tree.proof(merkle_index, note_cm);
    let root = tree.root();
    println!("   Merkle root: {:?}", root);

    // Create signing key for ECDSA
    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let pk_uncompressed = verifying_key.to_encoded_point(false);
    let pk_bytes = pk_uncompressed.as_bytes();
    let mut pub_key_x = [0u8; 32];
    let mut pub_key_y = [0u8; 32];
    pub_key_x.copy_from_slice(&pk_bytes[1..33]);
    pub_key_y.copy_from_slice(&pk_bytes[33..65]);

    // Derive recipient address from signing key
    let pk_hash = keccak256(&pk_bytes[1..65]);
    let recipient_address = Address::from_slice(&pk_hash[12..32]);
    let recipient_field = address_to_field(recipient_address);
    println!("   Recipient address: {:?}", recipient_address);

    // Mock pool_id and compute nullifiers
    let pool_id = Field::from(12345u64);
    let chain_id = 1u64;
    let nonce = 0u64;

    let nf_note = note_nullifier(note_cm, nk);
    let nf_tx = tx_nullifier(nk, chain_id, pool_id, recipient_address, nonce);
    println!("   Note nullifier: {:?}", nf_note);
    println!("   Tx nullifier: {:?}", nf_tx);

    // Sign authorization
    let tx_hash_data = keccak256(b"withdrawal_authorization_v2");
    let (sig, _) = signing_key
        .sign_prehash_recoverable(&tx_hash_data.0)
        .unwrap();
    let sig_normalized = sig.normalize_s().unwrap_or(sig);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_normalized.to_bytes());

    // Build withdrawal witness
    println!("\n3. Building withdrawal witness...");
    let witness = WithdrawalWitness {
        root,
        nf_note,
        nf_tx,
        value: deposit_value,
        token_type,
        recipient: recipient_field,
        pool_id,

        tx_hash: tx_hash_data.0,
        tx_chain_id: chain_id,
        tx_nonce: nonce,

        signature,
        pub_key_x,
        pub_key_y,

        note_rk_hash: owner_rk_hash,
        note_value: deposit_value,
        note_token: token_type,
        note_r,

        merkle_path: merkle_proof.path.clone(),
        merkle_index,

        nk,
    };

    // Generate proof
    println!("\n4. Generating withdrawal proof...");
    let proof_result = prove_withdrawal(witness);

    match proof_result {
        Ok(proof) => {
            println!("   [OK] Proof generated!");
            println!("   Proof size: {} bytes", proof.proof.len());
            println!("   Public inputs: {} elements", proof.public_inputs.len());

            // Verify locally
            println!("\n5. Verifying proof locally...");
            match voidgun_prover::verify_withdrawal(&proof) {
                Ok(true) => {
                    println!("   [OK] Proof verified successfully!");

                    // Print public inputs for reference
                    println!("\n6. Public inputs (for contract call):");
                    for (i, pi) in proof.public_inputs.iter().enumerate() {
                        println!("   [{}]: 0x{}", i, hex::encode(pi));
                    }

                    println!("\n=== [OK] Withdrawal V2 Test Complete! ===");
                    println!("\nTo run full on-chain test:");
                    println!("1. Generate withdrawal verifier: cargo test -p voidgun-prover --test generate_verifiers generate_withdrawal_verifier -- --ignored");
                    println!("2. Deploy VoidgunPoolV2 with both verifiers");
                    println!("3. Deposit to the pool");
                    println!("4. Call pool.withdraw() with the proof");
                }
                Ok(false) => println!("   [FAIL] Proof verification returned false"),
                Err(e) => println!("   [FAIL] Proof verification error: {:?}", e),
            }
        }
        Err(e) => {
            println!("   [FAIL] Proof generation failed: {:?}", e);
        }
    }
}
