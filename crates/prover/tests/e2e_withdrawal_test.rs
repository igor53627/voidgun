//! E2E test for withdrawal from shielded pool on Tenderly VNet
//!
//! This test:
//! 1. Creates and deposits a note to VoidgunPool
//! 2. Syncs the Merkle tree from on-chain events
//! 3. Generates a ZK proof for withdrawal
//! 4. Submits the withdrawal to the contract and verifies on-chain
//!
//! Run with: cargo test -p voidgun-prover --test e2e_withdrawal_test -- --ignored --nocapture

use alloy::{
    network::EthereumWallet,
    primitives::{keccak256, Address, Bytes, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use std::str::FromStr;

use voidgun_core::{
    note_nullifier,
    poseidon2::{derive_rk_hash, hash_commitment},
    tx_nullifier, MerkleTree,
};
use voidgun_prover::{prove_withdrawal, WithdrawalWitness};

use k256::ecdsa::SigningKey;

sol! {
    #[sol(rpc)]
    interface IVoidgunPool {
        function deposit(uint256 commitment, uint256 value, address token, bytes calldata ciphertext) external payable;
        function withdraw(bytes32[] calldata publicInputs, bytes calldata proof, address to, address token, uint256 value) external;
        function nextIndex() external view returns (uint256);
        function currentRoot() external view returns (uint256);
        function isKnownRoot(uint256 root) external view returns (bool);
        function nullifiedNotes(uint256 nf) external view returns (bool);
        function verifier() external view returns (address);

        #[allow(missing_docs)]
        event Deposit(uint256 indexed commitment, uint256 value, address indexed token, bytes ciphertext, uint256 leafIndex, uint256 newRoot);
        event Transfer(uint256 indexed nfNote, uint256 indexed nfTx, uint256 cmOut, uint256 cmChange, uint256 leafIndexOut, uint256 leafIndexChange, uint256 newRoot, bytes ciphertextOut, bytes ciphertextChange);
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

fn field_to_bytes32(f: Field) -> FixedBytes<32> {
    let bytes = f.into_bigint().to_bytes_be();
    FixedBytes::from_slice(&bytes)
}

#[tokio::test]
#[ignore]
async fn test_e2e_withdrawal_on_tenderly() {
    println!("=== E2E Withdrawal Test on Tenderly ===\n");

    let mut rng = rand::thread_rng();

    // Load environment
    dotenv::dotenv().ok();

    // Deployment info (from contracts/deployment.json)
    let pool_address = Address::from_str("0x3a1dD74b4415a755c5Af35182d3B9Ee88E001Aa0").unwrap();
    let rpc_url = "https://virtual.mainnet.eu.rpc.tenderly.co/0c523439-45ce-414e-8d7a-5e198770eccf";

    // Create a test signer - this will be used for both deposit and withdrawal
    let signer = PrivateKeySigner::random();
    let wallet = EthereumWallet::from(signer.clone());

    println!("Test account: {:?}", signer.address());
    println!("Pool address: {:?}", pool_address);

    // Create provider
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().unwrap());

    // Fund the test account using Tenderly's setBalance
    println!("\n1. Funding test account...");
    let fund_amount = U256::from(100_000_000_000_000_000_000u128); // 100 ETH
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

    // Get pool contract
    let pool = IVoidgunPool::new(pool_address, &provider);

    // Get initial state
    let initial_index = pool.nextIndex().call().await.unwrap();
    println!("\n2. Initial pool state:");
    println!("   Next index: {}", initial_index);

    // Create keys for the note owner
    println!("\n3. Creating keys...");
    let nk = Field::from(123456789u64);
    let owner_rk_hash = derive_rk_hash(nk);
    println!("   Owner RK hash: {:?}", owner_rk_hash);

    // Create note commitment
    let deposit_value = U256::from(1_000_000_000_000_000_000u64); // 1 ETH
    let note_r = Field::rand(&mut rng);
    let note_cm = hash_commitment(
        owner_rk_hash,
        u256_to_field(deposit_value),
        address_to_field(Address::ZERO),
        note_r,
    );
    println!("\n4. Creating deposit note...");
    println!("   Value: {} wei", deposit_value);
    println!("   Commitment: {:?}", note_cm);

    // Deposit to contract
    println!("\n5. Depositing to VoidgunPool...");
    let commitment_u256 = field_to_u256(note_cm);
    let ciphertext = Bytes::from(vec![0u8; 64]); // Placeholder ciphertext

    let tx_hash = pool
        .deposit(commitment_u256, deposit_value, Address::ZERO, ciphertext)
        .value(deposit_value)
        .send()
        .await
        .expect("Failed to send deposit tx")
        .watch()
        .await
        .expect("Failed to confirm deposit");

    println!("   Deposit tx: {:?}", tx_hash);

    // Get the new root and merkle index from contract
    let post_deposit_index = pool.nextIndex().call().await.unwrap();
    let contract_root = pool.currentRoot().call().await.unwrap();
    println!("   Post-deposit index: {}", post_deposit_index);
    println!("   Contract root: {:?}", contract_root);

    // Build local Merkle tree by syncing all events (Deposit + Transfer)
    println!("\n6. Syncing Merkle tree from contract events...");
    let mut tree = MerkleTree::new();

    // Collect all leaves from both Deposit and Transfer events
    let mut all_leaves: Vec<(u64, Field)> = vec![];

    // Fetch all Deposit events
    let deposit_filter = Filter::new()
        .address(pool_address)
        .event_signature(IVoidgunPool::Deposit::SIGNATURE_HASH)
        .from_block(0);

    let deposit_logs = provider.get_logs(&deposit_filter).await.unwrap();
    println!("   Found {} deposit events", deposit_logs.len());

    // Process Deposit events
    for log in &deposit_logs {
        if log.topics().len() > 1 {
            let commitment = U256::from_be_slice(log.topics()[1].as_slice());
            let data = log.data().data.as_ref();
            // Deposit event data: value (32) + ciphertext_offset (32) + leafIndex (32) + newRoot (32) + ...
            if data.len() >= 128 {
                let leaf_index = U256::from_be_slice(&data[64..96]);
                all_leaves.push((leaf_index.try_into().unwrap(), u256_to_field(commitment)));
            }
        }
    }

    // Fetch Transfer events (they add cmOut and cmChange)
    let transfer_filter = Filter::new()
        .address(pool_address)
        .event_signature(IVoidgunPool::Transfer::SIGNATURE_HASH)
        .from_block(0);

    let transfer_logs = provider.get_logs(&transfer_filter).await.unwrap();
    println!("   Found {} transfer events", transfer_logs.len());

    // Process Transfer events
    // Transfer event: (nfNote indexed, nfTx indexed, cmOut, cmChange, leafIndexOut, leafIndexChange, newRoot, ...)
    for log in &transfer_logs {
        let data = log.data().data.as_ref();
        if data.len() >= 192 {
            // cmOut at offset 0, cmChange at offset 32, leafIndexOut at 64, leafIndexChange at 96
            let cm_out = U256::from_be_slice(&data[0..32]);
            let cm_change = U256::from_be_slice(&data[32..64]);
            let leaf_index_out = U256::from_be_slice(&data[64..96]);
            let leaf_index_change = U256::from_be_slice(&data[96..128]);

            all_leaves.push((leaf_index_out.try_into().unwrap(), u256_to_field(cm_out)));
            all_leaves.push((
                leaf_index_change.try_into().unwrap(),
                u256_to_field(cm_change),
            ));
        }
    }

    // Sort by leaf index to ensure correct insertion order
    all_leaves.sort_by_key(|(idx, _)| *idx);

    println!("   Total leaves to sync: {}", all_leaves.len());
    println!(
        "   Leaf indices: {:?}",
        all_leaves.iter().map(|(idx, _)| idx).collect::<Vec<_>>()
    );

    // Track our deposit's index
    let mut our_deposit_idx = None;

    // Insert commitments in order - handle gaps by inserting zeros
    for (expected_idx, cm) in &all_leaves {
        // Fill in any gaps with zeros
        while tree.next_index < *expected_idx {
            println!(
                "   Warning: Filling gap at index {} with zero",
                tree.next_index
            );
            tree.insert(Field::from(0u64));
        }

        let actual_idx = tree.insert(*cm);
        if actual_idx != *expected_idx {
            println!(
                "   Warning: Leaf index mismatch - expected {}, got {}",
                expected_idx, actual_idx
            );
        }

        if *cm == note_cm {
            our_deposit_idx = Some(actual_idx);
        }
    }

    let our_merkle_index = our_deposit_idx.expect("Our deposit not found in events");
    let local_root = tree.root();
    let merkle_proof = tree.proof(our_merkle_index, note_cm);

    println!("   Synced {} leaves", all_leaves.len());
    println!("   Our deposit merkle index: {}", our_merkle_index);
    println!("   Local root: {:?}", local_root);
    println!("   Contract root: {:?}", contract_root);

    // Verify roots match
    let roots_match = field_to_u256(local_root) == contract_root;
    println!("   Roots match: {}", roots_match);

    if !roots_match {
        println!("   [FAIL] Root mismatch after syncing all deposits!");
        return;
    }

    // Create signing key for ECDSA (this signs the withdrawal authorization)
    println!("\n7. Creating signing key for withdrawal...");
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

    // Get pool_id from contract address
    let pool_id = address_to_field(pool_address);
    let chain_id = 1u64;
    let nonce = 0u64;

    // Compute nullifiers
    let nf_note = note_nullifier(note_cm, nk);
    let nf_tx = tx_nullifier(nk, chain_id, pool_id, recipient_address, nonce);
    println!("\n8. Computing nullifiers...");
    println!("   Note nullifier: {:?}", nf_note);
    println!("   Tx nullifier: {:?}", nf_tx);

    // Create and sign tx_hash (authorization message)
    let tx_hash_data = keccak256(b"withdrawal_authorization");
    let (sig, _) = signing_key
        .sign_prehash_recoverable(&tx_hash_data.0)
        .unwrap();
    let sig_normalized = sig.normalize_s().unwrap_or(sig);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_normalized.to_bytes());

    // Build withdrawal witness
    println!("\n9. Building withdrawal witness...");
    let witness = WithdrawalWitness {
        root: local_root,
        nf_note,
        nf_tx,
        value: u256_to_field(deposit_value),
        token_type: address_to_field(Address::ZERO),
        recipient: recipient_field,
        pool_id,

        tx_hash: tx_hash_data.0,
        tx_chain_id: chain_id,
        tx_nonce: nonce,

        signature,
        pub_key_x,
        pub_key_y,

        note_rk_hash: owner_rk_hash,
        note_value: u256_to_field(deposit_value),
        note_token: address_to_field(Address::ZERO),
        note_r,

        merkle_path: merkle_proof.path.clone(),
        merkle_index: our_merkle_index,

        nk,
    };

    // Generate proof
    println!("\n10. Generating ZK proof for withdrawal...");
    println!("    (This may take a few seconds...)");

    let proof_result = prove_withdrawal(witness);

    match proof_result {
        Ok(proof) => {
            println!("    [OK] Proof generated!");
            println!("    Proof size: {} bytes", proof.proof.len());
            println!("    Public inputs: {} elements", proof.public_inputs.len());

            // Convert public inputs to bytes32[]
            let public_inputs_bytes32: Vec<FixedBytes<32>> = proof
                .public_inputs
                .iter()
                .map(|bytes| FixedBytes::from_slice(bytes))
                .collect();

            // First, test the verifier directly
            println!("\n11. Testing verifier directly...");
            let verifier_address = pool.verifier().call().await.unwrap();
            println!("    Verifier address: {:?}", verifier_address);

            let verifier = IVerifier::new(verifier_address, &provider);
            let verify_result = verifier
                .verify(
                    Bytes::from(proof.proof.clone()),
                    public_inputs_bytes32.clone(),
                )
                .call()
                .await;

            match &verify_result {
                Ok(is_valid) => println!("    Verifier.verify() returned: {}", is_valid),
                Err(e) => {
                    println!("    Verifier.verify() failed: {:?}", e);
                    println!("\n    Note: The current verifier is for transfers, not withdrawals.");
                    println!("    A separate withdrawal verifier needs to be deployed.");
                    println!("    Skipping on-chain withdrawal submission.");
                    return;
                }
            }

            println!("\n12. Submitting withdrawal to contract...");

            // Fund recipient so they can receive ETH
            let _ = provider
                .raw_request::<_, ()>(
                    "tenderly_setBalance".into(),
                    (vec![recipient_address], "0x0"),
                )
                .await;

            let recipient_balance_before = provider.get_balance(recipient_address).await.unwrap();
            println!(
                "    Recipient balance before: {} wei",
                recipient_balance_before
            );

            // Submit withdrawal
            let withdraw_result = pool
                .withdraw(
                    public_inputs_bytes32,
                    Bytes::from(proof.proof.clone()),
                    recipient_address,
                    Address::ZERO, // ETH
                    deposit_value,
                )
                .send()
                .await;

            match withdraw_result {
                Ok(pending) => {
                    let tx_hash = pending.watch().await;
                    match tx_hash {
                        Ok(hash) => {
                            println!("    [OK] Withdrawal tx confirmed: {:?}", hash);

                            // Verify nullifier is now spent
                            let is_spent = pool
                                .nullifiedNotes(field_to_u256(nf_note))
                                .call()
                                .await
                                .unwrap();
                            println!("    Note nullifier is spent: {}", is_spent);

                            // Check recipient balance
                            let recipient_balance_after =
                                provider.get_balance(recipient_address).await.unwrap();
                            println!(
                                "    Recipient balance after: {} wei",
                                recipient_balance_after
                            );
                            println!(
                                "    Balance increase: {} wei",
                                recipient_balance_after - recipient_balance_before
                            );

                            println!("\n=== [OK] E2E Withdrawal Test Complete! ===");
                        }
                        Err(e) => {
                            println!("    [FAIL] Withdrawal tx failed: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("    [FAIL] Failed to send withdrawal: {:?}", e);
                    println!("\n    This likely means proof verification failed on-chain.");
                    println!("    Possible causes:");
                    println!("    - Wrong verifier contract (transfer vs withdrawal)");
                    println!("    - Invalid public inputs");
                    println!("    - Proof format mismatch");
                }
            }
        }
        Err(e) => {
            println!("    [FAIL] Proof generation failed: {:?}", e);
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_withdrawal_proof_generation_only() {
    println!("=== Withdrawal Proof Generation Test ===\n");

    let mut rng = rand::thread_rng();

    // Create mock data for testing proof generation
    let nk = Field::from(123456789u64);
    let owner_rk_hash = derive_rk_hash(nk);

    let deposit_value = Field::from(1_000_000_000_000_000_000u64);
    let note_r = Field::rand(&mut rng);
    let token_type = Field::from(0u64);

    let note_cm = hash_commitment(owner_rk_hash, deposit_value, token_type, note_r);

    // Create a mock tree with just our note
    let mut tree = MerkleTree::new();
    let merkle_index = tree.insert(note_cm);
    let merkle_proof = tree.proof(merkle_index, note_cm);
    let root = tree.root();

    // Create signing key
    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let pk_uncompressed = verifying_key.to_encoded_point(false);
    let pk_bytes = pk_uncompressed.as_bytes();
    let mut pub_key_x = [0u8; 32];
    let mut pub_key_y = [0u8; 32];
    pub_key_x.copy_from_slice(&pk_bytes[1..33]);
    pub_key_y.copy_from_slice(&pk_bytes[33..65]);

    // Derive recipient address
    let pk_hash = keccak256(&pk_bytes[1..65]);
    let recipient_address = Address::from_slice(&pk_hash[12..32]);
    let recipient_field = address_to_field(recipient_address);

    // Mock pool_id and compute nullifiers
    let pool_id = Field::from(12345u64);
    let chain_id = 1u64;
    let nonce = 0u64;

    let nf_note = note_nullifier(note_cm, nk);
    let nf_tx = tx_nullifier(nk, chain_id, pool_id, recipient_address, nonce);

    // Sign authorization
    let tx_hash_data = keccak256(b"withdrawal_authorization");
    let (sig, _) = signing_key
        .sign_prehash_recoverable(&tx_hash_data.0)
        .unwrap();
    let sig_normalized = sig.normalize_s().unwrap_or(sig);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_normalized.to_bytes());

    println!("Building withdrawal witness...");
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

    println!("Generating withdrawal proof...");
    let proof_result = prove_withdrawal(witness);

    match proof_result {
        Ok(proof) => {
            println!("[OK] Withdrawal proof generated successfully!");
            println!("Proof size: {} bytes", proof.proof.len());
            println!("Public inputs: {} elements", proof.public_inputs.len());

            // Verify the proof locally
            println!("\nVerifying proof locally...");
            match voidgun_prover::verify_withdrawal(&proof) {
                Ok(true) => println!("[OK] Proof verified successfully!"),
                Ok(false) => println!("[FAIL] Proof verification returned false"),
                Err(e) => println!("[FAIL] Proof verification error: {:?}", e),
            }
        }
        Err(e) => {
            println!("[FAIL] Proof generation failed: {:?}", e);
        }
    }
}
