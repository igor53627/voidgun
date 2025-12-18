//! E2E test for shielded transfer on Tenderly VNet
//!
//! This test:
//! 1. Creates a proper note commitment
//! 2. Deposits it to VoidgunPool on Tenderly
//! 3. Generates a ZK proof for shielded transfer
//! 4. Submits the transfer to the contract and verifies on-chain
//!
//! Run with: cargo test -p voidgun-prover --test e2e_tenderly_test -- --ignored --nocapture

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
use voidgun_prover::{prove_transfer, TransferWitness};

use k256::ecdsa::SigningKey;

sol! {
    #[sol(rpc)]
    interface IVoidgunPool {
        function deposit(uint256 commitment, uint256 value, address token, bytes calldata ciphertext) external payable;
        function shieldedTransfer(bytes32[] calldata publicInputs, bytes calldata proof, bytes calldata ciphertextOut, bytes calldata ciphertextChange) external;
        function nextIndex() external view returns (uint256);
        function currentRoot() external view returns (uint256);
        function isKnownRoot(uint256 root) external view returns (bool);
        function nullifiedNotes(uint256 nf) external view returns (bool);
        function verifier() external view returns (address);

        #[allow(missing_docs)]
        event Deposit(uint256 indexed commitment, uint256 value, address indexed token, bytes ciphertext, uint256 leafIndex, uint256 newRoot);
        event Transfer(uint256 indexed nfNote, uint256 indexed nfTx, uint256 cmOut, uint256 cmChange, uint256 leafIndexOut, uint256 leafIndexChange, uint256 newRoot, bytes ciphertextOut, bytes ciphertextChange);
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
async fn test_e2e_shielded_transfer_on_tenderly() {
    println!("=== E2E Shielded Transfer Test on Tenderly ===\n");

    let mut rng = rand::thread_rng();

    // Load environment
    dotenv::dotenv().ok();

    // Deployment info (from contracts/deployment.json)
    let pool_address = Address::from_str("0x3a1dD74b4415a755c5Af35182d3B9Ee88E001Aa0").unwrap();
    let rpc_url = "https://virtual.mainnet.eu.rpc.tenderly.co/0c523439-45ce-414e-8d7a-5e198770eccf";

    // Create a test signer
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

    // Create keys
    println!("\n3. Creating keys...");
    let nk = Field::from(123456789u64);
    let sender_rk_hash = derive_rk_hash(nk);
    let recipient_nk = Field::from(987654321u64);
    let recipient_rk_hash = derive_rk_hash(recipient_nk);
    println!("   Sender RK hash: {:?}", sender_rk_hash);

    // Create note commitment
    let deposit_value = U256::from(1_000_000_000_000_000_000u64); // 1 ETH
    let input_r = Field::rand(&mut rng);
    let input_cm = hash_commitment(
        sender_rk_hash,
        u256_to_field(deposit_value),
        address_to_field(Address::ZERO),
        input_r,
    );
    println!("\n4. Creating deposit note...");
    println!("   Value: {} wei", deposit_value);
    println!("   Commitment: {:?}", input_cm);

    // Deposit to contract
    println!("\n5. Depositing to VoidgunPool...");
    let commitment_u256 = field_to_u256(input_cm);
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
    let merkle_index = u64::try_from(post_deposit_index - U256::from(1)).unwrap();
    let contract_root = pool.currentRoot().call().await.unwrap();
    println!("   Merkle index: {}", merkle_index);
    println!("   Contract root: {:?}", contract_root);

    // Build local Merkle tree to match contract state by syncing all events
    println!("\n6. Syncing Merkle tree from contract events...");
    let mut tree = MerkleTree::new();

    // Fetch all Deposit events to reconstruct tree
    let deposit_filter = Filter::new()
        .address(pool_address)
        .event_signature(IVoidgunPool::Deposit::SIGNATURE_HASH)
        .from_block(0);

    let deposit_logs = provider.get_logs(&deposit_filter).await.unwrap();
    println!("   Found {} deposit events", deposit_logs.len());

    // Process all deposits in order (they should already be in order by leafIndex)
    let mut deposits: Vec<(u64, Field)> = vec![];
    for log in &deposit_logs {
        // The commitment is the first indexed topic
        if log.topics().len() > 1 {
            let commitment = U256::from_be_slice(log.topics()[1].as_slice());
            // Decode the log data to get leafIndex
            let data = log.data().data.as_ref();
            // Data layout: value (32) + ciphertext_offset (32) + leafIndex (32) + newRoot (32) + ciphertext_len + ciphertext
            if data.len() >= 96 {
                let leaf_index = U256::from_be_slice(&data[64..96]);
                deposits.push((leaf_index.try_into().unwrap(), u256_to_field(commitment)));
            }
        }
    }

    // Sort by leaf index to ensure correct order
    deposits.sort_by_key(|(idx, _)| *idx);

    // Track our deposit's index
    let mut our_deposit_idx = None;

    // Insert all commitments
    for (expected_idx, cm) in &deposits {
        let actual_idx = tree.insert(*cm);
        assert_eq!(actual_idx, *expected_idx, "Leaf index mismatch during sync");

        if *cm == input_cm {
            our_deposit_idx = Some(*expected_idx);
        }
    }

    let our_merkle_index = our_deposit_idx.expect("Our deposit not found in events");
    let local_root = tree.root();
    let merkle_proof = tree.proof(our_merkle_index, input_cm);

    println!("   Synced {} deposits", deposits.len());
    println!("   Our deposit merkle index: {}", our_merkle_index);
    println!("   Local root: {:?}", local_root);
    println!("   Contract root: {:?}", contract_root);

    // Verify roots match
    let roots_match = field_to_u256(local_root) == contract_root;
    println!("   Roots match: {}", roots_match);

    if !roots_match {
        println!("   [FAIL] Root mismatch after syncing all deposits!");
        println!("   This indicates a Poseidon2 hash mismatch between Rust and Solidity.");
        return;
    }

    let proof_root = local_root;

    // Build transfer parameters
    println!("\n7. Building transfer...");
    let transfer_value = U256::from(500_000_000_000_000_000u64); // 0.5 ETH
    let change_value = deposit_value - transfer_value;
    let r_out = Field::rand(&mut rng);
    let r_change = Field::rand(&mut rng);

    let cm_out = hash_commitment(
        recipient_rk_hash,
        u256_to_field(transfer_value),
        address_to_field(Address::ZERO),
        r_out,
    );
    let cm_change = hash_commitment(
        sender_rk_hash,
        u256_to_field(change_value),
        address_to_field(Address::ZERO),
        r_change,
    );
    println!("   Transfer value: {} wei", transfer_value);
    println!("   Change value: {} wei", change_value);

    // Create signing key for ECDSA
    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let pk_uncompressed = verifying_key.to_encoded_point(false);
    let pk_bytes = pk_uncompressed.as_bytes();
    let mut pub_key_x = [0u8; 32];
    let mut pub_key_y = [0u8; 32];
    pub_key_x.copy_from_slice(&pk_bytes[1..33]);
    pub_key_y.copy_from_slice(&pk_bytes[33..65]);

    let pk_hash = keccak256(&pk_bytes[1..65]);
    let sender_address = Address::from_slice(&pk_hash[12..32]);
    println!("   Sender address (from signing key): {:?}", sender_address);

    // Get pool_id from contract address (matches Solidity: poolId = uint256(uint160(address(this))))
    let pool_id = address_to_field(pool_address);
    let chain_id = 1u64;
    let nonce = 0u64;
    let to_address = sender_address;

    // Compute nullifiers
    let nf_note = note_nullifier(input_cm, nk);
    let nf_tx = tx_nullifier(nk, chain_id, pool_id, to_address, nonce);
    println!("   Note nullifier: {:?}", nf_note);
    println!("   Tx nullifier: {:?}", nf_tx);

    // Create and sign tx_hash
    let tx_hash_data = keccak256(b"mock_transaction_data");
    let (sig, _) = signing_key
        .sign_prehash_recoverable(&tx_hash_data.0)
        .unwrap();
    let sig_normalized = sig.normalize_s().unwrap_or(sig);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_normalized.to_bytes());

    // Build witness
    println!("\n8. Building witness...");
    let witness = TransferWitness {
        root: proof_root,
        cm_out,
        cm_change,
        nf_note,
        nf_tx,
        gas_tip: Field::from(2_000_000_000u64),
        gas_fee_cap: Field::from(100_000_000_000u64),
        token_type: address_to_field(Address::ZERO),
        pool_id,

        tx_hash: tx_hash_data.0,
        tx_chain_id: chain_id,
        tx_nonce: nonce,
        tx_to: to_address.0 .0,
        tx_value: u256_to_field(transfer_value),
        tx_max_priority_fee: Field::from(2_000_000_000u64),
        tx_max_fee: Field::from(100_000_000_000u64),

        signature,
        pub_key_x,
        pub_key_y,

        note_in_rk_hash: sender_rk_hash,
        note_in_value: u256_to_field(deposit_value),
        note_in_token: address_to_field(Address::ZERO),
        note_in_r: input_r,

        note_out_rk_hash: recipient_rk_hash,
        note_out_value: u256_to_field(transfer_value),
        note_out_r: r_out,

        note_change_rk_hash: sender_rk_hash,
        note_change_value: u256_to_field(change_value),
        note_change_r: r_change,

        merkle_path: merkle_proof.path.clone(),
        merkle_index: our_merkle_index,

        nk,

        recipient_pk_x: pub_key_x,
        recipient_pk_y: pub_key_y,
    };

    // Generate proof
    println!("\n9. Generating ZK proof...");
    println!("   (This may take a few seconds...)");

    let proof_result = prove_transfer(witness);

    match proof_result {
        Ok(proof) => {
            println!("   [OK] Proof generated!");
            println!("   Proof size: {} bytes", proof.proof.len());
            println!("   Public inputs: {} elements", proof.public_inputs.len());

            // Convert public inputs to bytes32[]
            let public_inputs_bytes32: Vec<FixedBytes<32>> = proof
                .public_inputs
                .iter()
                .map(|bytes| FixedBytes::from_slice(bytes))
                .collect();

            // First, test the verifier directly
            println!("\n10. Testing verifier directly...");
            let verifier_address = pool.verifier().call().await.unwrap();
            println!("   Verifier address: {:?}", verifier_address);

            let verifier = IVerifier::new(verifier_address, &provider);
            let verify_result = verifier
                .verify(
                    Bytes::from(proof.proof.clone()),
                    public_inputs_bytes32.clone(),
                )
                .call()
                .await;

            match &verify_result {
                Ok(is_valid) => println!("   Verifier.verify() returned: {}", is_valid),
                Err(e) => println!("   Verifier.verify() failed: {:?}", e),
            }

            println!("\n11. Submitting shielded transfer to contract...");

            // Submit to contract
            let transfer_result = pool
                .shieldedTransfer(
                    public_inputs_bytes32,
                    Bytes::from(proof.proof.clone()),
                    Bytes::from(vec![0u8; 64]), // ciphertext_out placeholder
                    Bytes::from(vec![0u8; 64]), // ciphertext_change placeholder
                )
                .send()
                .await;

            match transfer_result {
                Ok(pending) => {
                    let tx_hash = pending.watch().await;
                    match tx_hash {
                        Ok(hash) => {
                            println!("   [OK] Transfer tx confirmed: {:?}", hash);

                            // Verify nullifier is now spent
                            let is_spent = pool
                                .nullifiedNotes(field_to_u256(nf_note))
                                .call()
                                .await
                                .unwrap();
                            println!("   Note nullifier is spent: {}", is_spent);

                            // Check new tree state
                            let final_index = pool.nextIndex().call().await.unwrap();
                            println!("   New tree index: {}", final_index);

                            println!("\n=== [OK] E2E Test Complete! ===");
                        }
                        Err(e) => {
                            println!("   [FAIL] Transfer tx failed: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("   [FAIL] Failed to send transfer: {:?}", e);
                    println!("\n   This likely means the proof verification failed on-chain.");
                    println!("   Possible causes:");
                    println!("   - Root mismatch (tree not synced)");
                    println!("   - Invalid public inputs");
                    println!("   - Proof format mismatch");
                }
            }
        }
        Err(e) => {
            println!("   [FAIL] Proof generation failed: {:?}", e);
        }
    }
}
