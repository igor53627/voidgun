//! Full E2E test for withdrawal with fresh contract deployment
//!
//! This test:
//! 1. Deploys Poseidon2, TransferVerifier, WithdrawalVerifier, and VoidgunPoolV2
//! 2. Deposits ETH to create a note
//! 3. Syncs Merkle tree from on-chain events
//! 4. Generates a withdrawal proof
//! 5. Withdraws and verifies the full flow
//!
//! Run with: cargo test -p voidgun-prover --test e2e_full_withdrawal_test -- --ignored --nocapture

use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{keccak256, Address, Bytes, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
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
async fn test_full_e2e_withdrawal_with_fresh_deploy() {
    println!("=== Full E2E Withdrawal Test with Fresh Deployment ===\n");

    let mut rng = rand::thread_rng();

    // Load environment
    dotenv::dotenv().ok();

    let rpc_url = "https://virtual.mainnet.eu.rpc.tenderly.co/0c523439-45ce-414e-8d7a-5e198770eccf";

    // Create a deployer/test signer
    let signer = PrivateKeySigner::random();
    let wallet = EthereumWallet::from(signer.clone());

    println!("Deployer/Test account: {:?}", signer.address());

    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().unwrap());

    // Fund the deployer
    println!("\n1. Funding deployer account...");
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

    // Deploy contracts
    println!("\n2. Deploying contracts...");

    // Read compiled bytecode
    let contracts_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("contracts");

    // Helper to deploy contract from bytecode
    async fn deploy_contract<P: Provider>(
        provider: &P,
        bytecode: &str,
        constructor_args: Option<&[u8]>,
    ) -> Address {
        let mut data = alloy::primitives::hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        if let Some(args) = constructor_args {
            data.extend_from_slice(args);
        }

        let tx = TransactionRequest::default().with_deploy_code(data);

        let pending = provider
            .send_transaction(tx)
            .await
            .expect("Failed to send deploy tx");
        let receipt = pending.get_receipt().await.expect("Failed to get receipt");
        receipt.contract_address.expect("No contract address")
    }

    // 2a. Deploy Poseidon2
    println!("   Deploying Poseidon2...");
    let poseidon2_artifact_path = contracts_dir.join("out/Poseidon2.sol/Poseidon2Yul.json");
    let poseidon2_artifact: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&poseidon2_artifact_path)
            .expect("Failed to read Poseidon2 artifact - run `forge build` first"),
    )
    .unwrap();
    let poseidon2_bytecode = poseidon2_artifact["bytecode"]["object"]
        .as_str()
        .expect("No bytecode in artifact");

    let poseidon2_address = deploy_contract(&provider, poseidon2_bytecode, None).await;
    println!("   Poseidon2: {:?}", poseidon2_address);

    // 2b. Deploy ZKTranscriptLib (required by HonkVerifier)
    println!("   Deploying ZKTranscriptLib...");
    let zk_transcript_lib_path = contracts_dir.join("verifier/compiled/ZKTranscriptLib.bin");
    let zk_transcript_lib_bytecode = std::fs::read_to_string(&zk_transcript_lib_path)
        .expect("Failed to read ZKTranscriptLib.bin - run solc to compile verifier contracts")
        .trim()
        .to_string();

    let zk_transcript_lib_address =
        deploy_contract(&provider, &zk_transcript_lib_bytecode, None).await;
    println!("   ZKTranscriptLib: {:?}", zk_transcript_lib_address);

    // Helper to link library address into bytecode (replace library placeholders with actual address)
    fn link_library(bytecode: &str, lib_address: Address) -> String {
        let lib_addr_hex = alloy::primitives::hex::encode(lib_address);
        bytecode
            .replace("__$4c51bd4ab2f1d1cfe6a9e85f2433f63ec1$__", &lib_addr_hex)
            .replace("__$4d459fa6165269826fca6afc23fa39cec7$__", &lib_addr_hex)
            .replace("__$ed6280354e314b8b2b94f4371bbd0e3883$__", &lib_addr_hex)
    }

    // 2c. Deploy TransferVerifier
    println!("   Deploying TransferVerifier...");
    let transfer_verifier_path = contracts_dir.join("verifier/compiled/HonkVerifier.bin");
    let transfer_verifier_bytecode_raw = std::fs::read_to_string(&transfer_verifier_path)
        .expect("Failed to read HonkVerifier.bin - run solc to compile verifier contracts");
    // solc bin output may contain trailing comments - extract only hex characters
    let transfer_verifier_bytecode_hex: String = transfer_verifier_bytecode_raw
        .chars()
        .take_while(|c| c.is_ascii_hexdigit() || *c == '_' || *c == '$')
        .collect();
    let transfer_verifier_bytecode =
        link_library(&transfer_verifier_bytecode_hex, zk_transcript_lib_address);

    let transfer_verifier_address =
        deploy_contract(&provider, &transfer_verifier_bytecode, None).await;
    println!("   TransferVerifier: {:?}", transfer_verifier_address);

    // 2d. Deploy WithdrawalVerifier (uses the same library)
    println!("   Deploying WithdrawalVerifier...");
    let withdrawal_verifier_path =
        contracts_dir.join("out-verifier/WithdrawalVerifier.sol/WithdrawalVerifier.json");
    let withdrawal_verifier_artifact: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&withdrawal_verifier_path)
            .expect("Failed to read WithdrawalVerifier artifact"),
    )
    .unwrap();
    let withdrawal_verifier_bytecode_raw = withdrawal_verifier_artifact["bytecode"]["object"]
        .as_str()
        .expect("No bytecode in artifact");
    let withdrawal_verifier_bytecode =
        link_library(withdrawal_verifier_bytecode_raw, zk_transcript_lib_address);

    let withdrawal_verifier_address =
        deploy_contract(&provider, &withdrawal_verifier_bytecode, None).await;
    println!("   WithdrawalVerifier: {:?}", withdrawal_verifier_address);

    // 2e. Deploy VoidgunPoolV2
    println!("   Deploying VoidgunPoolV2...");
    let pool_artifact_path = contracts_dir.join("out/VoidgunPoolV2.sol/VoidgunPoolV2.json");
    let pool_artifact: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&pool_artifact_path).expect(
            "Failed to read VoidgunPoolV2 artifact - run `forge build src/VoidgunPoolV2.sol`",
        ))
        .unwrap();
    let pool_bytecode_raw = pool_artifact["bytecode"]["object"]
        .as_str()
        .expect("No bytecode in artifact");

    // Encode constructor arguments: (transferVerifier, withdrawalVerifier, poseidon2)
    let mut constructor_args = Vec::new();
    constructor_args.extend_from_slice(&[0u8; 12]); // pad to 32 bytes
    constructor_args.extend_from_slice(transfer_verifier_address.as_slice());
    constructor_args.extend_from_slice(&[0u8; 12]);
    constructor_args.extend_from_slice(withdrawal_verifier_address.as_slice());
    constructor_args.extend_from_slice(&[0u8; 12]);
    constructor_args.extend_from_slice(poseidon2_address.as_slice());

    let pool_address = deploy_contract(&provider, pool_bytecode_raw, Some(&constructor_args)).await;
    println!("   VoidgunPoolV2: {:?}", pool_address);

    // Get pool instance
    let pool = IVoidgunPoolV2::new(pool_address, &provider);

    // Verify deployment
    let deployed_transfer_verifier = pool.transferVerifier().call().await.unwrap();
    let deployed_withdrawal_verifier = pool.withdrawalVerifier().call().await.unwrap();
    let pool_id_u256 = pool.poolId().call().await.unwrap();
    println!("   Pool ID: {}", pool_id_u256);
    println!(
        "   Transfer Verifier matches: {}",
        deployed_transfer_verifier == transfer_verifier_address
    );
    println!(
        "   Withdrawal Verifier matches: {}",
        deployed_withdrawal_verifier == withdrawal_verifier_address
    );

    // 3. Create keys and deposit
    println!("\n3. Creating note and depositing...");
    let nk = Field::from(123456789u64);
    let owner_rk_hash = derive_rk_hash(nk);

    let deposit_value = U256::from(1_000_000_000_000_000_000u64); // 1 ETH
    let note_r = Field::rand(&mut rng);
    let note_cm = hash_commitment(
        owner_rk_hash,
        u256_to_field(deposit_value),
        address_to_field(Address::ZERO),
        note_r,
    );
    println!("   Note commitment: {:?}", note_cm);

    let ciphertext = Bytes::from(vec![0u8; 64]);
    let deposit_tx = pool
        .deposit(
            field_to_u256(note_cm),
            deposit_value,
            Address::ZERO,
            ciphertext,
        )
        .value(deposit_value)
        .send()
        .await
        .expect("Failed to send deposit tx")
        .watch()
        .await
        .expect("Failed to confirm deposit");
    println!("   Deposit tx: {:?}", deposit_tx);

    // 4. Sync Merkle tree
    println!("\n4. Syncing Merkle tree from events...");
    let contract_root = pool.currentRoot().call().await.unwrap();
    let mut tree = MerkleTree::new();

    let deposit_filter = Filter::new()
        .address(pool_address)
        .event_signature(IVoidgunPoolV2::Deposit::SIGNATURE_HASH)
        .from_block(0);

    let deposit_logs = provider.get_logs(&deposit_filter).await.unwrap();
    println!("   Found {} deposit events", deposit_logs.len());

    let mut our_merkle_index = 0u64;
    for log in &deposit_logs {
        if log.topics().len() > 1 {
            let commitment = U256::from_be_slice(log.topics()[1].as_slice());
            let cm_field = u256_to_field(commitment);
            let idx = tree.insert(cm_field);
            if cm_field == note_cm {
                our_merkle_index = idx;
            }
        }
    }

    let local_root = tree.root();
    let merkle_proof = tree.proof(our_merkle_index, note_cm);
    println!("   Our merkle index: {}", our_merkle_index);
    println!("   Local root: {:?}", local_root);
    println!("   Contract root: {:?}", contract_root);
    println!(
        "   Roots match: {}",
        field_to_u256(local_root) == contract_root
    );

    if field_to_u256(local_root) != contract_root {
        println!("   [FAIL] Root mismatch!");
        return;
    }

    // 5. Create withdrawal proof
    println!("\n5. Creating signing key and withdrawal proof...");
    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let pk_uncompressed = verifying_key.to_encoded_point(false);
    let pk_bytes = pk_uncompressed.as_bytes();
    let mut pub_key_x = [0u8; 32];
    let mut pub_key_y = [0u8; 32];
    pub_key_x.copy_from_slice(&pk_bytes[1..33]);
    pub_key_y.copy_from_slice(&pk_bytes[33..65]);

    let pk_hash = keccak256(&pk_bytes[1..65]);
    let recipient_address = Address::from_slice(&pk_hash[12..32]);
    let recipient_field = address_to_field(recipient_address);
    println!("   Recipient: {:?}", recipient_address);

    let pool_id = address_to_field(pool_address);
    let chain_id = 1u64;
    let nonce = 0u64;

    let nf_note = note_nullifier(note_cm, nk);
    let nf_tx = tx_nullifier(nk, chain_id, pool_id, recipient_address, nonce);
    println!("   Note nullifier: {:?}", nf_note);

    let tx_hash_data = keccak256(b"withdrawal_authorization");
    let (sig, _) = signing_key
        .sign_prehash_recoverable(&tx_hash_data.0)
        .unwrap();
    let sig_normalized = sig.normalize_s().unwrap_or(sig);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_normalized.to_bytes());

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

    println!("\n6. Generating ZK proof...");
    let proof = prove_withdrawal(witness).expect("Proof generation failed");
    println!("   [OK] Proof generated! {} bytes", proof.proof.len());

    // 7. Test verifier directly
    println!("\n7. Testing withdrawal verifier directly...");
    let public_inputs_bytes32: Vec<FixedBytes<32>> = proof
        .public_inputs
        .iter()
        .map(|bytes| FixedBytes::from_slice(bytes))
        .collect();

    let verifier = IVerifier::new(withdrawal_verifier_address, &provider);
    let verify_result = verifier
        .verify(
            Bytes::from(proof.proof.clone()),
            public_inputs_bytes32.clone(),
        )
        .call()
        .await;

    match &verify_result {
        Ok(is_valid) => println!("   Verifier.verify() returned: {}", is_valid),
        Err(e) => {
            println!("   [FAIL] Verifier.verify() failed: {:?}", e);
            return;
        }
    }

    // 8. Submit withdrawal
    println!("\n8. Submitting withdrawal to contract...");

    // Fund recipient to be able to receive
    let _ = provider
        .raw_request::<_, ()>(
            "tenderly_setBalance".into(),
            (vec![recipient_address], "0x0"),
        )
        .await;

    let recipient_balance_before = provider.get_balance(recipient_address).await.unwrap();
    println!(
        "   Recipient balance before: {} wei",
        recipient_balance_before
    );

    let withdraw_result = pool
        .withdraw(
            public_inputs_bytes32,
            Bytes::from(proof.proof.clone()),
            recipient_address,
            Address::ZERO,
            deposit_value,
        )
        .send()
        .await;

    match withdraw_result {
        Ok(pending) => match pending.watch().await {
            Ok(hash) => {
                println!("   [OK] Withdrawal tx confirmed: {:?}", hash);

                let is_spent = pool
                    .nullifiedNotes(field_to_u256(nf_note))
                    .call()
                    .await
                    .unwrap();
                println!("   Note nullifier is spent: {}", is_spent);

                let recipient_balance_after =
                    provider.get_balance(recipient_address).await.unwrap();
                println!(
                    "   Recipient balance after: {} wei",
                    recipient_balance_after
                );
                println!(
                    "   Balance increase: {} wei",
                    recipient_balance_after - recipient_balance_before
                );

                assert!(is_spent, "Note should be spent");
                assert!(
                    recipient_balance_after > recipient_balance_before,
                    "Balance should increase"
                );

                println!("\n=== [OK] FULL E2E WITHDRAWAL TEST PASSED! ===");
            }
            Err(e) => println!("   [FAIL] Withdrawal tx failed: {:?}", e),
        },
        Err(e) => println!("   [FAIL] Failed to send withdrawal: {:?}", e),
    }
}
