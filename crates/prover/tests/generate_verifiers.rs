//! Generate Solidity verifier contracts for transfer and withdrawal circuits
//!
//! Run with: cargo test -p voidgun-prover --test generate_verifiers -- --ignored --nocapture

use voidgun_prover::{generate_solidity_verifier, generate_withdrawal_solidity_verifier};

#[test]
#[ignore]
fn generate_transfer_verifier() {
    println!("Generating transfer verifier Solidity...");

    match generate_solidity_verifier() {
        Ok(sol) => {
            let output_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("contracts")
                .join("verifier")
                .join("TransferVerifier.sol");

            std::fs::write(&output_path, &sol).expect("Failed to write verifier");
            println!(
                "[OK] Transfer verifier written to: {}",
                output_path.display()
            );
            println!("Verifier size: {} chars", sol.len());
        }
        Err(e) => {
            println!("[FAIL] Failed to generate transfer verifier: {:?}", e);
        }
    }
}

#[test]
#[ignore]
fn generate_withdrawal_verifier() {
    println!("Generating withdrawal verifier Solidity...");

    match generate_withdrawal_solidity_verifier() {
        Ok(sol) => {
            let output_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("contracts")
                .join("verifier")
                .join("WithdrawalVerifier.sol");

            // Rename the contract/library to avoid collision
            let sol = sol
                .replace("HonkVerifier", "WithdrawalVerifier")
                .replace("HonkVerificationKey", "WithdrawalVerificationKey");

            std::fs::write(&output_path, &sol).expect("Failed to write verifier");
            println!(
                "[OK] Withdrawal verifier written to: {}",
                output_path.display()
            );
            println!("Verifier size: {} chars", sol.len());
        }
        Err(e) => {
            println!("[FAIL] Failed to generate withdrawal verifier: {:?}", e);
        }
    }
}

#[test]
#[ignore]
fn generate_both_verifiers() {
    generate_transfer_verifier();
    generate_withdrawal_verifier();
}
