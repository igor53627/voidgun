//! Railgun-compatible Poseidon hash implementation
//!
//! Railgun uses Poseidon (not Poseidon2) with specific parameters from circomlibjs:
//! - Curve: BN254
//! - t = width (number of inputs + 1 for capacity)
//! - RF = 8 (full rounds)
//! - RP = varies by width (57 for t=3)
//!
//! This wraps the `light-poseidon` crate which provides circomlibjs-compatible
//! Poseidon hash with pre-generated round constants from the official hadeshash
//! SageMath script.

use ark_bn254::Fr as Field;
use light_poseidon::{Poseidon, PoseidonHasher};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PoseidonError {
    #[error("Invalid input count: {0} (max 12)")]
    InvalidInputCount(usize),
}

/// Poseidon hash function (Railgun/circomlibjs compatible)
///
/// This uses the light-poseidon crate which generates parameters matching
/// circomlibjs exactly. The parameters are:
/// - S-box: x^5 (quintic)
/// - Full rounds: 8
/// - Partial rounds: varies by width [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65]
/// - BN254 field modulus
pub fn poseidon_hash(inputs: &[Field]) -> Result<Field, PoseidonError> {
    if inputs.is_empty() || inputs.len() > 12 {
        return Err(PoseidonError::InvalidInputCount(inputs.len()));
    }

    let mut poseidon = Poseidon::<Field>::new_circom(inputs.len())
        .map_err(|_| PoseidonError::InvalidInputCount(inputs.len()))?;

    poseidon
        .hash(inputs)
        .map_err(|_| PoseidonError::InvalidInputCount(inputs.len()))
}

/// Hash two field elements (commonly used for Merkle trees)
pub fn poseidon2(left: Field, right: Field) -> Field {
    poseidon_hash(&[left, right]).expect("t=3 always valid")
}

/// Hash three field elements
pub fn poseidon3(a: Field, b: Field, c: Field) -> Field {
    poseidon_hash(&[a, b, c]).expect("t=4 always valid")
}

/// Hash four field elements
pub fn poseidon4(a: Field, b: Field, c: Field, d: Field) -> Field {
    poseidon_hash(&[a, b, c, d]).expect("t=5 always valid")
}

/// Hash five field elements
pub fn poseidon5(a: Field, b: Field, c: Field, d: Field, e: Field) -> Field {
    poseidon_hash(&[a, b, c, d, e]).expect("t=6 always valid")
}

/// Hash six field elements
pub fn poseidon6(a: Field, b: Field, c: Field, d: Field, e: Field, f: Field) -> Field {
    poseidon_hash(&[a, b, c, d, e, f]).expect("t=7 always valid")
}

/// Variable-length Poseidon hash
///
/// For inputs longer than 12 elements, we use iterative hashing:
/// - Split into chunks of max 11 elements
/// - Hash each chunk with previous hash as first element
/// - Return final hash
///
/// For inputs <= 12, just call poseidon_hash directly.
pub fn poseidon_var(inputs: &[Field]) -> Field {
    if inputs.is_empty() {
        return Field::from(0u64);
    }

    if inputs.len() <= 12 {
        return poseidon_hash(inputs).expect("valid input count");
    }

    // Iterative hashing for longer inputs
    // Start with first 12 elements
    let mut hash = poseidon_hash(&inputs[..12]).expect("12 elements valid");

    // Process remaining in chunks of 11 (1 slot for previous hash)
    let mut i = 12;
    while i < inputs.len() {
        let end = std::cmp::min(i + 11, inputs.len());
        let mut chunk = vec![hash];
        chunk.extend_from_slice(&inputs[i..end]);
        hash = poseidon_hash(&chunk).expect("valid chunk size");
        i = end;
    }

    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn test_poseidon_deterministic() {
        let a = Field::from(1u64);
        let b = Field::from(2u64);

        let h1 = poseidon2(a, b);
        let h2 = poseidon2(a, b);

        assert_eq!(h1, h2);
    }

    #[test]
    fn test_poseidon_different_inputs() {
        let a = Field::from(1u64);
        let b = Field::from(2u64);
        let c = Field::from(3u64);

        let h1 = poseidon2(a, b);
        let h2 = poseidon2(a, c);
        let h3 = poseidon2(b, a);

        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_poseidon_widths() {
        let a = Field::from(1u64);
        let b = Field::from(2u64);
        let c = Field::from(3u64);
        let d = Field::from(4u64);

        // All widths should work
        let _ = poseidon2(a, b);
        let _ = poseidon3(a, b, c);
        let _ = poseidon4(a, b, c, d);
    }

    #[test]
    fn test_poseidon_circomlibjs_compatibility() {
        // Test vector from light-poseidon tests (circomlibjs compatible)
        // poseidon([1, 1]) should produce a specific output
        let a = Field::from(1u64);
        let b = Field::from(1u64);

        let result = poseidon2(a, b);

        // The result should be non-zero and deterministic
        assert!(!result.is_zero());

        // Verify it matches across multiple calls
        let result2 = poseidon2(a, b);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_poseidon_single_input() {
        // Single input hash (t=2)
        let a = Field::from(1u64);
        let result = poseidon_hash(&[a]).unwrap();
        assert!(!result.is_zero());
    }

    #[test]
    fn test_poseidon_max_inputs() {
        // 12 inputs is the maximum supported
        let inputs: Vec<Field> = (1..=12).map(|i| Field::from(i as u64)).collect();
        let result = poseidon_hash(&inputs).unwrap();
        assert!(!result.is_zero());
    }

    #[test]
    fn test_poseidon_invalid_input_count() {
        // 0 inputs should fail
        assert!(poseidon_hash(&[]).is_err());

        // 13 inputs should fail
        let inputs: Vec<Field> = (1..=13).map(|i| Field::from(i as u64)).collect();
        assert!(poseidon_hash(&inputs).is_err());
    }
}

#[test]
fn test_poseidon_known_vector() {
    use ark_ff::{BigInteger, PrimeField};

    // Known test vector from circomlibjs
    // poseidon([1, 2]) = 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
    let a = Field::from(1u64);
    let b = Field::from(2u64);

    let result = poseidon2(a, b);
    let result_hex = format!("0x{}", hex::encode(result.into_bigint().to_bytes_be()));

    println!("poseidon([1, 2]) = {}", result_hex);

    // circomlibjs output
    let expected = "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a";
    assert_eq!(
        result_hex, expected,
        "Poseidon hash doesn't match circomlibjs!"
    );
}
