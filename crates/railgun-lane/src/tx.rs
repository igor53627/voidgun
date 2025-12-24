//! Transaction building and signing utilities
//!
//! This module provides EIP-1559 transaction construction and signing
//! for submitting Railgun operations on-chain.

use alloy_primitives::{Address, Bytes, B256, U256};
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TxError {
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("RLP encoding failed: {0}")]
    RlpEncodingFailed(String),

    #[error("Invalid private key")]
    InvalidPrivateKey,
}

/// EIP-1559 transaction parameters
#[derive(Clone, Debug)]
pub struct Eip1559Tx {
    /// Chain ID
    pub chain_id: u64,
    /// Nonce
    pub nonce: u64,
    /// Max priority fee per gas (tip)
    pub max_priority_fee_per_gas: u128,
    /// Max fee per gas (base + tip)
    pub max_fee_per_gas: u128,
    /// Gas limit
    pub gas_limit: u64,
    /// Recipient address
    pub to: Address,
    /// Value in wei
    pub value: U256,
    /// Calldata
    pub data: Bytes,
    /// Access list (empty for most Railgun txs)
    pub access_list: Vec<(Address, Vec<B256>)>,
}

impl Eip1559Tx {
    /// Create a new EIP-1559 transaction for a contract call
    pub fn new_contract_call(
        chain_id: u64,
        nonce: u64,
        to: Address,
        data: Vec<u8>,
        gas_limit: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
    ) -> Self {
        Self {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value: U256::ZERO,
            data: Bytes::from(data),
            access_list: Vec::new(),
        }
    }

    /// RLP encode the transaction for signing (without signature)
    fn rlp_encode_for_signing(&self) -> Vec<u8> {
        let mut rlp = Vec::new();

        // EIP-1559 transaction type prefix
        rlp.push(0x02);

        // Start RLP list
        let mut list_content = Vec::new();

        // Chain ID
        rlp_encode_u64(&mut list_content, self.chain_id);
        // Nonce
        rlp_encode_u64(&mut list_content, self.nonce);
        // Max priority fee per gas
        rlp_encode_u128(&mut list_content, self.max_priority_fee_per_gas);
        // Max fee per gas
        rlp_encode_u128(&mut list_content, self.max_fee_per_gas);
        // Gas limit
        rlp_encode_u64(&mut list_content, self.gas_limit);
        // To address
        rlp_encode_bytes(&mut list_content, self.to.as_slice());
        // Value
        rlp_encode_u256(&mut list_content, self.value);
        // Data
        rlp_encode_bytes(&mut list_content, &self.data);
        // Access list (empty list)
        rlp_encode_list(&mut list_content, &self.encode_access_list());

        // Wrap in list
        rlp_encode_list(&mut rlp, &list_content);

        rlp
    }

    /// Encode access list as RLP
    fn encode_access_list(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for (addr, keys) in &self.access_list {
            let mut entry = Vec::new();
            rlp_encode_bytes(&mut entry, addr.as_slice());

            let mut keys_content = Vec::new();
            for key in keys {
                rlp_encode_bytes(&mut keys_content, key.as_slice());
            }
            rlp_encode_list(&mut entry, &keys_content);

            rlp_encode_list(&mut result, &entry);
        }
        result
    }

    /// RLP encode the signed transaction
    fn rlp_encode_signed(&self, v: u8, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let mut rlp = Vec::new();

        // EIP-1559 transaction type prefix
        rlp.push(0x02);

        // Start RLP list
        let mut list_content = Vec::new();

        // Chain ID
        rlp_encode_u64(&mut list_content, self.chain_id);
        // Nonce
        rlp_encode_u64(&mut list_content, self.nonce);
        // Max priority fee per gas
        rlp_encode_u128(&mut list_content, self.max_priority_fee_per_gas);
        // Max fee per gas
        rlp_encode_u128(&mut list_content, self.max_fee_per_gas);
        // Gas limit
        rlp_encode_u64(&mut list_content, self.gas_limit);
        // To address
        rlp_encode_bytes(&mut list_content, self.to.as_slice());
        // Value
        rlp_encode_u256(&mut list_content, self.value);
        // Data
        rlp_encode_bytes(&mut list_content, &self.data);
        // Access list
        rlp_encode_list(&mut list_content, &self.encode_access_list());
        // v (recovery id, 0 or 1 for EIP-1559)
        rlp_encode_u64(&mut list_content, v as u64);
        // r
        rlp_encode_bytes(&mut list_content, trim_leading_zeros(r));
        // s
        rlp_encode_bytes(&mut list_content, trim_leading_zeros(s));

        // Wrap in list
        rlp_encode_list(&mut rlp, &list_content);

        rlp
    }

    /// Sign the transaction with a private key
    ///
    /// Returns the RLP-encoded signed transaction ready for eth_sendRawTransaction.
    pub fn sign(&self, private_key: &[u8; 32]) -> Result<Vec<u8>, TxError> {
        let signing_key =
            SigningKey::from_bytes(private_key.into()).map_err(|_| TxError::InvalidPrivateKey)?;

        // Get the signing hash
        let unsigned_rlp = self.rlp_encode_for_signing();
        let signing_hash = Keccak256::digest(&unsigned_rlp);

        // Sign with k256
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&signing_hash)
            .map_err(|e| TxError::SigningFailed(e.to_string()))?;

        let r_bytes: [u8; 32] = signature.r().to_bytes().into();
        let s_bytes: [u8; 32] = signature.s().to_bytes().into();
        let v = recovery_id.to_byte();

        Ok(self.rlp_encode_signed(v, &r_bytes, &s_bytes))
    }

    /// Compute the transaction hash (before signing)
    pub fn signing_hash(&self) -> B256 {
        let unsigned_rlp = self.rlp_encode_for_signing();
        let hash: [u8; 32] = Keccak256::digest(&unsigned_rlp).into();
        B256::from(hash)
    }
}

/// Submitted transaction with tracking
#[derive(Clone, Debug)]
pub struct SubmittedTx {
    /// Transaction hash
    pub hash: B256,
    /// Nonce used
    pub nonce: u64,
    /// Chain ID
    pub chain_id: u64,
}

// RLP encoding helpers

fn rlp_encode_u64(buf: &mut Vec<u8>, value: u64) {
    if value == 0 {
        buf.push(0x80);
    } else if value < 128 {
        buf.push(value as u8);
    } else {
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(8);
        let len = 8 - start;
        buf.push(0x80 + len as u8);
        buf.extend_from_slice(&bytes[start..]);
    }
}

fn rlp_encode_u128(buf: &mut Vec<u8>, value: u128) {
    if value == 0 {
        buf.push(0x80);
    } else if value < 128 {
        buf.push(value as u8);
    } else {
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(16);
        let len = 16 - start;
        buf.push(0x80 + len as u8);
        buf.extend_from_slice(&bytes[start..]);
    }
}

fn rlp_encode_u256(buf: &mut Vec<u8>, value: U256) {
    if value.is_zero() {
        buf.push(0x80);
    } else {
        let bytes: [u8; 32] = value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(32);
        let trimmed = &bytes[start..];
        if trimmed.len() == 1 && trimmed[0] < 128 {
            buf.push(trimmed[0]);
        } else {
            buf.push(0x80 + trimmed.len() as u8);
            buf.extend_from_slice(trimmed);
        }
    }
}

fn rlp_encode_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.is_empty() {
        buf.push(0x80);
    } else if bytes.len() == 1 && bytes[0] < 128 {
        buf.push(bytes[0]);
    } else if bytes.len() < 56 {
        buf.push(0x80 + bytes.len() as u8);
        buf.extend_from_slice(bytes);
    } else {
        let len_bytes = bytes.len().to_be_bytes();
        let len_start = len_bytes.iter().position(|&b| b != 0).unwrap_or(8);
        let len_len = 8 - len_start;
        buf.push(0xb7 + len_len as u8);
        buf.extend_from_slice(&len_bytes[len_start..]);
        buf.extend_from_slice(bytes);
    }
}

fn rlp_encode_list(buf: &mut Vec<u8>, content: &[u8]) {
    if content.len() < 56 {
        buf.push(0xc0 + content.len() as u8);
        buf.extend_from_slice(content);
    } else {
        let len_bytes = content.len().to_be_bytes();
        let len_start = len_bytes.iter().position(|&b| b != 0).unwrap_or(8);
        let len_len = 8 - len_start;
        buf.push(0xf7 + len_len as u8);
        buf.extend_from_slice(&len_bytes[len_start..]);
        buf.extend_from_slice(content);
    }
}

fn trim_leading_zeros(bytes: &[u8; 32]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(32);
    if start == 32 {
        &bytes[31..32] // Keep at least one byte (0x00)
    } else {
        &bytes[start..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rlp_encode_u64() {
        let mut buf = Vec::new();
        rlp_encode_u64(&mut buf, 0);
        assert_eq!(buf, vec![0x80]);

        buf.clear();
        rlp_encode_u64(&mut buf, 127);
        assert_eq!(buf, vec![127]);

        buf.clear();
        rlp_encode_u64(&mut buf, 128);
        assert_eq!(buf, vec![0x81, 128]);

        buf.clear();
        rlp_encode_u64(&mut buf, 256);
        assert_eq!(buf, vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_rlp_encode_bytes() {
        let mut buf = Vec::new();
        rlp_encode_bytes(&mut buf, &[]);
        assert_eq!(buf, vec![0x80]);

        buf.clear();
        rlp_encode_bytes(&mut buf, &[0x42]);
        assert_eq!(buf, vec![0x42]);

        buf.clear();
        rlp_encode_bytes(&mut buf, &[0x80]);
        assert_eq!(buf, vec![0x81, 0x80]);

        buf.clear();
        let data = vec![0x42; 55];
        rlp_encode_bytes(&mut buf, &data);
        assert_eq!(buf[0], 0x80 + 55);
    }

    #[test]
    fn test_eip1559_tx_signing_hash() {
        let tx = Eip1559Tx::new_contract_call(
            1, // mainnet
            0, // nonce
            Address::repeat_byte(0x42),
            vec![0xde, 0xad, 0xbe, 0xef],
            21000,
            1_000_000_000,  // 1 gwei priority
            50_000_000_000, // 50 gwei max
        );

        let hash = tx.signing_hash();
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_eip1559_tx_sign() {
        // Use a test private key (DO NOT use in production!)
        let private_key: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let tx = Eip1559Tx::new_contract_call(
            1,
            0,
            Address::repeat_byte(0x42),
            vec![0xde, 0xad, 0xbe, 0xef],
            21000,
            1_000_000_000,
            50_000_000_000,
        );

        let signed = tx.sign(&private_key).expect("signing should succeed");

        // Should start with 0x02 (EIP-1559 type)
        assert_eq!(signed[0], 0x02);

        // Should be reasonable length
        assert!(signed.len() > 100);
    }
}
