use alloy_primitives::{keccak256, Address, Bytes, U256};
use alloy_rlp::Encodable;

/// BN254 scalar field modulus (Fr)
/// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const BN254_MODULUS: U256 = U256::from_limbs([
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
]);

/// Parsed EIP-1559 transaction
#[derive(Clone, Debug)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
}

impl Eip1559Tx {
    /// Validate that all U256 fields are within BN254 scalar field range.
    /// This ensures the RLP encoding in Noir (using Field) matches the Rust encoding.
    pub fn validate_for_circuit(&self) -> Result<(), TxError> {
        if self.max_priority_fee_per_gas >= BN254_MODULUS {
            return Err(TxError::FieldOverflow("max_priority_fee_per_gas"));
        }
        if self.max_fee_per_gas >= BN254_MODULUS {
            return Err(TxError::FieldOverflow("max_fee_per_gas"));
        }
        if self.value >= BN254_MODULUS {
            return Err(TxError::FieldOverflow("value"));
        }
        if !self.data.is_empty() {
            return Err(TxError::NonEmptyData);
        }
        Ok(())
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        use alloy_rlp::EMPTY_LIST_CODE;

        let mut list_buf = Vec::new();

        self.chain_id.encode(&mut list_buf);
        self.nonce.encode(&mut list_buf);
        self.max_priority_fee_per_gas.encode(&mut list_buf);
        self.max_fee_per_gas.encode(&mut list_buf);
        self.gas_limit.encode(&mut list_buf);
        self.to.encode(&mut list_buf);
        self.value.encode(&mut list_buf);
        self.data.encode(&mut list_buf);
        list_buf.push(EMPTY_LIST_CODE);

        let mut rlp_buf = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: list_buf.len(),
        }
        .encode(&mut rlp_buf);
        rlp_buf.extend_from_slice(&list_buf);

        let mut typed_tx = vec![0x02u8];
        typed_tx.extend_from_slice(&rlp_buf);

        keccak256(&typed_tx).0
    }
}

/// Signed EIP-1559 transaction
#[derive(Clone, Debug)]
pub struct SignedEip1559Tx {
    pub tx: Eip1559Tx,
    pub v: u8,
    pub r: U256,
    pub s: U256,
    /// Raw transaction bytes
    pub raw: Bytes,
}

impl SignedEip1559Tx {
    /// Parse a signed transaction from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TxError> {
        // First byte should be 0x02 for EIP-1559
        if bytes.is_empty() || bytes[0] != 0x02 {
            return Err(TxError::InvalidTxType);
        }

        // TODO: Implement full RLP decoding with alloy-consensus
        Err(TxError::DecodingNotImplemented)
    }

    /// Get the transaction hash
    pub fn tx_hash(&self) -> [u8; 32] {
        keccak256(&self.raw).0
    }
}

/// Convert a secp256k1 public key bytes to an Ethereum address
pub fn pubkey_to_address(pubkey_bytes: &[u8]) -> Address {
    // Skip the 0x04 prefix if present (uncompressed format)
    let bytes = if pubkey_bytes.len() == 65 && pubkey_bytes[0] == 0x04 {
        &pubkey_bytes[1..]
    } else {
        pubkey_bytes
    };

    let hash = keccak256(bytes);
    Address::from_slice(&hash[12..])
}

#[derive(Debug, thiserror::Error)]
pub enum TxError {
    #[error("Invalid transaction type")]
    InvalidTxType,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("RLP decoding not yet implemented")]
    DecodingNotImplemented,

    #[error("Field {0} exceeds BN254 scalar field modulus")]
    FieldOverflow(&'static str),

    #[error("Non-empty data not supported (only simple transfers)")]
    NonEmptyData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eip1559_signing_hash() {
        let tx = Eip1559Tx {
            chain_id: 1,
            nonce: 42,
            max_priority_fee_per_gas: U256::from(2_000_000_000u64),
            max_fee_per_gas: U256::from(100_000_000_000u64),
            gas_limit: 21000,
            to: Address::from_slice(&[
                0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ]),
            value: U256::from(1_000_000_000_000_000_000u64),
            data: Bytes::default(),
        };

        let hash = tx.signing_hash();

        println!("EIP-1559 signing hash: 0x{}", hex::encode(hash));
        println!();
        println!("// Noir test vector:");
        println!("let chain_id: u64 = {};", tx.chain_id);
        println!("let nonce: u64 = {};", tx.nonce);
        println!(
            "let max_priority_fee: Field = {};",
            tx.max_priority_fee_per_gas
        );
        println!("let max_fee: Field = {};", tx.max_fee_per_gas);
        println!("let gas_limit: u64 = {};", tx.gas_limit);
        println!("let to: [u8; 20] = {:?};", tx.to.as_slice());
        println!("let value: Field = {};", tx.value);
        print!("let expected_hash: [u8; 32] = [");
        for (i, b) in hash.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("0x{:02x}", b);
        }
        println!("];");

        assert!(
            !hash.iter().all(|&b| b == 0),
            "Hash should not be all zeros"
        );
    }

    #[test]
    fn test_eip1559_signing_hash_simple() {
        let tx = Eip1559Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: U256::from(1u64),
            max_fee_per_gas: U256::from(1u64),
            gas_limit: 21000,
            to: Address::ZERO,
            value: U256::ZERO,
            data: Bytes::default(),
        };

        let hash = tx.signing_hash();
        println!("Simple tx hash: 0x{}", hex::encode(hash));

        print!("let expected_hash: [u8; 32] = [");
        for (i, b) in hash.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("0x{:02x}", b);
        }
        println!("];");
    }
}
