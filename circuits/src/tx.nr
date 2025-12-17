use keccak256::keccak256;
use crate::rlp::{Eip1559TxRlp, eip1559_signing_hash, verify_tx_hash};

/// EIP-1559 transaction fields relevant for shielding
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: Field,
    pub max_fee_per_gas: Field,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: Field,
}

impl Eip1559Tx {
    /// Convert to RLP-encodable format
    pub fn to_rlp(self) -> Eip1559TxRlp {
        Eip1559TxRlp {
            chain_id: self.chain_id,
            nonce: self.nonce,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            gas_limit: self.gas_limit,
            to: self.to,
            value: self.value,
        }
    }
    
    /// Compute the EIP-1559 signing hash for this transaction
    pub fn signing_hash(self) -> [u8; 32] {
        eip1559_signing_hash(self.to_rlp())
    }
    
    /// Verify that the provided hash matches this transaction's signing hash
    pub fn verify_hash(self, expected_hash: [u8; 32]) {
        verify_tx_hash(self.to_rlp(), expected_hash);
    }
}

/// Derive Ethereum address from uncompressed secp256k1 public key
/// address = keccak256(pk_x || pk_y)[12:32]
pub fn pubkey_to_address(pk_x: [u8; 32], pk_y: [u8; 32]) -> [u8; 20] {
    let mut pk_bytes: [u8; 64] = [0; 64];
    for i in 0..32 {
        pk_bytes[i] = pk_x[i];
        pk_bytes[i + 32] = pk_y[i];
    }
    
    let hash: [u8; 32] = keccak256(pk_bytes, 64);
    
    let mut address: [u8; 20] = [0; 20];
    for i in 0..20 {
        address[i] = hash[i + 12];
    }
    
    address
}

/// Compare two addresses for equality
pub fn addresses_equal(a: [u8; 20], b: [u8; 20]) -> bool {
    let mut equal = true;
    for i in 0..20 {
        if a[i] != b[i] {
            equal = false;
        }
    }
    equal
}

/// Convert address bytes to Field for hashing
pub fn address_to_field(addr: [u8; 20]) -> Field {
    let mut result: Field = 0;
    for i in 0..20 {
        result = result * 256 + addr[i] as Field;
    }
    result
}
