use keccak256::keccak256;

/// EIP-1559 transaction fields relevant for shielding
struct Eip1559Tx {
    chain_id: Field,
    nonce: Field,
    max_priority_fee_per_gas: Field,
    max_fee_per_gas: Field,
    gas_limit: Field,
    to: [u8; 20],
    value: Field,
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
