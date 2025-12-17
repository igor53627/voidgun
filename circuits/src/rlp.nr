use keccak256::keccak256;

/// EIP-1559 RLP Encoding for Simple Transfers
/// 
/// SCOPE LIMITATIONS:
/// - Only supports simple value transfers (no contract creation)
/// - `to` field must be a 20-byte address (not empty)
/// - `data` field is always empty (0x80)
/// - `access_list` is always empty (0xc0)
/// 
/// For contract calls or complex transactions, this module would need extension.

/// Maximum RLP buffer size for EIP-1559 simple transfer transactions
/// Actual max payload: type(1) + list_header(3) + 9 encoded fields
///   - chain_id: max 9 bytes (u64)
///   - nonce: max 9 bytes (u64)
///   - max_priority_fee: max 33 bytes (Field)
///   - max_fee: max 33 bytes (Field)
///   - gas_limit: max 9 bytes (u64)
///   - to: 21 bytes (fixed address)
///   - value: max 33 bytes (Field)
///   - data: 1 byte (empty)
///   - access_list: 1 byte (empty)
/// Total max: 1 + 3 + 9+9+33+33+9+21+33+1+1 = 153 bytes
/// We use 192 for safety margin
global MAX_RLP_SIZE: u32 = 192;

/// RLP encoding buffer with write position
pub struct RlpBuffer {
    pub data: [u8; MAX_RLP_SIZE],
    pub pos: u32,
}

impl RlpBuffer {
    pub fn new() -> Self {
        RlpBuffer { data: [0; MAX_RLP_SIZE], pos: 0 }
    }
    
    fn write_byte(self, b: u8) -> Self {
        let mut result = self;
        result.data[result.pos] = b;
        result.pos += 1;
        result
    }
    
    fn write_bytes<let N: u32>(self, bytes: [u8; N]) -> Self {
        let mut result = self;
        for i in 0..N {
            result.data[result.pos + i] = bytes[i];
        }
        result.pos += N;
        result
    }
}

/// Encode a u64 as big-endian bytes, returning the number of significant bytes
pub fn u64_to_be_bytes(value: u64) -> ([u8; 8], u32) {
    let mut bytes: [u8; 8] = [0; 8];
    let mut v = value;
    for i in 0..8 {
        bytes[7 - i] = (v & 0xff) as u8;
        v = v >> 8;
    }
    
    let mut leading_zeros: u32 = 0;
    for i in 0..8 {
        if bytes[i] == 0 {
            if leading_zeros == i as u32 {
                leading_zeros += 1;
            }
        }
    }
    
    let len = if leading_zeros == 8 { 0 } else { 8 - leading_zeros };
    (bytes, len)
}

/// RLP encode a single byte or short string (0-55 bytes)
pub fn rlp_encode_bytes<let N: u32>(buf: RlpBuffer, bytes: [u8; N], len: u32) -> RlpBuffer {
    if len == 0 {
        buf.write_byte(0x80)
    } else if len == 1 {
        if bytes[0] < 0x80 {
            buf.write_byte(bytes[0])
        } else {
            buf.write_byte(0x81).write_byte(bytes[0])
        }
    } else if len <= 55 {
        let mut result = buf.write_byte(0x80 + len as u8);
        for i in 0..N {
            if i < len {
                result = result.write_byte(bytes[i]);
            }
        }
        result
    } else {
        let (len_bytes, len_len) = u64_to_be_bytes(len as u64);
        let mut result = buf.write_byte(0xb7 + len_len as u8);
        for i in 0..8 {
            if i >= (8 - len_len) {
                result = result.write_byte(len_bytes[i]);
            }
        }
        for i in 0..N {
            if i < len {
                result = result.write_byte(bytes[i]);
            }
        }
        result
    }
}

/// RLP encode a u64 integer
pub fn rlp_encode_u64(buf: RlpBuffer, value: u64) -> RlpBuffer {
    if value == 0 {
        buf.write_byte(0x80)
    } else if value < 128 {
        buf.write_byte(value as u8)
    } else {
        let (bytes, len) = u64_to_be_bytes(value);
        let start = 8 - len;
        let mut result = buf.write_byte(0x80 + len as u8);
        for i in 0..8 {
            if i >= start {
                result = result.write_byte(bytes[i]);
            }
        }
        result
    }
}

/// RLP encode a Field as big-endian bytes (trimmed leading zeros)
/// BN254 scalar field is ~254 bits, so we use to_be_bytes which returns [u8; 32]
pub fn rlp_encode_field(buf: RlpBuffer, value: Field) -> RlpBuffer {
    let bytes: [u8; 32] = value.to_be_bytes();
    
    let mut leading_zeros: u32 = 0;
    for i in 0..32 {
        if bytes[i] == 0 {
            if leading_zeros == i as u32 {
                leading_zeros += 1;
            }
        }
    }
    
    let len = if leading_zeros == 32 { 0 } else { 32 - leading_zeros };
    
    if len == 0 {
        buf.write_byte(0x80)
    } else {
        let mut trimmed: [u8; 32] = [0; 32];
        for i in 0..32 {
            if i >= leading_zeros {
                trimmed[i - leading_zeros] = bytes[i];
            }
        }
        rlp_encode_bytes(buf, trimmed, len)
    }
}

/// RLP encode a 20-byte address
fn rlp_encode_address(buf: RlpBuffer, addr: [u8; 20]) -> RlpBuffer {
    buf.write_byte(0x80 + 20).write_bytes(addr)
}

/// EIP-1559 transaction for RLP encoding
pub struct Eip1559TxRlp {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: Field,
    pub max_fee_per_gas: Field,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: Field,
    // data and access_list are empty for simple transfers
}

/// Encode EIP-1559 transaction fields as RLP list (without type prefix)
/// Returns: (encoded_bytes, length)
fn encode_eip1559_fields(tx: Eip1559TxRlp) -> ([u8; MAX_RLP_SIZE], u32) {
    let mut buf = RlpBuffer::new();
    
    buf = rlp_encode_u64(buf, tx.chain_id);
    buf = rlp_encode_u64(buf, tx.nonce);
    buf = rlp_encode_field(buf, tx.max_priority_fee_per_gas);
    buf = rlp_encode_field(buf, tx.max_fee_per_gas);
    buf = rlp_encode_u64(buf, tx.gas_limit);
    buf = rlp_encode_address(buf, tx.to);
    buf = rlp_encode_field(buf, tx.value);
    buf = buf.write_byte(0x80); // empty data
    buf = buf.write_byte(0xc0); // empty access_list
    
    assert(buf.pos <= MAX_RLP_SIZE, "RLP fields buffer overflow");
    
    (buf.data, buf.pos)
}

/// Compute EIP-1559 signing hash: keccak256(0x02 || RLP([fields]))
pub fn eip1559_signing_hash(tx: Eip1559TxRlp) -> [u8; 32] {
    let (fields_rlp, fields_len) = encode_eip1559_fields(tx);
    
    let mut final_buf = RlpBuffer::new();
    
    final_buf = final_buf.write_byte(0x02);
    
    if fields_len <= 55 {
        final_buf = final_buf.write_byte(0xc0 + fields_len as u8);
    } else {
        let (len_bytes, len_len) = u64_to_be_bytes(fields_len as u64);
        final_buf = final_buf.write_byte(0xf7 + len_len as u8);
        for i in 0..8 {
            if i >= (8 - len_len) {
                final_buf = final_buf.write_byte(len_bytes[i]);
            }
        }
    }
    
    for i in 0..MAX_RLP_SIZE {
        if i < fields_len {
            final_buf = final_buf.write_byte(fields_rlp[i]);
        }
    }
    
    let total_len = final_buf.pos;
    assert(total_len <= MAX_RLP_SIZE, "RLP final buffer overflow");
    
    keccak256(final_buf.data, total_len)
}

/// Verify that a provided tx_hash matches the EIP-1559 signing hash
pub fn verify_tx_hash(tx: Eip1559TxRlp, expected_hash: [u8; 32]) {
    let computed_hash = eip1559_signing_hash(tx);
    for i in 0..32 {
        assert(computed_hash[i] == expected_hash[i], "tx_hash mismatch");
    }
}
