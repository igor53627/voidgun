use crate::rlp::{Eip1559TxRlp, eip1559_signing_hash, u64_to_be_bytes, rlp_encode_u64, rlp_encode_field, RlpBuffer};

#[test]
fn test_u64_to_be_bytes_zero() {
    let (bytes, len) = u64_to_be_bytes(0);
    assert(len == 0, "zero should have len 0");
}

#[test]
fn test_u64_to_be_bytes_one() {
    let (bytes, len) = u64_to_be_bytes(1);
    assert(len == 1, "1 should have len 1");
    assert(bytes[7] == 1, "1 should be at last byte");
}

#[test]
fn test_u64_to_be_bytes_127() {
    let (bytes, len) = u64_to_be_bytes(127);
    assert(len == 1, "127 should have len 1");
    assert(bytes[7] == 127, "127 should be at last byte");
}

#[test]
fn test_u64_to_be_bytes_128() {
    let (bytes, len) = u64_to_be_bytes(128);
    assert(len == 1, "128 should have len 1");
    assert(bytes[7] == 128, "128 should be at last byte");
}

#[test]
fn test_u64_to_be_bytes_255() {
    let (bytes, len) = u64_to_be_bytes(255);
    assert(len == 1, "255 should have len 1");
    assert(bytes[7] == 255, "255 should be at last byte");
}

#[test]
fn test_u64_to_be_bytes_256() {
    let (bytes, len) = u64_to_be_bytes(256);
    assert(len == 2, "256 should have len 2");
    assert(bytes[6] == 1, "256 high byte");
    assert(bytes[7] == 0, "256 low byte");
}

#[test]
fn test_u64_to_be_bytes_max() {
    let max: u64 = 0xffffffffffffffff;
    let (bytes, len) = u64_to_be_bytes(max);
    assert(len == 8, "max u64 should have len 8");
    for i in 0..8 {
        assert(bytes[i] == 0xff, "all bytes should be 0xff");
    }
}

#[test]
fn test_rlp_encode_u64_zero() {
    let buf = RlpBuffer::new();
    let result = rlp_encode_u64(buf, 0);
    assert(result.pos == 1, "zero encodes to 1 byte");
    assert(result.data[0] == 0x80, "zero encodes as 0x80");
}

#[test]
fn test_rlp_encode_u64_single_byte() {
    let buf = RlpBuffer::new();
    let result = rlp_encode_u64(buf, 127);
    assert(result.pos == 1, "127 encodes to 1 byte");
    assert(result.data[0] == 127, "127 encodes as itself");
}

#[test]
fn test_rlp_encode_u64_needs_prefix() {
    let buf = RlpBuffer::new();
    let result = rlp_encode_u64(buf, 128);
    assert(result.pos == 2, "128 encodes to 2 bytes");
    assert(result.data[0] == 0x81, "prefix for 1-byte string");
    assert(result.data[1] == 128, "128 value");
}

#[test]
fn test_rlp_encode_field_zero() {
    let buf = RlpBuffer::new();
    let result = rlp_encode_field(buf, 0);
    assert(result.pos == 1, "zero field encodes to 1 byte");
    assert(result.data[0] == 0x80, "zero field encodes as 0x80");
}

#[test]
fn test_rlp_encode_field_small() {
    let buf = RlpBuffer::new();
    let result = rlp_encode_field(buf, 127);
    assert(result.pos == 1, "127 encodes to 1 byte");
    assert(result.data[0] == 127, "127 encodes as itself");
}

#[test]
fn test_rlp_encode_field_needs_prefix() {
    let buf = RlpBuffer::new();
    let result = rlp_encode_field(buf, 128);
    assert(result.pos == 2, "128 encodes to 2 bytes");
    assert(result.data[0] == 0x81, "prefix for 1-byte string");
    assert(result.data[1] == 128, "128 value");
}

#[test]
fn test_eip1559_signing_hash_simple() {
    let tx = Eip1559TxRlp {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 1,
        gas_limit: 21000,
        to: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        value: 0,
    };
    
    let hash = eip1559_signing_hash(tx);
    
    let expected: [u8; 32] = [
        0xda, 0xca, 0x52, 0xcf, 0xea, 0x52, 0x35, 0xbd,
        0x34, 0x45, 0xa8, 0x8c, 0x83, 0x71, 0xe6, 0x6d,
        0x7e, 0x26, 0xd5, 0x59, 0x73, 0x0f, 0xdb, 0x30,
        0xa7, 0xc1, 0x92, 0xf5, 0x7e, 0x47, 0x30, 0x48
    ];
    
    for i in 0..32 {
        assert(hash[i] == expected[i], "Hash mismatch at byte");
    }
}

#[test]
fn test_eip1559_signing_hash_complex() {
    let tx = Eip1559TxRlp {
        chain_id: 1,
        nonce: 42,
        max_priority_fee_per_gas: 2000000000,
        max_fee_per_gas: 100000000000,
        gas_limit: 21000,
        to: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        value: 1000000000000000000,
    };
    
    let hash = eip1559_signing_hash(tx);
    
    let expected: [u8; 32] = [
        0x25, 0xd7, 0x4c, 0xc0, 0xfa, 0x8c, 0x42, 0x7e,
        0xb0, 0x02, 0x9a, 0xda, 0x9c, 0xe6, 0x9d, 0xfb,
        0x33, 0x56, 0xc2, 0xb8, 0xdb, 0xbc, 0x99, 0x26,
        0x57, 0xc6, 0xa0, 0x2a, 0x3a, 0x02, 0x88, 0x7b
    ];
    
    for i in 0..32 {
        assert(hash[i] == expected[i], "Hash mismatch at byte");
    }
}
