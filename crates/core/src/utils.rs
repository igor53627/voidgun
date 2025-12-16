use ark_bn254::Fr as Field;
use ark_ff::PrimeField;
use alloy_primitives::{Address, U256};

pub fn u256_to_field(value: U256) -> Field {
    Field::from_be_bytes_mod_order(&value.to_be_bytes::<32>())
}

pub fn address_to_field(addr: Address) -> Field {
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(addr.as_slice());
    Field::from_be_bytes_mod_order(&bytes)
}
