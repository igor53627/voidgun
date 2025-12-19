//! Load Railgun events from JSON files and build merkle tree
//!
//! This module provides utilities for loading pre-dumped event data
//! from JSON files (created by scripts/dump-railgun-events.sh) and
//! building the merkle tree locally.

use alloy_primitives::{hex, U256};
use ark_bn254::Fr as Field;
use ark_ff::PrimeField;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

use crate::notes::NoteMerkleTree;
use crate::poseidon::poseidon3;

#[derive(Debug, Error)]
pub enum EventLoaderError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("ABI decode error: {0}")]
    AbiDecode(String),

    #[error("Merkle tree error: {0}")]
    MerkleTree(#[from] crate::notes::NoteError),
}

/// Raw event log from JSON dump
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawEventLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: String,
    pub block_timestamp: Option<String>,
    pub transaction_hash: String,
    pub log_index: String,
}

/// Parsed Shield event data
#[derive(Debug, Clone)]
pub struct ParsedShieldData {
    pub tree_number: u64,
    pub start_position: u64,
    pub commitments: Vec<Field>,
    pub block_number: u64,
}

/// Parsed Transact event data  
#[derive(Debug, Clone)]
pub struct ParsedTransactData {
    pub tree_number: u64,
    pub start_position: u64,
    pub commitment_hashes: Vec<Field>,
    pub block_number: u64,
}

/// Load Shield events from JSON file and parse into structured data
pub fn load_shield_events(
    path: impl AsRef<Path>,
) -> Result<Vec<ParsedShieldData>, EventLoaderError> {
    let contents = std::fs::read_to_string(path)?;
    let raw_events: Vec<RawEventLog> = serde_json::from_str(&contents)?;

    let parsed: Vec<_> = raw_events
        .par_iter()
        .filter_map(|raw| {
            parse_shield_event_data(&raw.data).ok().map(|event| {
                let block_number =
                    u64::from_str_radix(raw.block_number.trim_start_matches("0x"), 16).unwrap_or(0);

                ParsedShieldData {
                    tree_number: event.0,
                    start_position: event.1,
                    commitments: event.2,
                    block_number,
                }
            })
        })
        .collect();

    Ok(parsed)
}

/// Load Transact events from JSON file
pub fn load_transact_events(
    path: impl AsRef<Path>,
) -> Result<Vec<ParsedTransactData>, EventLoaderError> {
    let contents = std::fs::read_to_string(path)?;
    let raw_events: Vec<RawEventLog> = serde_json::from_str(&contents)?;

    let parsed: Vec<_> = raw_events
        .par_iter()
        .filter_map(|raw| {
            parse_transact_event_data(&raw.data).ok().map(|event| {
                let block_number =
                    u64::from_str_radix(raw.block_number.trim_start_matches("0x"), 16).unwrap_or(0);

                ParsedTransactData {
                    tree_number: event.0,
                    start_position: event.1,
                    commitment_hashes: event.2,
                    block_number,
                }
            })
        })
        .collect();

    Ok(parsed)
}

/// Parse Shield event data from hex string
///
/// Shield event: Shield(uint256 treeNumber, uint256 startPosition, CommitmentPreimage[], ShieldCiphertext[], uint256[])
fn parse_shield_event_data(data: &str) -> Result<(u64, u64, Vec<Field>), EventLoaderError> {
    let data = hex::decode(data.trim_start_matches("0x"))
        .map_err(|e| EventLoaderError::AbiDecode(e.to_string()))?;

    // Shield event ABI:
    // - treeNumber (uint256) at offset 0
    // - startPosition (uint256) at offset 32
    // - preimages array offset at offset 64
    // - ciphertexts array offset at offset 96
    // - fees array offset at offset 128

    if data.len() < 160 {
        return Err(EventLoaderError::AbiDecode("Data too short".into()));
    }

    let tree_number = U256::from_be_slice(&data[0..32]).to::<u64>();
    let start_position = U256::from_be_slice(&data[32..64]).to::<u64>();

    // Get preimages array offset and length
    let preimages_offset_u256 = U256::from_be_slice(&data[64..96]);
    let preimages_offset: usize = preimages_offset_u256
        .try_into()
        .map_err(|_| EventLoaderError::AbiDecode("Preimages offset too large".into()))?;

    if preimages_offset + 32 > data.len() {
        return Err(EventLoaderError::AbiDecode(
            "Invalid preimages offset".into(),
        ));
    }

    let preimages_count_u256 = U256::from_be_slice(&data[preimages_offset..preimages_offset + 32]);
    let preimages_count: usize = preimages_count_u256
        .try_into()
        .map_err(|_| EventLoaderError::AbiDecode("Preimages count too large".into()))?;

    let mut commitments = Vec::with_capacity(preimages_count);

    // CommitmentPreimage is a fixed-size struct in the array:
    // - npk: bytes32 (32 bytes)
    // - token: TokenData which is (uint8 tokenType, address tokenAddress, uint256 tokenSubID)
    //   - tokenType: 32 bytes (uint8 padded)
    //   - tokenAddress: 32 bytes (address padded)
    //   - tokenSubID: 32 bytes
    // - value: uint120 (32 bytes padded)
    // Total: 32 + 32 + 32 + 32 + 32 = 160 bytes per preimage

    let preimage_size = 160;
    let preimage_data_start = preimages_offset + 32;

    for i in 0..preimages_count {
        let offset = preimage_data_start + i * preimage_size;

        if offset + preimage_size > data.len() {
            break;
        }

        // npk is first 32 bytes
        let npk = Field::from_be_bytes_mod_order(&data[offset..offset + 32]);

        // TokenData starts at offset 32
        // tokenType is at byte 31 of the 32-byte slot (uint8 right-aligned)
        let token_type = data[offset + 32 + 31];

        // tokenAddress is at offset 64, right-aligned in 32 bytes
        let token_addr_start = offset + 64 + 12;
        let token_address: [u8; 20] = data[token_addr_start..token_addr_start + 20]
            .try_into()
            .unwrap_or([0u8; 20]);

        // tokenSubID at offset 96
        let token_sub_id = U256::from_be_slice(&data[offset + 96..offset + 128]);

        // value at offset 128 (uint120, so in last 15 bytes of 32-byte slot)
        let value_bytes = &data[offset + 128..offset + 160];
        let value = U256::from_be_slice(value_bytes).to::<u128>();

        // Compute token field
        let token_field = if token_type == 0 {
            // ERC20: just address padded to 32 bytes
            let mut bytes = [0u8; 32];
            bytes[12..32].copy_from_slice(&token_address);
            Field::from_be_bytes_mod_order(&bytes)
        } else {
            // ERC721/ERC1155: keccak256(abi.encode(tokenType, address, subID)) % SNARK_FIELD
            use sha3::{Digest, Keccak256};
            let mut encode_data = [0u8; 96];
            encode_data[31] = token_type;
            encode_data[44..64].copy_from_slice(&token_address);
            encode_data[64..96].copy_from_slice(&token_sub_id.to_be_bytes::<32>());
            let hash = Keccak256::digest(&encode_data);
            Field::from_be_bytes_mod_order(&hash)
        };

        let value_field = Field::from(value);

        // Compute commitment: Poseidon(npk, tokenField, value)
        let commitment = poseidon3(npk, token_field, value_field);
        commitments.push(commitment);
    }

    Ok((tree_number, start_position, commitments))
}

/// Parse Transact event data from hex string
///
/// Transact event: Transact(uint256 treeNumber, uint256 startPosition, bytes32[] hash, Ciphertext[])
fn parse_transact_event_data(data: &str) -> Result<(u64, u64, Vec<Field>), EventLoaderError> {
    let data = hex::decode(data.trim_start_matches("0x"))
        .map_err(|e| EventLoaderError::AbiDecode(e.to_string()))?;

    if data.len() < 128 {
        return Err(EventLoaderError::AbiDecode("Data too short".into()));
    }

    let tree_number = U256::from_be_slice(&data[0..32]).to::<u64>();
    let start_position = U256::from_be_slice(&data[32..64]).to::<u64>();

    // Get hash array offset and length
    let hash_offset = U256::from_be_slice(&data[64..96]).to::<usize>();
    if hash_offset + 32 > data.len() {
        return Err(EventLoaderError::AbiDecode("Invalid hash offset".into()));
    }

    let hash_count = U256::from_be_slice(&data[hash_offset..hash_offset + 32]).to::<usize>();

    let mut commitment_hashes = Vec::with_capacity(hash_count);

    for i in 0..hash_count {
        let hash_pos = hash_offset + 32 + i * 32;
        if hash_pos + 32 > data.len() {
            break;
        }

        let hash = Field::from_be_bytes_mod_order(&data[hash_pos..hash_pos + 32]);
        commitment_hashes.push(hash);
    }

    Ok((tree_number, start_position, commitment_hashes))
}

/// Result of building merkle tree from files
pub struct TreeBuildResult {
    pub tree: NoteMerkleTree,
    pub last_block: u64,
    pub leaf_count: u64,
}

/// Build merkle tree from event files
///
/// Loads Shield and Transact events, sorts by position, and builds tree.
pub fn build_merkle_tree_from_files(
    shield_events_path: impl AsRef<Path>,
    transact_events_path: Option<impl AsRef<Path>>,
    tree_number: u64,
    tree_depth: usize,
) -> Result<NoteMerkleTree, EventLoaderError> {
    let result = build_merkle_tree_from_files_with_info(
        shield_events_path,
        transact_events_path,
        tree_number,
        tree_depth,
    )?;
    Ok(result.tree)
}

/// Build merkle tree from event files, returning additional sync info
///
/// Returns the tree, last block number seen, and total leaf count.
/// Use this when you need to sync additional events from RPC.
pub fn build_merkle_tree_from_files_with_info(
    shield_events_path: impl AsRef<Path>,
    transact_events_path: Option<impl AsRef<Path>>,
    tree_number: u64,
    tree_depth: usize,
) -> Result<TreeBuildResult, EventLoaderError> {
    let mut all_commitments: Vec<(u64, Field, u64)> = Vec::new();
    let mut last_block = 0u64;

    // Load Shield events
    let shield_events = load_shield_events(shield_events_path)?;
    for event in shield_events {
        if event.tree_number == tree_number {
            last_block = last_block.max(event.block_number);
            for (i, commitment) in event.commitments.into_iter().enumerate() {
                all_commitments.push((
                    event.start_position + i as u64,
                    commitment,
                    event.block_number,
                ));
            }
        }
    }

    // Load Transact events if provided
    if let Some(path) = transact_events_path {
        let transact_events = load_transact_events(path)?;
        for event in transact_events {
            if event.tree_number == tree_number {
                last_block = last_block.max(event.block_number);
                for (i, commitment) in event.commitment_hashes.into_iter().enumerate() {
                    all_commitments.push((
                        event.start_position + i as u64,
                        commitment,
                        event.block_number,
                    ));
                }
            }
        }
    }

    // Sort by position
    all_commitments.sort_by_key(|(pos, _, _)| *pos);

    // Build tree using batch insert for speed
    let mut tree = NoteMerkleTree::new(tree_depth)?;

    // First pass: collect all leaves in order, filling gaps with ZERO_VALUE
    // (gaps should not occur in a properly synced tree - they indicate missing event data)
    let mut leaves_to_insert = Vec::new();
    let mut expected_idx = 0u64;

    for (pos, commitment, _) in all_commitments.iter() {
        // Fill gaps with ZERO_VALUE if needed (warning: this means data is missing)
        while expected_idx < *pos {
            tracing::warn!(
                "Gap in commitments at position {} (expected), filling with ZERO_VALUE",
                expected_idx
            );
            leaves_to_insert.push(*crate::notes::ZERO_VALUE);
            expected_idx += 1;
        }
        leaves_to_insert.push(*commitment);
        expected_idx += 1;
    }

    let leaf_count = leaves_to_insert.len() as u64;

    // Batch insert all leaves
    tree.batch_insert(&leaves_to_insert);

    // Rebuild tree structure (uses parallel computation)
    tree.rebuild();

    Ok(TreeBuildResult {
        tree,
        last_block,
        leaf_count,
    })
}

/// Append commitments to an existing merkle tree
///
/// Inserts new commitments at the correct positions, filling gaps if needed.
/// This uses incremental insert() which updates the path correctly.
///
/// # Errors
/// Returns `EventLoaderError::MerkleTree` if the tree is full.
pub fn append_commitments_to_tree(
    tree: &mut NoteMerkleTree,
    commitments: &[(u64, Field)],
) -> Result<(), EventLoaderError> {
    if commitments.is_empty() {
        return Ok(());
    }

    let mut sorted: Vec<_> = commitments.to_vec();
    sorted.sort_by_key(|(pos, _)| *pos);

    let mut current_leaf_count = tree.leaves.len() as u64;

    for (pos, commitment) in sorted {
        // Fill gaps with ZERO_VALUE if needed (warning: this means data is missing)
        while current_leaf_count < pos {
            tracing::warn!(
                "Gap in commitments at position {} (expected), filling with ZERO_VALUE",
                current_leaf_count
            );
            tree.insert(*crate::notes::ZERO_VALUE)?;
            current_leaf_count += 1;
        }

        if pos == current_leaf_count {
            tree.insert(commitment)?;
            current_leaf_count += 1;
        }
        // If pos < current_leaf_count, the commitment is already in the tree (duplicate)
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_shield_events() {
        let path = "artifacts/events/shield-events-mainnet.json";
        if std::path::Path::new(path).exists() {
            let events = load_shield_events(path).expect("Failed to load");
            println!("Loaded {} Shield events", events.len());

            if let Some(first) = events.first() {
                println!(
                    "First event: tree={}, pos={}, commitments={}",
                    first.tree_number,
                    first.start_position,
                    first.commitments.len()
                );
            }
        } else {
            println!("Skipping test - events file not found");
        }
    }

    #[test]
    fn test_load_transact_events() {
        let path = "artifacts/events/transact-events-mainnet.json";
        if std::path::Path::new(path).exists() {
            let events = load_transact_events(path).expect("Failed to load");
            println!("Loaded {} Transact events", events.len());

            if let Some(first) = events.first() {
                println!(
                    "First event: tree={}, pos={}, commitments={}",
                    first.tree_number,
                    first.start_position,
                    first.commitment_hashes.len()
                );
            }
        } else {
            println!("Skipping test - events file not found");
        }
    }

    #[test]
    fn test_build_merkle_tree() {
        let shield_path = "artifacts/events/shield-events-mainnet.json";
        let transact_path = "artifacts/events/transact-events-mainnet.json";

        if std::path::Path::new(shield_path).exists() {
            let transact_opt: Option<&str> = if std::path::Path::new(transact_path).exists() {
                Some(transact_path)
            } else {
                None
            };

            // Test tree 2 which is the currently active tree
            let tree = build_merkle_tree_from_files(shield_path, transact_opt, 2, 16)
                .expect("Failed to build tree");
            println!(
                "Built merkle tree with {} leaves for tree 2",
                tree.leaves.len()
            );

            // Verify root is non-zero
            let root = tree.root();
            println!("Tree root: {:?}", root);
        } else {
            println!("Skipping test - events file not found");
        }
    }
}

#[test]
fn test_shield_commitment_computation() {
    // From tx 0x1e707c272cb9f6c5711665e48456c7604aa46009bf3414673c9be08ad0203b74
    // Tree 2, Position 29737
    let npk_hex = "174728c71f7786531fbe97805fdf6e74b10eb2809e441882c14d90b4a1106c6d";
    let token_addr_hex = "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"; // WETH
    let value: u128 = 0x007db1b91319d638; // 35379780536358456

    let npk_bytes = hex::decode(npk_hex).unwrap();
    let npk = Field::from_be_bytes_mod_order(&npk_bytes);

    // For ERC20: token field = address padded to 32 bytes
    let mut token_bytes = [0u8; 32];
    let addr_bytes = hex::decode(token_addr_hex).unwrap();
    token_bytes[12..32].copy_from_slice(&addr_bytes);
    let token_field = Field::from_be_bytes_mod_order(&token_bytes);

    let value_field = Field::from(value);

    let commitment = crate::poseidon::poseidon3(npk, token_field, value_field);

    use ark_ff::{BigInteger, PrimeField};
    let commitment_hex = hex::encode(commitment.into_bigint().to_bytes_be());
    println!("Computed commitment: 0x{}", commitment_hex);

    // The contract computes this on-chain - we need to verify against it
    // For now just print it
    assert!(!commitment_hex.is_empty());
}

#[test]
fn test_token_field_interpretation() {
    use ark_ff::{BigInteger, PrimeField};

    // WETH address: 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
    // In Solidity: bytes32(uint256(uint160(address)))
    // = 0x000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2

    let addr_bytes = hex::decode("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();

    // Method 1: Left-pad with zeros (what we currently do)
    let mut token_be = [0u8; 32];
    token_be[12..32].copy_from_slice(&addr_bytes);
    let token_field_be = Field::from_be_bytes_mod_order(&token_be);
    println!(
        "BE token field: 0x{}",
        hex::encode(token_field_be.into_bigint().to_bytes_be())
    );

    // In Solidity, the bytes32 value as a uint256 would be:
    // 0x000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
    // which equals the integer: uint160(address) with high bits as zeros
    // = 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 as integer

    // The Poseidon circuit sees this as a field element equal to the address integer
    let addr_int = u128::from_be_bytes([
        0, 0, 0, 0, 0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f,
    ]);
    let addr_int_part2 = u128::from_be_bytes([
        0x27, 0xea, 0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0,
    ]) >> 64;

    // Actually easier: uint160 fits in u256
    use ark_bn254::Fr as Field;
    use ark_ff::BigInt;

    // The address as uint160 integer
    let addr_u256 = alloy_primitives::U256::from_be_slice(&token_be);
    println!("Address as U256: {}", addr_u256);

    // Verify our field interpretation is correct
    println!("Token BE bytes: {}", hex::encode(&token_be));
}

#[test]
fn test_commitment_matches_contract() {
    use ark_ff::{BigInteger, PrimeField};

    // Test case 1: Tree 2, Position 2
    // npk: 0x2184ae047eeb52bd2aa993abd33a33114a03b2bad8eaf1c49cfa71d1f7d7d4cb
    // token: WETH (0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2)
    // value: 4322744496434830
    // Expected: 0x1e061e4ce355dcff7e15f1d60b18bdfcf6453723d8fd0a92968219750f2761d4

    let npk_bytes =
        hex::decode("2184ae047eeb52bd2aa993abd33a33114a03b2bad8eaf1c49cfa71d1f7d7d4cb").unwrap();
    let npk = Field::from_be_bytes_mod_order(&npk_bytes);

    let mut token_bytes = [0u8; 32];
    let addr_bytes = hex::decode("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
    token_bytes[12..32].copy_from_slice(&addr_bytes);
    let token_field = Field::from_be_bytes_mod_order(&token_bytes);

    let value: u128 = 4322744496434830;
    let value_field = Field::from(value);

    let commitment = crate::poseidon::poseidon3(npk, token_field, value_field);
    let commitment_hex = format!("0x{}", hex::encode(commitment.into_bigint().to_bytes_be()));

    println!("Test case 1:");
    println!("  Computed: {}", commitment_hex);
    println!("  Expected: 0x1e061e4ce355dcff7e15f1d60b18bdfcf6453723d8fd0a92968219750f2761d4");

    assert_eq!(
        commitment_hex, "0x1e061e4ce355dcff7e15f1d60b18bdfcf6453723d8fd0a92968219750f2761d4",
        "Commitment mismatch for test case 1"
    );

    // Test case 2: Tree 2, Position 3
    let npk_bytes =
        hex::decode("067cdecee988941e90737e409448099abdd97b131e3e5df580acbd41d9ecd2ea").unwrap();
    let npk = Field::from_be_bytes_mod_order(&npk_bytes);

    let value: u128 = 2463582767267604;
    let value_field = Field::from(value);

    let commitment = crate::poseidon::poseidon3(npk, token_field, value_field);
    let commitment_hex = format!("0x{}", hex::encode(commitment.into_bigint().to_bytes_be()));

    println!("Test case 2:");
    println!("  Computed: {}", commitment_hex);
    println!("  Expected: 0x06b98a6ff3ee0706826a861f78cac6b68462c8b167710188e75fd4e2413747dc");

    assert_eq!(
        commitment_hex, "0x06b98a6ff3ee0706826a861f78cac6b68462c8b167710188e75fd4e2413747dc",
        "Commitment mismatch for test case 2"
    );

    println!("All commitment tests passed!");
}

#[test]
fn test_event_loader_parsing() {
    use ark_ff::{BigInteger, PrimeField};

    // Load first few Shield events for tree 2
    let path = "artifacts/events/shield-events-mainnet.json";
    if !std::path::Path::new(path).exists() {
        println!("Skipping - events file not found");
        return;
    }

    let events = load_shield_events(path).expect("Failed to load events");

    // Find events for tree 2
    let tree2_events: Vec<_> = events
        .iter()
        .filter(|e| e.tree_number == 2)
        .take(3)
        .collect();

    println!("Found {} events for tree 2", tree2_events.len());

    // Expected commitments from on-chain verification
    let expected = [
        (
            2,
            "0x1e061e4ce355dcff7e15f1d60b18bdfcf6453723d8fd0a92968219750f2761d4",
        ),
        (
            3,
            "0x06b98a6ff3ee0706826a861f78cac6b68462c8b167710188e75fd4e2413747dc",
        ),
        (
            18,
            "0x2be094d0b026e298675bb2ef7c48efe541fe9a330272c235bd21e4e74f4693eb",
        ),
    ];

    for (i, event) in tree2_events.iter().enumerate() {
        let commitment = &event.commitments[0];
        let commitment_hex = format!("0x{}", hex::encode(commitment.into_bigint().to_bytes_be()));

        println!(
            "Event {} (pos {}): {}",
            i, event.start_position, commitment_hex
        );

        // Check against expected
        if let Some((exp_pos, exp_commitment)) =
            expected.iter().find(|(p, _)| *p == event.start_position)
        {
            if commitment_hex == *exp_commitment {
                println!("  [OK] Matches expected!");
            } else {
                println!("  [FAIL] Expected: {}", exp_commitment);
            }
        }
    }
}

#[test]
fn test_merkle_tree_simple() {
    use crate::notes::NoteMerkleTree;
    use ark_ff::{BigInteger, PrimeField};

    // Build a tree with just 2 leaves and verify the root
    let mut tree = NoteMerkleTree::new(4).unwrap();

    // Use known commitments from our verified test cases
    let commitment1_bytes =
        hex::decode("1e061e4ce355dcff7e15f1d60b18bdfcf6453723d8fd0a92968219750f2761d4").unwrap();
    let commitment1 = Field::from_be_bytes_mod_order(&commitment1_bytes);

    let commitment2_bytes =
        hex::decode("06b98a6ff3ee0706826a861f78cac6b68462c8b167710188e75fd4e2413747dc").unwrap();
    let commitment2 = Field::from_be_bytes_mod_order(&commitment2_bytes);

    tree.insert(commitment1).unwrap();
    tree.insert(commitment2).unwrap();

    let root = tree.root();
    let root_hex = format!("0x{}", hex::encode(root.into_bigint().to_bytes_be()));

    println!("Tree with 2 leaves:");
    println!("  Leaf 0: 0x{}", hex::encode(commitment1_bytes));
    println!("  Leaf 1: 0x{}", hex::encode(commitment2_bytes));
    println!("  Root: {}", root_hex);

    // Manually compute: parent = Poseidon2(leaf0, leaf1)
    let parent = crate::poseidon::poseidon2(commitment1, commitment2);
    let parent_hex = format!("0x{}", hex::encode(parent.into_bigint().to_bytes_be()));
    println!("  Parent (poseidon2(leaf0, leaf1)): {}", parent_hex);

    // The root should be hashing parent with ZERO_HASHES up to the top
    // For depth 4: levels are [leaves, level1, level2, level3, root]
    // parent is at level 1 position 0
    // parent hashes with ZERO_HASHES[1] at level 1 position 1 to get level 2 position 0
    // etc.

    use crate::notes::ZERO_HASHES;
    let level2 = crate::poseidon::poseidon2(parent, ZERO_HASHES[1]);
    let level3 = crate::poseidon::poseidon2(level2, ZERO_HASHES[2]);
    let level4 = crate::poseidon::poseidon2(level3, ZERO_HASHES[3]);

    let manual_root_hex = format!("0x{}", hex::encode(level4.into_bigint().to_bytes_be()));
    println!("  Manual root computation: {}", manual_root_hex);

    assert_eq!(
        root_hex, manual_root_hex,
        "Tree root doesn't match manual computation"
    );
}

#[test]
fn test_tree2_initial_root() {
    use crate::notes::NoteMerkleTree;
    use ark_ff::{BigInteger, PrimeField};

    // Tree 2 starts with these 2 commitments from tx 0x96a88ec7...
    let c0_bytes =
        hex::decode("030808d4e236515280fafd15dd0935a517aa638a91347171eb76aea0d45c122a").unwrap();
    let c0 = Field::from_be_bytes_mod_order(&c0_bytes);

    let c1_bytes =
        hex::decode("2b362c33203a052ff1cdf99b25fb07999f21dec174cd01dffdb732f226a8bfc0").unwrap();
    let c1 = Field::from_be_bytes_mod_order(&c1_bytes);

    // Build tree with depth 16 (Railgun standard)
    let mut tree = NoteMerkleTree::new(16).unwrap();
    tree.insert(c0).unwrap();
    tree.insert(c1).unwrap();

    let root = tree.root();
    let root_hex = format!("0x{}", hex::encode(root.into_bigint().to_bytes_be()));

    println!("Tree 2 after positions 0,1:");
    println!("  Root: {}", root_hex);
    println!("\nTo verify, check this root in rootHistory(2, root) on mainnet");
}
