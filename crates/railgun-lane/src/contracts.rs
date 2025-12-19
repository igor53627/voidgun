//! Railgun smart contract interaction
//!
//! This module handles:
//! - Contract event parsing (Shield, Transact/Unshield events)
//! - Transaction building for shield/transact/unshield operations
//! - Proof submission to the Railgun contract
//!
//! # Railgun Contract Addresses
//!
//! Ethereum Mainnet:
//! - Relay: 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9
//! - Smart Wallet: 0xc0BEF2D373A1EfaDE8B952f33c1370E486f209Cc
//!
//! The contracts are upgradeable proxies.

use alloy_primitives::{Address, FixedBytes, Uint, B256, U256};
use alloy_sol_types::{sol, SolCall};
use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("Invalid event data: {0}")]
    InvalidEventData(String),

    #[error("Decoding failed: {0}")]
    DecodingFailed(String),

    #[error("Transaction build failed: {0}")]
    TransactionBuildFailed(String),

    #[error("RPC error: {0}")]
    RpcError(String),
}

/// Railgun contract addresses per chain
#[derive(Clone, Debug)]
pub struct RailgunAddresses {
    /// Relay contract (handles transactions)
    pub relay: Address,
    /// Smart wallet contract (stores state)
    pub smart_wallet: Address,
}

impl RailgunAddresses {
    /// Ethereum mainnet addresses
    pub fn ethereum() -> Self {
        Self {
            relay: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
                .parse()
                .unwrap(),
            smart_wallet: "0xc0BEF2D373A1EfaDE8B952f33c1370E486f209Cc"
                .parse()
                .unwrap(),
        }
    }

    /// Polygon mainnet addresses
    pub fn polygon() -> Self {
        Self {
            relay: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
                .parse()
                .unwrap(),
            smart_wallet: "0xc0BEF2D373A1EfaDE8B952f33c1370E486f209Cc"
                .parse()
                .unwrap(),
        }
    }

    /// Sepolia testnet addresses
    pub fn sepolia() -> Self {
        Self {
            relay: "0x464a0c9e62534b3b160c35638DD7d5cf761f429e"
                .parse()
                .unwrap(), // Delegator
            smart_wallet: "0x942D5026b421cf2705363A525897576cFAdA5964"
                .parse()
                .unwrap(), // Proxy
        }
    }

    /// Get addresses for a chain ID
    pub fn for_chain(chain_id: u64) -> Option<Self> {
        match chain_id {
            1 => Some(Self::ethereum()),
            137 => Some(Self::polygon()),
            11155111 => Some(Self::sepolia()),
            _ => None,
        }
    }
}

// Define Railgun event types using alloy sol! macro
sol! {
    /// Token data
    struct TokenData {
        uint8 tokenType;
        address tokenAddress;
        uint256 tokenSubID;
    }

    /// Commitment preimage
    struct CommitmentPreimage {
        bytes32 npk;
        TokenData token;
        uint120 value;
    }

    /// ShieldCiphertext structure (for Shield event)
    struct ShieldCiphertext {
        bytes32[3] encryptedBundle;
        bytes32 shieldKey;
    }

    /// Shield event - emitted when tokens enter the privacy pool
    /// Note: The event includes preimages, from which the commitment is computed on-chain
    event Shield(
        uint256 treeNumber,
        uint256 startPosition,
        CommitmentPreimage[] preimages,
        ShieldCiphertext[] ciphertexts,
        uint256[] fees
    );

    /// Transact event - emitted for private transfers and unshields
    event Transact(
        uint256 treeNumber,
        uint256 startPosition,
        bytes32[] hash,
        Ciphertext[] ciphertext
    );

    /// Ciphertext structure for transact events
    /// Note: The struct signature must match exactly for event topic calculation:
    /// (bytes32[4],bytes32,bytes32,bytes,bytes)
    struct Ciphertext {
        bytes32[4] ciphertext;
        bytes32 ephemeralKey;
        bytes32 blindedSenderViewingKey;
        bytes annotationData;
        bytes memo;
    }

    /// Nullifier event - emitted when a note is spent
    event Nullifiers(
        uint256 treeNumber,
        bytes32[] nullifiers
    );

    /// Shield function signature
    function shield(
        ShieldRequest[] calldata requests
    ) external;

    /// Shield request structure (uses shared structs above)
    struct ShieldRequest {
        CommitmentPreimage preimage;
        ShieldCiphertext ciphertext;
    }

    /// Transact function signature
    function transact(
        BoundParams calldata boundParams,
        VerifyInputs calldata verifyInputs
    ) external;

    /// Bound parameters for transact
    struct BoundParams {
        uint16 treeNumber;
        uint48 minGasPrice;
        bytes32 unshield;
        uint64 chainID;
        address adaptContract;
        bytes32 adaptParams;
        Commitment[] commitments;
    }

    /// Commitment structure
    struct Commitment {
        bytes32 hash;
        bytes ciphertext;
    }

    /// Verify inputs for transact
    struct VerifyInputs {
        Proof proof;
        bytes32 merkleRoot;
        bytes32[] nullifiers;
        bytes32[] commitments;
    }

    /// Groth16 proof structure
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }
}

/// Shield ciphertext data for trial decryption
#[derive(Clone, Debug)]
pub struct ParsedShieldCiphertext {
    /// Encrypted bundle (3 x 32 bytes)
    pub encrypted_bundle: [[u8; 32]; 3],
    /// Shield key (receiver's viewing key derived)
    pub shield_key: [u8; 32],
}

/// Shield preimage data (for reconstructing notes)
#[derive(Clone, Debug)]
pub struct ParsedShieldPreimage {
    /// Nullifier public key
    pub npk: Field,
    /// Token address (as field)
    pub token: Field,
    /// Token address (raw)
    pub token_address: alloy_primitives::Address,
    /// Value
    pub value: u128,
}

/// Parsed Shield event
#[derive(Clone, Debug)]
pub struct ParsedShieldEvent {
    /// Tree number
    pub tree_number: u64,
    /// Start position in tree
    pub start_position: u64,
    /// Commitments (as field elements)
    pub commitments: Vec<Field>,
    /// Shield ciphertexts for trial decryption
    pub ciphertexts: Vec<ParsedShieldCiphertext>,
    /// Shield preimages (contains npk, token, value)
    pub preimages: Vec<ParsedShieldPreimage>,
    /// Block number
    pub block_number: u64,
    /// Transaction hash
    pub tx_hash: B256,
}

/// Parsed Transact event
#[derive(Clone, Debug)]
pub struct ParsedTransactEvent {
    /// Tree number
    pub tree_number: u64,
    /// Start position in tree
    pub start_position: u64,
    /// Output commitment hashes
    pub commitment_hashes: Vec<Field>,
    /// Encrypted ciphertexts for trial decryption
    pub ciphertexts: Vec<Vec<u8>>,
    /// Block number
    pub block_number: u64,
    /// Transaction hash
    pub tx_hash: B256,
}

/// Parsed Nullifier event
#[derive(Clone, Debug)]
pub struct ParsedNullifierEvent {
    /// Tree number
    pub tree_number: u64,
    /// Nullifiers that were revealed (notes spent)
    pub nullifiers: Vec<Field>,
    /// Block number
    pub block_number: u64,
    /// Transaction hash
    pub tx_hash: B256,
}

/// Event scanner for syncing Railgun state
pub struct EventScanner {
    /// Contract addresses
    pub addresses: RailgunAddresses,
    /// Chain ID
    pub chain_id: u64,
}

impl EventScanner {
    pub fn new(chain_id: u64) -> Option<Self> {
        RailgunAddresses::for_chain(chain_id).map(|addresses| Self {
            addresses,
            chain_id,
        })
    }

    /// Parse a Shield event from raw log data
    pub fn parse_shield_event(
        &self,
        log_data: &[u8],
        _log_topics: &[B256],
        block_number: u64,
        tx_hash: B256,
    ) -> Result<ParsedShieldEvent, ContractError> {
        // Simplified parsing - in production, use alloy's ABI decoding
        // This is a placeholder showing the structure

        // Parse tree number (first 32 bytes)
        let tree_number = if log_data.len() >= 32 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&log_data[24..32]);
            u64::from_be_bytes(bytes)
        } else {
            return Err(ContractError::InvalidEventData("log too short".into()));
        };

        // Parse start position (next 32 bytes)
        let start_position = if log_data.len() >= 64 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&log_data[56..64]);
            u64::from_be_bytes(bytes)
        } else {
            return Err(ContractError::InvalidEventData("log too short".into()));
        };

        // TODO: Parse commitments array and ciphertexts from raw bytes
        // For now, return empty - the RPC client's parse_shield_log handles this properly
        let commitments = Vec::new();
        let ciphertexts = Vec::new();
        let preimages = Vec::new();

        Ok(ParsedShieldEvent {
            tree_number,
            start_position,
            commitments,
            ciphertexts,
            preimages,
            block_number,
            tx_hash,
        })
    }

    /// Parse a Nullifier event from raw log data
    pub fn parse_nullifier_event(
        &self,
        log_data: &[u8],
        _log_topics: &[B256],
        block_number: u64,
        tx_hash: B256,
    ) -> Result<ParsedNullifierEvent, ContractError> {
        // Parse tree number (first 32 bytes)
        let tree_number = if log_data.len() >= 32 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&log_data[24..32]);
            u64::from_be_bytes(bytes)
        } else {
            return Err(ContractError::InvalidEventData("log too short".into()));
        };

        // TODO: Parse nullifiers array
        let nullifiers = Vec::new();

        Ok(ParsedNullifierEvent {
            tree_number,
            nullifiers,
            block_number,
            tx_hash,
        })
    }
}

/// Transaction builder for Railgun operations
pub struct TransactionBuilder {
    /// Contract addresses
    pub addresses: RailgunAddresses,
    /// Chain ID
    pub chain_id: u64,
}

impl TransactionBuilder {
    pub fn new(chain_id: u64) -> Option<Self> {
        RailgunAddresses::for_chain(chain_id).map(|addresses| Self {
            addresses,
            chain_id,
        })
    }

    /// Build calldata for shield transaction
    ///
    /// # Arguments
    /// * `token` - Token address
    /// * `amount` - Amount to shield
    /// * `npk` - Nullifier public key (Poseidon(mpk, random))
    /// * `encrypted_bundle` - 3x32 byte encrypted ciphertext bundle
    /// * `shield_key` - 32 byte shield key for decryption
    pub fn build_shield_calldata(
        &self,
        token: Address,
        amount: U256,
        npk: Field,
        encrypted_bundle: [[u8; 32]; 3],
        shield_key: [u8; 32],
    ) -> Result<Vec<u8>, ContractError> {
        let token_data = TokenData {
            tokenType: 0, // ERC20
            tokenAddress: token,
            tokenSubID: U256::ZERO,
        };

        let value_u128: u128 = amount
            .try_into()
            .map_err(|_| ContractError::InvalidEventData("value overflow".into()))?;

        let preimage = CommitmentPreimage {
            npk: field_to_b256(&npk),
            token: token_data,
            value: Uint::<120, 2>::from(value_u128),
        };

        let ciphertext = ShieldCiphertext {
            encryptedBundle: encrypted_bundle.map(FixedBytes::from),
            shieldKey: FixedBytes::from(shield_key),
        };

        let request = ShieldRequest {
            preimage,
            ciphertext,
        };

        let call = shieldCall {
            requests: vec![request],
        };

        Ok(call.abi_encode())
    }

    /// Build calldata for transact (private transfer or unshield)
    pub fn build_transact_calldata(
        &self,
        proof: &crate::prover::RailgunProof,
        merkle_root: Field,
        nullifiers: &[Field],
        output_commitments: &[(Field, Vec<u8>)], // (hash, ciphertext)
        tree_number: u16,
        min_gas_price: u64,
        is_unshield: bool,
        unshield_recipient: Option<Address>,
    ) -> Result<Vec<u8>, ContractError> {
        let sol_proof = proof
            .to_solidity_proof()
            .map_err(|e| ContractError::TransactionBuildFailed(e.to_string()))?;

        let proof_struct = Proof {
            a: sol_proof.a.map(|b| U256::from_be_bytes(b)),
            b: sol_proof
                .b
                .map(|inner| inner.map(|b| U256::from_be_bytes(b))),
            c: sol_proof.c.map(|b| U256::from_be_bytes(b)),
        };

        let nullifier_bytes: Vec<FixedBytes<32>> =
            nullifiers.iter().map(|f| field_to_b256(f)).collect();

        let commitment_hashes: Vec<FixedBytes<32>> = output_commitments
            .iter()
            .map(|(f, _)| field_to_b256(f))
            .collect();

        let commitments: Vec<Commitment> = output_commitments
            .iter()
            .map(|(hash, ciphertext)| Commitment {
                hash: field_to_b256(hash),
                ciphertext: ciphertext.clone().into(),
            })
            .collect();

        let unshield_value = if is_unshield {
            if let Some(recipient) = unshield_recipient {
                let mut bytes = [0u8; 32];
                bytes[12..32].copy_from_slice(recipient.as_slice());
                FixedBytes::from(bytes)
            } else {
                FixedBytes::ZERO
            }
        } else {
            FixedBytes::ZERO
        };

        let min_gas: u64 = min_gas_price.min((1u64 << 48) - 1);
        let bound_params = BoundParams {
            treeNumber: tree_number,
            minGasPrice: Uint::<48, 1>::from(min_gas),
            unshield: unshield_value,
            chainID: self.chain_id,
            adaptContract: Address::ZERO,
            adaptParams: FixedBytes::ZERO,
            commitments,
        };

        let verify_inputs = VerifyInputs {
            proof: proof_struct,
            merkleRoot: field_to_b256(&merkle_root),
            nullifiers: nullifier_bytes,
            commitments: commitment_hashes,
        };

        let call = transactCall {
            boundParams: bound_params,
            verifyInputs: verify_inputs,
        };

        Ok(call.abi_encode())
    }

    /// Decode shield function calldata
    pub fn decode_shield_calldata(data: &[u8]) -> Result<Vec<ShieldRequest>, ContractError> {
        let call = shieldCall::abi_decode(data)
            .map_err(|e| ContractError::DecodingFailed(e.to_string()))?;
        Ok(call.requests)
    }

    /// Decode transact function calldata
    pub fn decode_transact_calldata(
        data: &[u8],
    ) -> Result<(BoundParams, VerifyInputs), ContractError> {
        let call = transactCall::abi_decode(data)
            .map_err(|e| ContractError::DecodingFailed(e.to_string()))?;
        Ok((call.boundParams, call.verifyInputs))
    }
}

/// Convert Field to U256 for Solidity
#[allow(dead_code)]
fn field_to_u256(f: &Field) -> U256 {
    let bytes = f.into_bigint().to_bytes_be();
    U256::from_be_slice(&bytes)
}

/// Convert Field to B256 (bytes32)
fn field_to_b256(f: &Field) -> FixedBytes<32> {
    let be_bytes = f.into_bigint().to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
    FixedBytes::from(bytes)
}

/// Convert U256 to Field
#[allow(dead_code)]
fn u256_to_field(u: U256) -> Field {
    let bytes: [u8; 32] = u.to_be_bytes();
    Field::from_be_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_addresses() {
        let addrs = RailgunAddresses::ethereum();
        assert!(!addrs.relay.is_zero());
        assert!(!addrs.smart_wallet.is_zero());
    }

    #[test]
    fn test_for_chain() {
        assert!(RailgunAddresses::for_chain(1).is_some());
        assert!(RailgunAddresses::for_chain(137).is_some());
        assert!(RailgunAddresses::for_chain(99999).is_none());
    }

    #[test]
    fn test_field_u256_conversion() {
        let f = Field::from(12345u64);
        let u = field_to_u256(&f);
        let f2 = u256_to_field(u);
        assert_eq!(f, f2);
    }

    #[test]
    fn test_event_scanner_creation() {
        assert!(EventScanner::new(1).is_some());
        assert!(EventScanner::new(99999).is_none());
    }

    #[test]
    fn test_transaction_builder_creation() {
        assert!(TransactionBuilder::new(1).is_some());
        assert!(TransactionBuilder::new(99999).is_none());
    }

    #[test]
    fn test_shield_calldata_roundtrip() {
        let builder = TransactionBuilder::new(1).unwrap();
        let token = Address::repeat_byte(0x42);
        let amount = U256::from(1_000_000_000_000_000_000u128);
        let npk = Field::from(12345u64);
        let encrypted_bundle = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let shield_key = [4u8; 32];

        let calldata = builder
            .build_shield_calldata(token, amount, npk, encrypted_bundle, shield_key)
            .unwrap();

        // Should be non-empty and start with function selector
        assert!(calldata.len() > 4);

        // Decode and verify roundtrip
        let requests = TransactionBuilder::decode_shield_calldata(&calldata).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].preimage.token.tokenAddress, token);
    }

    #[test]
    fn test_field_to_b256() {
        let f = Field::from(0x1234567890ABCDEFu64);
        let b = field_to_b256(&f);
        assert_eq!(
            b.as_slice()[24..],
            [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF]
        );
    }
}
