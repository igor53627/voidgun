# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed
- **voidgun-core**: Original Voidgun pool core types (replaced by railgun-lane self-contained implementation)
- **voidgun-prover**: Noir/Barretenberg proving stack (replaced by ark-circom + Railgun IPFS artifacts)
- **voidgun-contracts**: VoidgunPool Rust bindings (railgun-lane has own contract types)
- **reth-plugin**: Reth ExEx integration for original Voidgun pool (to be rebuilt for Railgun)
- **circuits/**: Noir circuit sources for original Voidgun pool
- **circuits-bin/**: Compiled Noir artifacts for original Voidgun pool
- **contracts/**: VoidgunPool Solidity contracts and verifiers

### Added
- `railgun-lane` crate: Rust implementation of Railgun protocol for privacy pool integration
  - Full EdDSA signature generation compatible with circomlib's Poseidon-based EdDSA
  - Baby Jubjub curve operations with coordinate transformation between arkworks and circomlib
  - Groth16 proof generation using ark-circom with Railgun's trusted setup
  - Merkle tree syncing from on-chain Shield/Transact events
  - End-to-end proof verification against deployed Railgun contracts

### Fixed
- **EdDSA signature verification**: Fixed critical bug where `BabyJubjubScalar::from_le_bytes_mod_order()` 
  was reducing the pruned secret scalar modulo the Baby Jubjub scalar field order. This corrupted the 
  bottom 3 bits and broke the identity `s = 8 * (s >> 3)` that circomlib relies on.
  - Changed `SpendingKey.secret` from `BabyJubjubScalar` to `secret_bytes: [u8; 32]` to preserve 
    the full 256-bit pruned value
  - Signature arithmetic now uses `BigUint` for `S = r + hm * s (mod subOrder)` without premature reduction
  - Public key derivation uses `BigUint` bit-shifting before converting to scalar

### Changed
- Baby Jubjub Base8 point now uses correct arkworks coordinates with `sqrt(168700)` transformation
- `SpendingKey::public_xy()` returns circomlib-format coordinates for circuit compatibility
- `SpendingKey::sign()` outputs R8 coordinates in circomlib format

## [0.1.0] - 2024-12-19

### Added
- Initial Voidgun implementation with Noir circuits
- Privacy-via-proxy architecture for Ethereum
- ECDSA signature verification in ZK circuits
- reth ExEx plugin for RPC proxy and event indexing
- VoidgunPool Solidity contracts
