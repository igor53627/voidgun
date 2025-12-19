# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Updated documentation and added protocol visualization

## [0.2.0] - 2024-12-19

### Changed
- **Major refactor**: Removed original Voidgun pool, now using Railgun protocol exclusively

### Removed
- **voidgun-core**: Original Voidgun pool core types (replaced by railgun-lane)
- **voidgun-prover**: Noir/Barretenberg proving stack (replaced by ark-circom + Railgun artifacts)
- **voidgun-contracts**: VoidgunPool Rust bindings (railgun-lane has own contract types)
- **reth-plugin**: Reth ExEx integration for original Voidgun pool
- **circuits/**: Noir circuit sources for original Voidgun pool
- **circuits-bin/**: Compiled Noir artifacts
- **contracts/**: VoidgunPool Solidity contracts and verifiers

### Security
- Upgraded `aes-gcm` to 0.10.3 to fix CVE-2023-42811
- Fixed nullifier computation to use `joinsplit_nullifier(nk, leafIndex)` formula
- Added explicit error handling in G1/G2 point parsing (fail-fast on malformed data)

### Improved
- Streaming downloads with incremental progress reporting for large circuit artifacts

### Added
- `railgun-lane` crate: Complete Railgun protocol implementation
  - EdDSA signature generation compatible with circomlib's Poseidon-based EdDSA
  - Baby Jubjub curve operations with arkworks <-> circomlib coordinate transformation
  - Groth16 proof generation using ark-circom with Railgun's trusted setup
  - Merkle tree syncing from on-chain Shield/Transact events
  - Trial decryption for Shield events (AES-GCM) and Transact events (ChaCha20-Poly1305)
  - Circuit artifact management with IPFS download and caching
  - End-to-end proof verification using VKEY JSON artifacts

### Fixed
- **EdDSA signature verification**: Fixed critical bug where `BabyJubjubScalar::from_le_bytes_mod_order()` 
  was reducing the pruned secret scalar modulo the Baby Jubjub scalar field order
  - Changed `SpendingKey.secret` to raw bytes to preserve the full 256-bit pruned value
  - Signature arithmetic now uses `BigUint` for `S = r + hm * s (mod subOrder)`
  - Public key derivation uses `BigUint` bit-shifting before converting to scalar

## [0.1.0] - 2024-12-18

### Added
- Initial Voidgun implementation with Noir circuits (now deprecated)
- Privacy-via-proxy architecture concept
- ECDSA signature verification in ZK circuits
- reth ExEx plugin prototype
