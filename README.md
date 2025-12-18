# Voidgun

Privacy-via-proxy architecture for Ethereum. Transact privately from any multi-chain wallet.

## Overview

Voidgun implements a "proxy without spending authority" model where:
- Your wallet retains full spending authority via ECDSA signatures
- The proxy cannot steal funds - only wallet-signed transactions authorize spends
- All privacy operations are verified in zero-knowledge using Noir circuits

## Architecture

```
┌─────────┐     ┌──────────────────────┐     ┌─────────────────┐
│  Wallet │────▶│  reth + voidgun      │────▶│  VoidgunPool    │
│  (signs)│     │  (RPC proxy + ExEx)  │     │  (L1 contract)  │
└─────────┘     └──────────────────────┘     └─────────────────┘
                         │
                         │ Noir circuit proves:
                         │ - ECDSA signature valid
                         │ - tx.to matches recipient
                         │ - tx.amount matches transfer
                         │ - Merkle proof valid
                         │ - Nullifiers correct
                         ▼
                   Zero-knowledge proof
```

## How It Works (User Flow)

### 1. Setup (one-time, ~30 seconds)
1. Connect your existing wallet to the Voidgun app
2. Add "Voidgun" as a custom RPC network in your wallet
3. Sign a message to derive your privacy keys (no new seed phrase needed)
4. Keys are registered with the key server

### 2. Shield Funds
1. Deposit ETH/tokens to the VoidgunPool contract
2. Compliance check runs (rejects illicit funds per Privacy Pools model)
3. Your balance becomes a shielded "Note" in the UTXO pool

### 3. Transact Privately
1. Use your wallet normally (connected to Voidgun network)
2. The local proxy intercepts your transaction
3. ZK proof is generated proving your signature authorizes the spend
4. Relayer submits the shielded tx on-chain
5. Recipient gets a new Note, you get change

After setup, everything is transparent - just use your wallet as usual.

## Security Model

Unlike other privacy protocols where the app holds spending keys, Voidgun:
1. Verifies wallet ECDSA signatures inside the zk circuit
2. Binds transaction fields (to, amount) to shielded outputs
3. Uses transaction nullifiers to prevent replay attacks

The proxy can view transactions but **cannot authorize spends**.

## Components

- `circuits/` - Noir circuits for transfer verification
- `crates/core/` - Rust types for keys, notes, merkle trees
- `crates/prover/` - Noir/Barretenberg proving integration
- `crates/contracts/` - VoidgunPool Solidity + Rust bindings
- `crates/reth-plugin/` - reth RPC middleware + ExEx
- `crates/railgun-lane/` - Railgun protocol integration (EdDSA, Groth16, Merkle sync)

## Building

```bash
# Install Noir
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup

# Build circuits
cd circuits && nargo compile

# Build Rust
cargo build --release

# Build Solidity contracts
cd contracts && forge build

# Build HonkVerifier (requires solc, compiled separately due to via_ir issues)
cd contracts/verifier && solc --optimize --optimize-runs 1 --bin --abi HonkVerifier.sol -o compiled
```

### Regenerating the Solidity Verifier

If the circuit changes, regenerate the verifier:

```bash
# Generate VK with keccak (required for EVM) and Solidity verifier
bb write_vk -b circuits-bin/transfer/target/transfer.json -o /tmp/vk --oracle_hash keccak
bb write_solidity_verifier -k /tmp/vk/vk -o contracts/verifier/HonkVerifier.sol -t evm --optimized

# Recompile
cd contracts/verifier && solc --optimize --optimize-runs 1 --bin --abi HonkVerifier.sol -o compiled
```

## Status

🚧 **Under Development** - See [Issues](../../issues) for progress tracking.

## Testing

### Voidgun (Noir circuits)

Run the integration test to verify end-to-end proof generation and verification:

```bash
# Requires bb built from source (see below)
cargo test -p voidgun-prover --test integration_test -- --ignored --nocapture
```

This test:
1. Creates sender/recipient keys from nullifying keys
2. Creates an input note and inserts it into a Merkle tree
3. Builds a shielded transfer witness with real ECDSA signatures
4. Generates a ZK proof (~16KB, takes ~1 second)
5. Verifies the proof

### Railgun Lane (Circom circuits)

Test Railgun protocol integration with Groth16 proofs:

```bash
# Unit tests (EdDSA, keys, notes)
cargo test -p railgun-lane

# Proof generation tests (requires circuit artifacts)
cargo test -p railgun-lane --test proof_generation -- --ignored --nocapture

# End-to-end test with Tenderly (shields tokens, generates proof, verifies on-chain)
# Requires Tenderly VNet (virtual testnet) setup:
#   1. Create free account at https://dashboard.tenderly.co
#   2. Create a project and note the account/project names
#   3. Generate access key at https://dashboard.tenderly.co/account/authorization
#   4. Export environment variables:
#      export TENDERLY_ACCESS_KEY="your-key-here"
#      export TENDERLY_ACCOUNT="your-account"
#      export TENDERLY_PROJECT="your-project"
cargo test -p railgun-lane --test onchain_verification test_e2e_auto -- --ignored --nocapture
```

## Known Issues

### ECDSA Proof Generation (secp256k1)

The released `bb` CLI (3.0.0-rc.4) has a [bigfield bug](https://github.com/AztecProtocol/aztec-packages/issues/14801) that causes proof generation to fail with ECDSA signature verification.

**Solution**: Build `bb` from source using the aztec-packages `next` branch. The fix (commit `2764b96d7f`) is included. See [Building bb from Source](#building-bb-from-source) below.

After building and installing the custom `bb`, proof generation works correctly.

## Building bb from Source

The released `bb` CLI (3.0.0-rc.4) has a bigfield bug affecting ECDSA verification. The fix exists in aztec-packages but hasn't been released yet. Here's how to build a fixed version:

### Prerequisites

```bash
# macOS
brew install cmake ninja

# Ubuntu
sudo apt-get install cmake clang clang-format ninja-build libstdc++-12-dev zlib1g-dev
```

### Build Steps

```bash
# Clone aztec-packages (contains barretenberg)
git clone https://github.com/AztecProtocol/aztec-packages.git ~/pse/vendor/aztec-packages
cd ~/pse/vendor/aztec-packages

# Configure with workarounds for Apple clang
cd barretenberg/cpp
cmake --preset default -DCMAKE_CXX_FLAGS="-Wno-error=vla-cxx-extension -Wno-vla-cxx-extension -Wno-error=missing-field-initializers"

# Build bb CLI (takes ~5-10 minutes)
cmake --build build --target bb -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)

# Verify build
./build/bin/bb --version
```

### Installation

Option 1: Add to PATH (temporary)
```bash
export PATH="$HOME/pse/vendor/aztec-packages/barretenberg/cpp/build/bin:$PATH"
```

Option 2: Replace system bb (permanent)
```bash
cp ~/pse/vendor/aztec-packages/barretenberg/cpp/build/bin/bb ~/.bb/bb
```

Option 3: Use the provided script
```bash
./scripts/build-bb.sh
```

### Verification

Test that ECDSA proof generation works:
```bash
cd /tmp && mkdir ecdsa_test && cd ecdsa_test

# Create minimal test circuit
cat > Nargo.toml << 'EOF'
[package]
name = "ecdsa_test"
type = "bin"
authors = [""]
compiler_version = ">=0.32.0"
[dependencies]
EOF

mkdir -p src && cat > src/main.nr << 'EOF'
fn main(
    pub_key_x: pub [u8;32],
    pub_key_y: pub [u8;32],
    signature: pub [u8;64],
    hashed_message: pub [u8;32],
) {
    assert(std::ecdsa_secp256k1::verify_signature(
        pub_key_x, pub_key_y, signature, hashed_message,
    ));
}
EOF

# Use known-good test vector
cat > Prover.toml << 'EOF'
pub_key_x = [157, 84, 104, 83, 251, 231, 222, 207, 53, 123, 229, 2, 81, 93, 84, 8, 16, 93, 219, 156, 0, 13, 188, 109, 70, 220, 244, 162, 110, 145, 43, 254]
pub_key_y = [238, 109, 94, 53, 199, 56, 172, 53, 22, 200, 112, 87, 90, 110, 174, 252, 196, 75, 37, 58, 116, 223, 111, 46, 157, 52, 88, 159, 36, 218, 199, 223]
signature = [93, 92, 36, 26, 151, 140, 39, 137, 175, 95, 69, 56, 227, 94, 214, 160, 114, 62, 6, 19, 107, 201, 144, 129, 83, 79, 15, 84, 10, 112, 112, 255, 5, 165, 82, 34, 76, 219, 87, 117, 227, 98, 178, 254, 20, 14, 98, 162, 6, 122, 27, 142, 75, 34, 171, 190, 235, 59, 27, 93, 79, 162, 201, 54]
hashed_message = [120, 31, 2, 94, 65, 21, 82, 128, 19, 69, 242, 157, 202, 248, 179, 51, 232, 42, 100, 101, 213, 62, 125, 132, 1, 172, 16, 29, 148, 161, 215, 108]
EOF

# Generate witness and proof
nargo execute
bb write_vk -b ./target/ecdsa_test.json -o ./target/vk
bb prove -b ./target/ecdsa_test.json -w ./target/ecdsa_test.gz -k ./target/vk/vk -o ./target/proof

# Verify the proof
bb verify -p ./target/proof/proof -k ./target/vk/vk -i ./target/proof/public_inputs

# Should output: "Proof verified successfully"
```

## License

MIT OR Apache-2.0

---

## Acknowledgments

A huge thank you to the [Nullmask](https://nullmask.io/) team for their groundbreaking research and inspiration. The Voidgun architecture is based on their paper "Nullmask: transact privately from any multi-chain wallet" which introduced the privacy-via-proxy concept and the security models that make this project possible.
