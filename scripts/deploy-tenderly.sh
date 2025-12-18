#!/bin/bash
set -euo pipefail

TENDERLY_RPC_URL="${TENDERLY_RPC_URL:?TENDERLY_RPC_URL not set}"
PRIVATE_KEY="${PRIVATE_KEY:?PRIVATE_KEY not set}"

cd "$(dirname "$0")/../contracts"

echo "=== Deploying to Tenderly ==="

# Step 1: Deploy library and get address
echo "Step 1: Deploying ZKTranscriptLib..."
LIB_BYTECODE=$(cat verifier/compiled/ZKTranscriptLib.bin)
LIB_RESULT=$(cast send --rpc-url "$TENDERLY_RPC_URL" --private-key "$PRIVATE_KEY" --create "0x$LIB_BYTECODE" --json)
LIB_ADDRESS=$(echo "$LIB_RESULT" | jq -r '.contractAddress')
echo "ZKTranscriptLib deployed at: $LIB_ADDRESS"

# Step 2: Link and deploy HonkVerifier
echo "Step 2: Deploying HonkVerifier (linked)..."
# Library placeholder: __$4c51bd4ab2f1d1cfe6a9e85f2433f63ec1$__ (with underscores)
LIB_ADDR_NO_PREFIX="${LIB_ADDRESS:2}"
# Read bytecode and link
VERIFIER_BYTECODE=$(cat verifier/compiled/HonkVerifier.bin | head -1 | sed "s/__\\\$4c51bd4ab2f1d1cfe6a9e85f2433f63ec1\\\$__/${LIB_ADDR_NO_PREFIX}/g")
VERIFIER_RESULT=$(cast send --rpc-url "$TENDERLY_RPC_URL" --private-key "$PRIVATE_KEY" --create "0x$VERIFIER_BYTECODE" --json)
VERIFIER_ADDRESS=$(echo "$VERIFIER_RESULT" | jq -r '.contractAddress')
echo "HonkVerifier deployed at: $VERIFIER_ADDRESS"

# Step 3: Deploy Poseidon2 using forge
echo "Step 3: Deploying Poseidon2 and VoidgunPool..."
forge script script/DeployPool.s.sol:DeployPoolScript \
    --rpc-url "$TENDERLY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --sig "run(address)" "$VERIFIER_ADDRESS"

echo "=== Deployment Complete ==="
