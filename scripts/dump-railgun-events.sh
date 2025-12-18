#!/bin/bash
# Dump all Railgun Shield and Transact events from mainnet archive node
#
# Usage: ./scripts/dump-railgun-events.sh
#
# Requires: ssh access to root@aya with reth mainnet on port 8555

set -e

RELAY_CONTRACT="0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
# Shield event: Shield(uint256,uint256,CommitmentPreimage[],ShieldCiphertext[],uint256[])
SHIELD_TOPIC="0x3a5b9dc26075a3801a6ddccf95fec485bb7500a91b44cec1add984c21ee6db3b"
# Transact event: Transact(uint256,uint256,bytes32[],(bytes32[4],bytes32,bytes32[])[])
# Note: This is the correct topic from on-chain, not computed from the sol! macro definition
TRANSACT_TOPIC="0x56a618cda1e34057b7f849a5792f6c8587a2dbe11c83d0254e72cb3daffda7d1"

# Railgun v2 deployed around block 16_800_000 (Jan 2023)
START_BLOCK=16800000
OUTPUT_DIR="crates/railgun-lane/artifacts/events"

mkdir -p "$OUTPUT_DIR"

echo "Fetching Railgun events from mainnet archive node..."
echo "  Relay contract: $RELAY_CONTRACT"
echo "  Start block: $START_BLOCK"

# Get current block
CURRENT_BLOCK=$(ssh root@aya 'curl -s -X POST -H "Content-Type: application/json" --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}" http://localhost:8555' | jq -r '.result' | xargs printf "%d")
echo "  Current block: $CURRENT_BLOCK"

# Fetch Shield events in batches
BATCH_SIZE=50000
FROM_BLOCK=$START_BLOCK
SHIELD_EVENTS="[]"

echo ""
echo "Fetching Shield events..."

while [ $FROM_BLOCK -lt $CURRENT_BLOCK ]; do
    TO_BLOCK=$((FROM_BLOCK + BATCH_SIZE))
    if [ $TO_BLOCK -gt $CURRENT_BLOCK ]; then
        TO_BLOCK=$CURRENT_BLOCK
    fi
    
    echo "  Blocks $FROM_BLOCK to $TO_BLOCK..."
    
    BATCH=$(ssh root@aya "curl -s -X POST -H 'Content-Type: application/json' --data '{
        \"jsonrpc\":\"2.0\",
        \"method\":\"eth_getLogs\",
        \"params\":[{
            \"address\":\"$RELAY_CONTRACT\",
            \"topics\":[\"$SHIELD_TOPIC\"],
            \"fromBlock\":\"0x$(printf '%x' $FROM_BLOCK)\",
            \"toBlock\":\"0x$(printf '%x' $TO_BLOCK)\"
        }],
        \"id\":1
    }' http://localhost:8555" | jq -c '.result // []')
    
    # Merge results
    SHIELD_EVENTS=$(echo "$SHIELD_EVENTS" "$BATCH" | jq -s 'add')
    
    COUNT=$(echo "$BATCH" | jq 'length')
    echo "    Found $COUNT events in batch"
    
    FROM_BLOCK=$((TO_BLOCK + 1))
done

TOTAL_SHIELD=$(echo "$SHIELD_EVENTS" | jq 'length')
echo "Total Shield events: $TOTAL_SHIELD"

# Save to file
echo "$SHIELD_EVENTS" | jq '.' > "$OUTPUT_DIR/shield-events-mainnet.json"
echo "Saved to $OUTPUT_DIR/shield-events-mainnet.json"

# Create a compact format with just commitments and positions
echo ""
echo "Extracting commitment data..."

# We'll process this in Rust to compute commitments from preimages
echo "Done! Load the events in Rust to compute commitments."

# Also fetch Transact events (topic already defined at top)
FROM_BLOCK=$START_BLOCK
TRANSACT_EVENTS="[]"

echo ""
echo "Fetching Transact events..."

while [ $FROM_BLOCK -lt $CURRENT_BLOCK ]; do
    TO_BLOCK=$((FROM_BLOCK + BATCH_SIZE))
    if [ $TO_BLOCK -gt $CURRENT_BLOCK ]; then
        TO_BLOCK=$CURRENT_BLOCK
    fi
    
    echo "  Blocks $FROM_BLOCK to $TO_BLOCK..."
    
    BATCH=$(ssh root@aya "curl -s -X POST -H 'Content-Type: application/json' --data '{
        \"jsonrpc\":\"2.0\",
        \"method\":\"eth_getLogs\",
        \"params\":[{
            \"address\":\"$RELAY_CONTRACT\",
            \"topics\":[\"$TRANSACT_TOPIC\"],
            \"fromBlock\":\"0x$(printf '%x' $FROM_BLOCK)\",
            \"toBlock\":\"0x$(printf '%x' $TO_BLOCK)\"
        }],
        \"id\":1
    }' http://localhost:8555" | jq -c '.result // []')
    
    TRANSACT_EVENTS=$(echo "$TRANSACT_EVENTS" "$BATCH" | jq -s 'add')
    
    COUNT=$(echo "$BATCH" | jq 'length')
    echo "    Found $COUNT events in batch"
    
    FROM_BLOCK=$((TO_BLOCK + 1))
done

TOTAL_TRANSACT=$(echo "$TRANSACT_EVENTS" | jq 'length')
echo "Total Transact events: $TOTAL_TRANSACT"

echo "$TRANSACT_EVENTS" | jq '.' > "$OUTPUT_DIR/transact-events-mainnet.json"
echo "Saved to $OUTPUT_DIR/transact-events-mainnet.json"
