#!/bin/bash
# Download Railgun circuit artifacts from IPFS
#
# These artifacts are needed for proof generation:
# - ZKEY: Proving key (Groth16)
# - WASM: WebAssembly circuit for witness generation
# - VKEY: Verification key (JSON)
#
# Source: https://github.com/Railgun-Community/wallet

set -e

IPFS_GATEWAY="https://ipfs-lb.com"
MASTER_IPFS_HASH="QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU"
OUTPUT_DIR="${1:-crates/railgun-lane/artifacts}"

# Common circuit variants (nullifiers x commitments)
# Start with small ones for testing
VARIANTS=(
    "01x01"
    "01x02"
    "02x01"
    "02x02"
)

echo "Downloading Railgun circuit artifacts to: $OUTPUT_DIR"
echo "IPFS Gateway: $IPFS_GATEWAY"
echo "IPFS Hash: $MASTER_IPFS_HASH"
echo ""

mkdir -p "$OUTPUT_DIR"

download_artifact() {
    local variant=$1
    local artifact_type=$2
    local path=$3
    local compressed=$4
    
    local url="${IPFS_GATEWAY}/ipfs/${MASTER_IPFS_HASH}/${path}"
    local output_file="${OUTPUT_DIR}/${variant}.${artifact_type}"
    
    if [[ -f "$output_file" ]]; then
        echo "[OK] ${variant}.${artifact_type} already exists, skipping"
        return 0
    fi
    
    echo "Downloading: ${variant}.${artifact_type}..."
    
    if [[ "$compressed" == "true" ]]; then
        # Download brotli-compressed file and decompress
        local temp_file="${output_file}.br"
        if curl -sL --fail "$url" -o "$temp_file"; then
            if command -v brotli &> /dev/null; then
                brotli -d "$temp_file" -o "$output_file"
                rm "$temp_file"
                echo "[OK] ${variant}.${artifact_type} downloaded and decompressed"
            else
                echo "[WARN] brotli not installed, keeping compressed file"
                mv "$temp_file" "$output_file.br"
            fi
        else
            echo "[FAIL] Failed to download ${variant}.${artifact_type}"
            return 1
        fi
    else
        # Download uncompressed
        if curl -sL --fail "$url" -o "$output_file"; then
            echo "[OK] ${variant}.${artifact_type} downloaded"
        else
            echo "[FAIL] Failed to download ${variant}.${artifact_type}"
            return 1
        fi
    fi
}

for variant in "${VARIANTS[@]}"; do
    echo ""
    echo "=== Processing $variant ==="
    
    # VKEY (uncompressed JSON)
    download_artifact "$variant" "vkey.json" "circuits/${variant}/vkey.json" "false"
    
    # ZKEY (brotli compressed) - Large file, ~50-200MB
    download_artifact "$variant" "zkey" "circuits/${variant}/zkey.br" "true"
    
    # WASM (brotli compressed)
    download_artifact "$variant" "wasm" "prover/snarkjs/${variant}.wasm.br" "true"
done

echo ""
echo "=== Download Summary ==="
echo "Artifacts saved to: $OUTPUT_DIR"
ls -lah "$OUTPUT_DIR"
echo ""
echo "Note: Full Railgun has 54 circuit variants. This script downloads only the most common ones."
echo "For production, download all variants or implement JIT downloading like the Railgun SDK."
