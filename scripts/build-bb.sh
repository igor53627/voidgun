#!/usr/bin/env bash
#
# Build bb CLI from aztec-packages source with ECDSA bigfield fix
#
# The released bb 3.0.0-rc.4 has a bug that crashes on ECDSA signature
# verification. The fix (commit 2764b96d7f) is in aztec-packages next
# branch but not yet released. This script builds bb from source.
#
# Usage:
#   ./scripts/build-bb.sh [--install]
#
# Options:
#   --install   Copy built bb to ~/.bb/bb (replaces bbup-installed version)
#

set -euo pipefail

VENDOR_DIR="${VENDOR_DIR:-$HOME/pse/vendor}"
AZTEC_REPO="$VENDOR_DIR/aztec-packages"
BB_BUILD_DIR="$AZTEC_REPO/barretenberg/cpp/build"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[build-bb]${NC} $*"; }
warn() { echo -e "${YELLOW}[build-bb]${NC} $*"; }
error() { echo -e "${RED}[build-bb]${NC} $*" >&2; }

check_deps() {
    local missing=()
    command -v cmake >/dev/null || missing+=("cmake")
    command -v ninja >/dev/null || missing+=("ninja")
    command -v clang++ >/dev/null || missing+=("clang++")
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing dependencies: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  macOS:  brew install cmake ninja"
        echo "  Ubuntu: sudo apt-get install cmake clang ninja-build libstdc++-12-dev zlib1g-dev"
        exit 1
    fi
}

clone_repo() {
    if [[ -d "$AZTEC_REPO" ]]; then
        log "Updating existing aztec-packages..."
        cd "$AZTEC_REPO"
        git fetch origin
        git reset --hard origin/next
    else
        log "Cloning aztec-packages..."
        mkdir -p "$VENDOR_DIR"
        git clone https://github.com/AztecProtocol/aztec-packages.git "$AZTEC_REPO"
    fi
}

build_bb() {
    log "Configuring barretenberg..."
    cd "$AZTEC_REPO/barretenberg/cpp"
    
    # Clean previous build if exists
    [[ -d build ]] && rm -rf build
    
    # Configure with Apple clang workarounds
    cmake --preset default \
        -DCMAKE_CXX_FLAGS="-Wno-error=vla-cxx-extension -Wno-vla-cxx-extension -Wno-error=missing-field-initializers"
    
    # Detect CPU count
    local jobs
    if command -v nproc >/dev/null; then
        jobs=$(nproc)
    elif command -v sysctl >/dev/null; then
        jobs=$(sysctl -n hw.ncpu)
    else
        jobs=4
    fi
    
    log "Building bb CLI with $jobs parallel jobs..."
    cmake --build build --target bb -j"$jobs"
    
    log "Build complete!"
    echo ""
    echo "Binary location: $BB_BUILD_DIR/bin/bb"
    "$BB_BUILD_DIR/bin/bb" --version || true
}

install_bb() {
    local bb_home="$HOME/.bb"
    mkdir -p "$bb_home"
    
    log "Installing bb to $bb_home/bb..."
    cp "$BB_BUILD_DIR/bin/bb" "$bb_home/bb"
    chmod +x "$bb_home/bb"
    
    log "Installed! Verify with: bb --version"
}

main() {
    local do_install=false
    
    for arg in "$@"; do
        case $arg in
            --install) do_install=true ;;
            --help|-h)
                echo "Usage: $0 [--install]"
                echo ""
                echo "Build bb CLI from aztec-packages source with ECDSA fix."
                echo ""
                echo "Options:"
                echo "  --install   Copy built bb to ~/.bb/bb"
                exit 0
                ;;
            *)
                error "Unknown option: $arg"
                exit 1
                ;;
        esac
    done
    
    log "Building bb with ECDSA bigfield fix..."
    echo ""
    
    check_deps
    clone_repo
    build_bb
    
    if $do_install; then
        install_bb
    else
        echo ""
        echo "To use this bb, either:"
        echo "  1. Add to PATH:  export PATH=\"$BB_BUILD_DIR/bin:\$PATH\""
        echo "  2. Install:      $0 --install"
    fi
    
    echo ""
    log "Done!"
}

main "$@"
