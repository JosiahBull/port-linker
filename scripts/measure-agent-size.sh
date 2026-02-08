#!/usr/bin/env bash
# Measure agent binary size for optimization benchmarking.
#
# Usage:
#   ./scripts/measure-agent-size.sh [target] [bloat]
#
# Targets:
#   aarch64-apple-darwin       (alias: mac, macos, darwin)
#   aarch64-unknown-linux-musl (alias: arm, aarch64, arm64)
#   x86_64-unknown-linux-musl  (alias: x86, x86_64, amd64)
#
# Default target: aarch64-apple-darwin
#
# Requires: nightly toolchain, rust-src component

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROFILE="agent-release"
PACKAGE="agent"
BUILD_TARGET_DIR="$WORKSPACE_ROOT/target/measure-build"

# Resolve target alias to full triple
resolve_target() {
    case "${1:-}" in
        mac|macos|darwin)       echo "aarch64-apple-darwin" ;;
        arm|aarch64|arm64)      echo "aarch64-unknown-linux-musl" ;;
        x86|x86_64|amd64)      echo "x86_64-unknown-linux-musl" ;;
        "")                     echo "aarch64-apple-darwin" ;;
        *)                      echo "$1" ;;
    esac
}

# Parse positional arguments: [target] [bloat]
BLOAT=false
TARGET=""

for arg in "$@"; do
    if [[ "$arg" == "bloat" ]]; then
        BLOAT=true
    elif [[ -z "$TARGET" ]]; then
        TARGET="$(resolve_target "$arg")"
    fi
done

# Default target if none provided
if [[ -z "$TARGET" ]]; then
    TARGET="aarch64-apple-darwin"
fi

# Ensure rust-src is installed on nightly
if ! rustup +nightly component list --installed 2>/dev/null | grep -q rust-src; then
    echo "Installing rust-src on nightly..."
    rustup +nightly component add rust-src
fi

# Build flags
RUSTFLAGS="-Z location-detail=none -Z fmt-debug=none -Z unstable-options -C panic=immediate-abort"

if [[ "$BLOAT" == true ]]; then
    if ! command -v cargo-bloat &> /dev/null; then
        echo "Error: cargo-bloat is not installed. Please run: cargo install cargo-bloat"
        exit 1
    fi

    echo "=== Analyzing bloat for $TARGET ==="

    BLOAT_CMD=(
        cargo +nightly bloat
        -p "$PACKAGE"
        --target "$TARGET"
        --profile "$PROFILE"
    )
    BLOAT_CMD+=(
        -Z "build-std=std,panic_abort"
        -Z "build-std-features=optimize_for_size"
        -n 50
    )

    CARGO_TARGET_DIR="$BUILD_TARGET_DIR" \
    RUSTFLAGS="$RUSTFLAGS" \
    "${BLOAT_CMD[@]}"
    exit 0
fi

echo "=== Building agent for $TARGET ==="
echo "  Profile: $PROFILE"

BUILD_CMD=(
    cargo +nightly build
    -p "$PACKAGE"
    --target "$TARGET"
    --profile "$PROFILE"
)
BUILD_CMD+=(
    -Z "build-std=std,panic_abort"
    -Z "build-std-features=optimize_for_size"
)

CARGO_TARGET_DIR="$BUILD_TARGET_DIR" \
RUSTFLAGS="$RUSTFLAGS" \
    "${BUILD_CMD[@]}"

BINARY="$BUILD_TARGET_DIR/$TARGET/$PROFILE/$PACKAGE"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found at $BINARY"
    exit 1
fi

RAW_SIZE=$(stat -f%z "$BINARY" 2>/dev/null || stat -c%s "$BINARY" 2>/dev/null)
echo ""
echo "=== Results ==="
echo "  Binary: $BINARY"
echo "  Size (raw): $RAW_SIZE bytes ($(echo "scale=1; $RAW_SIZE / 1024" | bc)K)"

cp "$BINARY" "$BINARY.upx"
upx --best --lzma "$BINARY.upx" >/dev/null 2>&1 || true
UPX_SIZE=$(stat -f%z "$BINARY.upx" 2>/dev/null || stat -c%s "$BINARY.upx" 2>/dev/null)
echo "  Size (UPX): $UPX_SIZE bytes ($(echo "scale=1; $UPX_SIZE / 1024" | bc)K)"
rm -f "$BINARY.upx"
