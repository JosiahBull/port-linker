#!/usr/bin/env bash
# Measure target-agent binary size for optimization benchmarking.
#
# Usage:
#   ./scripts/measure-agent-size.sh
#
# Requires: nightly toolchain, rust-src component

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="aarch64-apple-darwin"
PROFILE="target-agent-release"
PACKAGE="target-agent"
BUILD_TARGET_DIR="$WORKSPACE_ROOT/target/measure-build"

# Ensure rust-src is installed on nightly
if ! rustup +nightly component list --installed 2>/dev/null | grep -q rust-src; then
    echo "Installing rust-src on nightly..."
    rustup +nightly component add rust-src
fi

echo "=== Building target-agent for $TARGET ==="
echo "  Profile: $PROFILE"
echo ""

# Build command
RUSTFLAGS="-Z location-detail=none -Z fmt-debug=none -Z unstable-options -C panic=immediate-abort"

BUILD_CMD=(
    cargo +nightly build
    -p "$PACKAGE"
    --target "$TARGET"
    --profile "$PROFILE"
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
