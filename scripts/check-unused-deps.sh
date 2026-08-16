#!/usr/bin/env bash
# Find dependencies that are declared but never used.
#
# Part of the Dependencies job in .github/workflows/ci.yaml. cargo-udeps needs a
# nightly toolchain because it reads unstable compiler output; that is why this
# is separate from check-deps.sh, which needs no toolchain at all and can run in
# the pre-commit hook.
#
# Usage:
#   ./scripts/check-unused-deps.sh

set -euo pipefail
cd "$(dirname "$0")/.."

fail() {
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::error::$*" >&2
    else
        echo "error: $*" >&2
    fi
    exit 1
}

case "${1:-}" in
-h | --help)
    sed -n '2,/^$/p' "$0" | sed 's/^#\( \|$\)//'
    exit 0
    ;;
"") ;;
*) fail "unknown argument '$1' (try --help)" ;;
esac

command -v cargo-udeps >/dev/null 2>&1 ||
    fail "cargo-udeps is not installed (cargo +nightly install --locked cargo-udeps)"

cargo +nightly udeps --all-targets --all-features
echo "✓ no unused dependencies"
