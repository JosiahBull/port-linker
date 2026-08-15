#!/usr/bin/env bash
# Build the docs with warnings denied. The gate behind the Documentation job in
# .github/workflows/ci.yaml.
#
# RUSTDOCFLAGS is exported here, unlike RUSTFLAGS in check-clippy.sh: nothing else
# covers rustdoc warnings, and rustdoc keeps its own fingerprint, so setting it
# does not invalidate the build artifacts a normal `cargo build` produces.
#
# Not run by .githooks/pre-commit — it is slow, and broken intra-doc links are
# not the kind of mistake worth paying for on every commit.
#
# Usage:
#   ./scripts/check-docs.sh

set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-}" in
-h | --help)
    sed -n '2,/^$/p' "$0" | sed 's/^#\( \|$\)//'
    exit 0
    ;;
"") ;;
*)
    echo "error: unknown argument '$1' (try --help)" >&2
    exit 1
    ;;
esac

export RUSTDOCFLAGS="-D warnings"
cargo doc --workspace --all-features --no-deps --locked
echo "✓ docs OK"
