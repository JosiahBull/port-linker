#!/usr/bin/env bash
# Run the test suite. The gate behind the Tests job in
# .github/workflows/ci.yaml, on all three runner OSes.
#
# The agent binary is built first and explicitly: tests/integration_test.rs
# spawns it, and `cargo test` does not build another package's binary just
# because a test wants it. The alternative is the test suite shelling out to
# cargo mid-run, which then races the outer build's lock.
#
# Not `--bins`: for `cargo test` that runs only binary targets, which silently
# skips every lib unit test and the whole of tests/integration_test.rs. This also
# covers crates/tunnel/tests and the crates/perf regression tests, which is why
# neither has a job of its own.
#
# Usage:
#   ./scripts/test.sh

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

cargo build -p agent --locked
cargo test --workspace --all-features --locked
echo "✓ tests OK"
