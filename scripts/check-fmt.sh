#!/usr/bin/env bash
# Check formatting. The gate behind the Format job in .github/workflows/ci.yaml,
# and the same command .githooks/pre-commit runs, so the two cannot drift.
#
# Usage:
#   ./scripts/check-fmt.sh

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

cargo fmt --all -- --check
echo "✓ formatting OK"
