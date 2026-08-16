#!/usr/bin/env bash
# Refuse any runtime dependency on OpenSSL.
#
# port-linker ships a statically linked agent that is copied onto a machine it
# knows nothing about; linking the system libssl is how that stops working.
# rustls is the intended path and is what the workspace already depends on.
#
# The gate behind the Dependencies job in .github/workflows/ci.yaml.
#
# Usage:
#   ./scripts/check-deps.sh

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

# Captured into a variable before matching, deliberately. The inline version this
# replaces was:
#
#   cargo tree --edges no-dev,no-build --all-features | grep -v openssl-probe | grep openssl && exit 1 || exit 0
#
# where a *failing* cargo tree produced empty input, a non-matching grep, and a
# passing job. The gate could not fail closed, so it could have been silently
# dead for any length of time.
tree=$(cargo tree --edges no-dev,no-build --all-features --locked) ||
    fail "cargo tree failed, so the openssl ban could not be evaluated"

# openssl-probe only locates a system certificate store; it links nothing.
if hits=$(printf '%s\n' "$tree" | grep -v 'openssl-probe' | grep -E 'openssl'); then
    printf '%s\n' "$hits" >&2
    fail "openssl reached the runtime dependency graph (use rustls)"
fi

echo "✓ no openssl in the runtime dependency graph"
