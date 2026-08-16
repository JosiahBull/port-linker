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

# Nudge, once, if this clone has no hooks. `core.hooksPath` is per clone, so it
# survives no amount of committing it to the repo — someone has to run the
# installer, and until this line there was nothing anywhere that said so.
#
# Here rather than in the check-* scripts because the pre-commit hook runs seven
# of those in a row, and a reminder that printed once per script would be noise
# aimed at the one person who does not need it.
#
# A note, never an error. Hooks are the convenience and ci.yaml is the gate, so
# missing them must not be the reason a command fails. Silent under CI, where
# `core.hooksPath` is meant to be unset, and outside a git repository at all.
if [ -z "${CI:-}" ] && [ "$(git config --get core.hooksPath 2>/dev/null || true)" != ".githooks" ]; then
    echo "note: git hooks are not installed in this clone." >&2
    echo "      ./scripts/install-hooks.sh runs these same checks before each commit." >&2
fi

cargo build -p agent --locked
cargo test --workspace --all-features --locked
echo "✓ tests OK"
