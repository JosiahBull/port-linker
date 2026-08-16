#!/usr/bin/env bash
# Point this clone's git hooks at .githooks/.
#
# Hooks live in the repo rather than .git/hooks so they are reviewed like any
# other code, but git will not use them until core.hooksPath says so — and that
# setting is per clone, so this has to be run once after cloning.
#
# Usage:
#   ./scripts/install-hooks.sh              install
#   ./scripts/install-hooks.sh --uninstall  restore git's default hooks

set -euo pipefail
cd "$(dirname "$0")/.."

fail() {
    echo "error: $*" >&2
    exit 1
}

case "${1:-}" in
-h | --help)
    sed -n '2,/^$/p' "$0" | sed 's/^#\( \|$\)//'
    exit 0
    ;;
--uninstall)
    git config --unset core.hooksPath || true
    echo "✓ hooks uninstalled; git is back to .git/hooks"
    exit 0
    ;;
"") ;;
*) fail "unknown argument '$1' (try --help)" ;;
esac

[ -d .githooks ] || fail ".githooks/ not found — run this from a clone of the repo"

for hook in .githooks/*; do
    [ -x "$hook" ] || fail "$hook is not executable (chmod +x $hook)"
done

git config core.hooksPath .githooks

echo "✓ core.hooksPath = .githooks"
echo
echo "The pre-commit hook runs the fast CI gates before each commit."
echo "Bypass a single commit with: git commit --no-verify"
echo "Remove it entirely with:     ./scripts/install-hooks.sh --uninstall"
