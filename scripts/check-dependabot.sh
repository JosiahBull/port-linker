#!/usr/bin/env bash
# Assert every 0.x direct dependency is ignored for minor bumps in
# .github/dependabot.yml.
#
# Dependabot classifies 0.10 -> 0.11 as a minor update, because the major field
# is still 0. Under Cargo's semver that is a breaking change — for a 0.x crate
# the minor field is the compatibility boundary. Dependabot has no setting for
# this, so the rule lives as an explicit list of crates, and a list is only as
# good as whatever keeps it current. That is this script.
#
# Part of the Dependencies job in .github/workflows/ci.yaml.
#
# Usage:
#   ./scripts/check-dependabot.sh

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

python3 - <<'PY'
import glob
import re
import sys

# Direct dependencies, from every dependency table in every workspace manifest.
deps = {}
for path in ["Cargo.toml"] + sorted(glob.glob("crates/*/Cargo.toml")) + ["tests/Cargo.toml"]:
    section = None
    for line in open(path):
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped.strip("[]")
            continue
        if not section or "dependencies" not in section:
            continue
        m = re.match(
            r'^([A-Za-z0-9_-]+)\s*=\s*(?:\{[^}]*?version\s*=\s*"([^"]+)"|"([^"]+)")',
            stripped,
        )
        if m:
            deps.setdefault(m.group(1), m.group(2) or m.group(3))

# A leading 0 major means the minor field is the compatibility boundary.
zero_x = {name for name, req in deps.items() if req.lstrip("^~=").startswith("0.")}

# Crates ignored for minor bumps. Each entry is a dependency-name line followed
# by its update-types line.
config = open(".github/dependabot.yml").read()
ignored = set(
    re.findall(
        r'- dependency-name: "([^"]+)"\s*\n\s*update-types: \[[^\]]*version-update:semver-minor[^\]]*\]',
        config,
    )
)

missing = sorted(zero_x - ignored)
if missing:
    print("::error::0.x dependencies not ignored for minor bumps in .github/dependabot.yml:")
    for name in missing:
        print(f"  {name} = \"{deps[name]}\"")
    print()
    print("A 0.x minor bump is a breaking change under Cargo's semver, but Dependabot")
    print("calls it minor and would merge it unattended. Add each one as:")
    print()
    for name in missing:
        print(f'      - dependency-name: "{name}"')
        print('        update-types: ["version-update:semver-minor"]')
    sys.exit(1)

# The reverse direction is a warning, not a failure: a crate that reached 1.0, or
# one that was removed, leaves a stale entry that costs nothing but noise.
stale = sorted(ignored - zero_x)
if stale:
    print(f"note: listed but no longer a 0.x direct dependency: {', '.join(stale)}")

print(f"✓ all {len(zero_x)} 0.x direct dependencies are ignored for minor bumps")
PY
