#!/usr/bin/env bash
# Lint the CI configuration itself: actionlint over the workflows, shellcheck
# over the tracked shell scripts, and an assertion that the Gate job depends on
# every other job.
#
# The gate behind the Workflows job in .github/workflows/ci.yaml.
#
# The Gate assertion is the important one. Gate is the only required status check
# on main, so a job missing from its `needs:` is a job that cannot fail a pull
# request — indistinguishable, from the merge box, from one that can. That is the
# failure mode the single-context design trades for, and this is what closes it.
#
# actionlint and shellcheck are expected on PATH; CI installs them. Locally,
# each is skipped with a note rather than failing, because the gate is CI.
#
# Usage:
#   ./scripts/check-workflows.sh

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

# Read into arrays with a loop rather than `mapfile`, which is bash 4+; macOS
# still ships bash 3.2, and this script runs from the pre-commit hook there.
#
# Both extensions: the repo convention is .yaml, but GitHub reads either, and a
# .yml workflow slipping past the linter is exactly what a glob-by-convention
# misses.
workflows=()
while IFS= read -r workflow; do
    workflows+=("$workflow")
done < <(find .github/workflows -type f \( -name '*.yaml' -o -name '*.yml' \) | sort)
[ ${#workflows[@]} -gt 0 ] || fail "no workflow files found"

if command -v actionlint >/dev/null 2>&1; then
    echo "▶ actionlint (${#workflows[@]} workflows)"
    actionlint -color "${workflows[@]}"
else
    echo "↳ skipping actionlint (not installed)"
fi

if command -v shellcheck >/dev/null 2>&1; then
    # scripts/ and .githooks/ only, not tests/docker/.
    #
    # The Docker harness predates this check and has around twenty findings. Most
    # are informational, but two are SC2046 on `$(_resolve_agent_args)`, where the
    # unquoted expansion is deliberate — it splits into several arguments, and
    # quoting it would pass one argument containing spaces and break the
    # scenarios. Those scripts are also what the required Docker Integration Tests
    # job runs, so a blind sweep there risks a merge gate to satisfy a linter.
    # Cleaning them up is worth its own change; see CI.md.
    shell_scripts=()
    while IFS= read -r script; do
        shell_scripts+=("$script")
    done < <(git ls-files 'scripts/*.sh' '.githooks/*' | sort)
    echo "▶ shellcheck (${#shell_scripts[@]} scripts)"
    # Guarded rather than expanded directly: under bash 3.2, "${arr[@]}" on an
    # empty array trips `set -u`.
    if [ ${#shell_scripts[@]} -gt 0 ]; then
        shellcheck "${shell_scripts[@]}"
    fi
else
    echo "↳ skipping shellcheck (not installed)"
fi

echo "▶ Gate covers every job"
python3 - <<'PY'
import re
import sys

src = open(".github/workflows/ci.yaml").read()

# Only the jobs: block — `on:` also has two-space keys (push, pull_request) and
# they are not jobs.
try:
    jobs_block = src.split("\njobs:\n", 1)[1]
except IndexError:
    sys.exit("::error::could not find the jobs: block in ci.yaml")

jobs = re.findall(r"^  ([A-Za-z0-9_-]+):$", jobs_block, re.M)
if "gate" not in jobs:
    sys.exit("::error::ci.yaml has no `gate` job, but Gate is the required check")

gate_block = jobs_block.split("\n  gate:\n", 1)[1]
# Stop at the next job so a later job's `needs:` is not counted as Gate's.
gate_block = re.split(r"^  [A-Za-z0-9_-]+:$", gate_block, maxsplit=1, flags=re.M)[0]

# Both the block form and the inline `needs: [a, b]` form.
needs = set(re.findall(r"^      - ([A-Za-z0-9_-]+)$", gate_block, re.M))
inline = re.search(r"^    needs:\s*\[(.*?)\]", gate_block, re.M | re.S)
if inline:
    needs |= {n.strip() for n in inline.group(1).split(",") if n.strip()}

missing = sorted(set(jobs) - {"gate"} - needs)
if missing:
    sys.exit(
        "::error::jobs missing from gate.needs, so they cannot fail a PR: "
        + ", ".join(missing)
    )

print(f"  {len(needs)} jobs, all covered")
PY

echo "✓ workflows OK"
