#!/bin/bash
# Scenario G: SSH agent authentication.
#
# Every other scenario sets SSH_AUTH_SOCK="" to force key-file auth, so
# SshSession::try_agent_identities — the code that enumerates what an agent
# holds and picks an authentication method per identity — had no coverage at
# all. That is the path russh reshaped in 0.62, when request_identities started
# returning AgentIdentity instead of PublicKey.
#
# The client tries the agent before any identity file (see authenticate() in
# crates/cli/src/ssh/client.rs), so running with an agent that holds the test
# key is enough to select the path. Succeeding is not sufficient evidence
# though: a fallback to the key file in ~/.ssh/config would also succeed and
# would look identical from the outside. The log line is what distinguishes
# them, so this asserts on it.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

info "=== Scenario G: SSH agent authentication ==="

KEY_FILE="$DOCKER_DIR/ssh/keys/id_ed25519"
[ -f "$KEY_FILE" ] || fail "Scenario G: test key missing at $KEY_FILE"

command -v ssh-agent >/dev/null 2>&1 || fail "Scenario G: ssh-agent is not installed"
command -v ssh-add >/dev/null 2>&1 || fail "Scenario G: ssh-add is not installed"

reset_firewalls

plk_bin="$REPO_ROOT/target/debug/port-linker"
if [ ! -x "$plk_bin" ]; then
    plk_bin="$REPO_ROOT/target/release/port-linker"
fi

# A private agent for this scenario only, so the developer's own agent is
# neither read nor modified, and so the identity list is exactly one key.
agent_env="$(mktemp)"
ssh-agent -s >"$agent_env" 2>/dev/null || fail "Scenario G: could not start ssh-agent"
# shellcheck disable=SC1090  # generated at runtime by ssh-agent
source "$agent_env" >/dev/null

cleanup_agent() {
    if [ -n "${SSH_AGENT_PID:-}" ]; then
        ssh-agent -k >/dev/null 2>&1 || true
    fi
    rm -f "$agent_env"
}
trap cleanup_agent EXIT

# The generated key has no passphrase, so this needs no askpass.
ssh-add "$KEY_FILE" >/dev/null 2>&1 || fail "Scenario G: ssh-add rejected the test key"

loaded=$(ssh-add -l 2>/dev/null | wc -l | tr -d ' ')
[ "$loaded" -eq 1 ] || fail "Scenario G: expected exactly 1 agent identity, found $loaded"
info "agent holds $loaded identity"

AGENT_ARGS=()
musl_agent="$REPO_ROOT/target/x86_64-unknown-linux-musl/debug/port-linker-agent"
if [ -x "$musl_agent" ]; then
    AGENT_ARGS+=(--agent-binary "$musl_agent")
fi

# Note SSH_AUTH_SOCK is deliberately *not* cleared here, unlike every other
# scenario. That is the whole point.
info "running port-linker with the agent reachable (SSH_AUTH_SOCK set)"
output=$(RUST_LOG=debug timeout 60 "$plk_bin" \
    --remote "testuser@jump1" \
    --ssh-host-key-verification accept-all \
    --echo-only \
    "${AGENT_ARGS[@]}" 2>&1) && rc=$? || rc=$?

if [ "$rc" -ne 0 ]; then
    fail "Scenario G: port-linker exited $rc. Output: $output"
fi

# Proves the agent path ran. Without this the scenario would still pass if the
# agent were ignored and ~/.ssh/config's IdentityFile were used instead.
if ! grep -q "SSH agent authentication successful" <<<"$output"; then
    echo "$output" | tail -30
    fail "Scenario G: connected, but not via the agent — no agent success line in the log"
fi

# The identity was enumerated as a plain public key rather than a certificate,
# which is the AgentIdentity::PublicKey arm of the 0.62 migration.
if ! grep -q "trying SSH agent identities" <<<"$output"; then
    fail "Scenario G: agent identities were never enumerated"
fi

pass "Scenario G: authenticated via the SSH agent"

kill_remote_processes
