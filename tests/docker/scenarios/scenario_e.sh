#!/bin/bash
# Scenario E: Direct connection (regression).
# Expected: Direct QUIC, no ProxyJump involved.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

info "=== Scenario E: Direct connection (regression) ==="

# Reset firewalls.
reset_firewalls

# Run port-linker directly to jump1 (which is directly reachable).
# This tests that the existing direct connection path still works.
plk_bin="$REPO_ROOT/target/debug/port-linker"
if [ ! -x "$plk_bin" ]; then
    plk_bin="$REPO_ROOT/target/release/port-linker"
fi

info "running port-linker with --remote testuser@jump1 (direct, no ProxyJump)"
output=$(SSH_AUTH_SOCK="" timeout 60 "$plk_bin" \
    --remote "testuser@jump1" \
    --ssh-host-key-verification accept-all \
    --echo-only 2>&1) && rc=$? || rc=$?

if [ $rc -eq 0 ]; then
    pass "Scenario E: direct connection works (regression test)"
else
    fail "Scenario E: port-linker exited $rc. Output: $output"
fi

# Cleanup.
kill_remote_processes
