#!/bin/bash
# Scenario D-TCP: Single jump, TCP mode.
# Expected: TCP bridge through jump1.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

info "=== Scenario D-TCP: Single jump, TCP ==="

# Block UDP on jump1.
reset_firewalls
apply_firewall plk-jump1 block-udp.sh

# Run port-linker with TCP bridge.
info "running port-linker with --transport tcp-bridge (single jump)"
output=$(run_port_linker --transport tcp-bridge 2>&1) && rc=$? || rc=$?

if [ $rc -eq 0 ]; then
    pass "Scenario D-TCP: port-linker exited 0 with TCP bridge"
else
    fail "Scenario D-TCP: port-linker exited $rc. Output: $output"
fi

# Cleanup.
kill_remote_processes
reset_firewalls
