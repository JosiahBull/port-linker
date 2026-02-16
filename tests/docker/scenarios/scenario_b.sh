#!/bin/bash
# Scenario B: Mixed -- jump2 blocks UDP.
# Expected: Auto falls back to TCP bridge.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

info "=== Scenario B: Mixed (jump2 blocks UDP) ==="

# Reset firewalls, then block UDP on jump2.
reset_firewalls
apply_firewall plk-jump2 block-udp.sh

# Run port-linker with auto transport.
info "running port-linker with --transport auto"
output=$(run_port_linker --transport auto --relay-probe-timeout 3 2>&1) && rc=$? || rc=$?

if [ $rc -eq 0 ]; then
    pass "Scenario B: port-linker exited 0 with auto transport (fallback to TCP)"
else
    fail "Scenario B: port-linker exited $rc. Output: $output"
fi

# Cleanup.
kill_remote_processes
reset_firewalls
