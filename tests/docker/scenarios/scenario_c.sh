#!/bin/bash
# Scenario C: All hops block UDP.
# Expected: TCP bridge is used.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

info "=== Scenario C: No UDP ==="

# Block UDP on all jump hosts.
reset_firewalls
apply_firewall plk-jump1 block-udp.sh
apply_firewall plk-jump2 block-udp.sh

# Run port-linker with TCP bridge transport.
info "running port-linker with --transport tcp-bridge"
output=$(run_port_linker --transport tcp-bridge 2>&1) && rc=$? || rc=$?

if [ $rc -eq 0 ]; then
    pass "Scenario C: port-linker exited 0 with TCP bridge"
else
    fail "Scenario C: port-linker exited $rc. Output: $output"
fi

# Cleanup.
kill_remote_processes
reset_firewalls
