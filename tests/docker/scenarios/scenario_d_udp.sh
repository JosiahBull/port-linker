#!/bin/bash
# Scenario D-UDP: Single jump, UDP mode.
# Expected: Single UDP relay on jump1.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

info "=== Scenario D-UDP: Single jump, UDP ==="

# Reset firewalls.
reset_firewalls

# Run port-linker with UDP relay (single hop).
info "running port-linker with --transport udp-relay (single jump)"
output=$(run_port_linker --transport udp-relay 2>&1) && rc=$? || rc=$?

if [ $rc -eq 0 ]; then
    pass "Scenario D-UDP: port-linker exited 0 with single-hop UDP relay"
else
    fail "Scenario D-UDP: port-linker exited $rc. Output: $output"
fi

# Cleanup.
kill_remote_processes
