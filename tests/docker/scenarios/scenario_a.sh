#!/bin/bash
# Scenario A: All hops UDP-capable.
# Expected: UDP relay chain is used.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

info "=== Scenario A: All UDP ==="

# Reset firewalls to allow all.
reset_firewalls

# Run port-linker with UDP relay transport.
info "running port-linker with --transport udp-relay"
output=$(run_port_linker --transport udp-relay 2>&1) && rc=$? || rc=$?

if [ $rc -eq 0 ]; then
    pass "Scenario A: port-linker exited 0 with UDP relay"
else
    fail "Scenario A: port-linker exited $rc. Output: $output"
fi

# Cleanup.
kill_remote_processes
