#!/bin/bash
# Scenario F: TCP data flow verification.
#
# This scenario validates that port-linker actually forwards TCP data
# end-to-end, not just that it exits cleanly.
#
# Steps:
#   1. Start TCP echo server on target container (port 9876)
#   2. Run port-linker in background (forwarding mode)
#   3. Wait for port-linker to detect and bind port 9876 locally
#   4. Send data through socat to localhost:9876, verify echo response
#   5. Clean up

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

info "Scenario F: TCP data flow verification"

# Cleanup function.
cleanup() {
    if [ -n "${PLK_BG_PID:-}" ]; then
        kill "$PLK_BG_PID" 2>/dev/null || true
        wait "$PLK_BG_PID" 2>/dev/null || true
    fi
    kill_remote_processes
    docker exec plk-target bash -c "pkill socat 2>/dev/null; true" || true
    reset_firewalls
}
trap cleanup EXIT

# Reset state.
reset_firewalls
kill_remote_processes

# 1. Start TCP echo server on target.
info "starting TCP echo server on plk-target:9876"
start_tcp_echo plk-target 9876

# 2. Run port-linker in background (forwarding mode).
#    Explicitly use tcp-bridge since we're testing TCP data flow, not UDP relay.
run_port_linker_bg --transport tcp-bridge

# 3. Wait for port-linker to bind port 9876 locally.
info "waiting for local port 9876 to become available..."
MAX_WAIT=15
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
    if socat -T1 /dev/null "TCP:127.0.0.1:9876,connect-timeout=1" 2>/dev/null; then
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    fail "port 9876 did not become available locally within ${MAX_WAIT}s"
fi

info "local port 9876 is up after ${ELAPSED}s"

# 4. Verify TCP echo through the forwarded port.
info "verifying TCP echo through localhost:9876"
if verify_tcp_echo "127.0.0.1" 9876; then
    pass "TCP data flow verification succeeded"
else
    fail "TCP echo verification failed"
fi
