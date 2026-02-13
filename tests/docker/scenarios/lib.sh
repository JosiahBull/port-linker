#!/bin/bash
# Common helpers for port-linker Docker test scenarios.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DOCKER_DIR/../.." && pwd)"

# Colors for output.
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}INFO${NC}: $1"; }

# Wait for SSH to become available on a container.
wait_for_ssh() {
    local container="$1"
    local max_wait="${2:-30}"
    local elapsed=0

    info "waiting for SSH on $container..."
    while [ $elapsed -lt $max_wait ]; do
        if docker exec "$container" ssh-keyscan -H localhost >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    fail "SSH not available on $container after ${max_wait}s"
}

# Apply firewall rules on a container.
apply_firewall() {
    local container="$1"
    local script="$2"
    docker exec "$container" bash -c "$(cat "$DOCKER_DIR/firewall/$script")"
}

# Reset firewall rules on all containers.
reset_firewalls() {
    for container in plk-jump1 plk-jump2 plk-target; do
        docker exec "$container" bash -c "$(cat "$DOCKER_DIR/firewall/allow-all.sh")" 2>/dev/null || true
    done
}

# Start a TCP echo server on a container.
start_tcp_echo() {
    local container="$1"
    local port="$2"
    docker exec -d "$container" socat TCP-LISTEN:${port},fork,reuseaddr EXEC:cat
    sleep 1
}

# Kill any running agent/relay processes on all containers.
kill_remote_processes() {
    for container in plk-jump1 plk-jump2 plk-target; do
        docker exec "$container" bash -c "pkill -f port-linker 2>/dev/null; true" || true
    done
}

# Verify TCP echo through a host:port.
verify_tcp_echo() {
    local host="$1" port="$2"
    local test_string="PLK_ECHO_$(date +%s)"
    local result
    result=$(echo "$test_string" | socat - "TCP:${host}:${port},connect-timeout=5" 2>/dev/null)
    [ "$result" = "$test_string" ]
}

# Run port-linker in background (forwarding mode, not --echo-only).
# Sets PLK_BG_PID to the backgrounded PID.
run_port_linker_bg() {
    local extra_args=("$@")
    local plk_bin="$REPO_ROOT/target/debug/port-linker"

    if [ ! -x "$plk_bin" ]; then
        plk_bin="$REPO_ROOT/target/release/port-linker"
    fi

    if [ ! -x "$plk_bin" ]; then
        fail "port-linker binary not found. Build with: cargo build -p cli"
    fi

    SSH_AUTH_SOCK="" RUST_LOG=debug "$plk_bin" \
        --remote "testuser@target" \
        --ssh-host-key-verification accept-all \
        "${extra_args[@]}" >"/tmp/plk-bg-$$.log" 2>&1 &
    PLK_BG_PID=$!
    info "port-linker started in background (PID: $PLK_BG_PID)"
}

# Run port-linker with the test SSH config and capture output.
# Returns the exit code.
run_port_linker() {
    local extra_args=("$@")
    local plk_bin="$REPO_ROOT/target/debug/port-linker"

    if [ ! -x "$plk_bin" ]; then
        plk_bin="$REPO_ROOT/target/release/port-linker"
    fi

    if [ ! -x "$plk_bin" ]; then
        fail "port-linker binary not found. Build with: cargo build -p cli"
    fi

    SSH_AUTH_SOCK="" RUST_LOG=debug timeout 60 "$plk_bin" \
        --remote "testuser@target" \
        --ssh-host-key-verification accept-all \
        --echo-only \
        "${extra_args[@]}" 2>&1
}

# Verify that a specific transport mode was used by checking log output.
verify_transport() {
    local log_output="$1"
    local expected="$2"

    case "$expected" in
        "udp-relay")
            if echo "$log_output" | grep -qi "udp relay"; then
                return 0
            fi
            ;;
        "tcp-bridge")
            if echo "$log_output" | grep -qi "tcp bridge"; then
                return 0
            fi
            ;;
        "direct")
            if ! echo "$log_output" | grep -qi "proxy"; then
                return 0
            fi
            ;;
    esac
    return 1
}
