#!/bin/bash
# Top-level orchestrator for port-linker Docker integration tests.
#
# Usage:
#   bash tests/docker/run-tests.sh all        # Run all scenarios
#   bash tests/docker/run-tests.sh a           # Run scenario A only
#   KEEP_CONTAINERS=1 bash tests/docker/run-tests.sh b  # Keep containers for debugging
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yaml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${YELLOW}INFO${NC}: $1"; }
pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
# Non-fatal failure reporter for per-scenario results (does not exit).
scenario_fail() { echo -e "${RED}FAIL${NC}: $1"; }

# Parse arguments.
SCENARIO="${1:-all}"

# Step 1: Ensure SSH keys exist.
info "checking SSH keys..."
bash "$SCRIPT_DIR/ssh/setup-keys.sh"

# Step 2: Write SSH config so the CLI can resolve Docker container hostnames.
# The CLI reads ~/.ssh/config to discover ProxyJump chains and identity files.
KEY_FILE="$SCRIPT_DIR/ssh/keys/id_ed25519"
SSH_DIR="$HOME/.ssh"
SSH_CONFIG="$SSH_DIR/config"
PLK_MARKER="# --- port-linker integration tests ---"

info "writing SSH config for Docker test hosts..."
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

# Remove any previous port-linker test block (portable across GNU/BSD sed).
if [ -f "$SSH_CONFIG" ]; then
    sed -e "/$PLK_MARKER/,/$PLK_MARKER/d" "$SSH_CONFIG" > "$SSH_CONFIG.tmp"
    mv "$SSH_CONFIG.tmp" "$SSH_CONFIG"
fi

cat >> "$SSH_CONFIG" <<EOF
$PLK_MARKER
Host jump1
    Hostname 172.20.0.10
    User testuser
    IdentityFile $KEY_FILE
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host jump2
    Hostname 172.20.1.20
    User testuser
    IdentityFile $KEY_FILE
    ProxyJump jump1
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host target
    Hostname 172.20.2.20
    User testuser
    IdentityFile $KEY_FILE
    ProxyJump jump1,jump2
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
$PLK_MARKER
EOF
chmod 600 "$SSH_CONFIG"

# Verify the key file exists.
if [ ! -f "$KEY_FILE" ]; then
    fail "SSH key not found at $KEY_FILE"
fi
chmod 600 "$KEY_FILE"

# Step 3: Build containers.
info "building Docker containers..."
docker compose -f "$COMPOSE_FILE" build

# Step 4: Start containers.
info "starting containers..."
docker compose -f "$COMPOSE_FILE" up -d

# Wait for SSH to be ready on all nodes by attempting actual connections.
info "waiting for SSH on all nodes..."
for container in plk-jump1 plk-jump2 plk-target; do
    for i in $(seq 1 30); do
        if docker exec "$container" sh -c 'echo | nc -w1 127.0.0.1 22' >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
done

# Step 4.5: Inject authorized keys directly into containers.
# Docker volume mounts may use cached layers; ensure the freshly generated
# public key is present in every container's authorized_keys.
info "injecting SSH authorized keys into containers..."
for container in plk-jump1 plk-jump2 plk-target; do
    docker cp "$SCRIPT_DIR/ssh/keys/id_ed25519.pub" "$container:/home/testuser/.ssh/authorized_keys"
    docker exec "$container" chmod 600 /home/testuser/.ssh/authorized_keys
    docker exec "$container" chown testuser:testuser /home/testuser/.ssh/authorized_keys
done

# Step 4.6: Verify SSH connectivity before running scenarios.
info "verifying SSH connectivity to jump1 (172.20.0.10)..."
if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       -o BatchMode=yes -o ConnectTimeout=5 \
       -i "$KEY_FILE" testuser@172.20.0.10 echo "SSH OK" 2>&1; then
    pass "SSH connectivity to jump1"
else
    fail "Cannot SSH to jump1"
    info "sshd logs from container:"
    docker logs plk-jump1 2>&1 | tail -20 || true
fi

# Step 5: Run scenarios.
PASSED=0
FAILED=0
ERRORS=""

run_scenario() {
    local name="$1"
    local script="$2"

    info "--- Running scenario: $name ---"
    if bash "$script"; then
        pass "Scenario $name"
        PASSED=$((PASSED + 1))
    else
        scenario_fail "Scenario $name"
        FAILED=$((FAILED + 1))
        ERRORS="$ERRORS  - Scenario $name\n"
    fi
    echo ""
}

case "$SCENARIO" in
    all)
        run_scenario "A (all UDP)" "$SCRIPT_DIR/scenarios/scenario_a.sh"
        run_scenario "B (mixed)" "$SCRIPT_DIR/scenarios/scenario_b.sh"
        run_scenario "C (no UDP)" "$SCRIPT_DIR/scenarios/scenario_c.sh"
        run_scenario "D-UDP (single hop UDP)" "$SCRIPT_DIR/scenarios/scenario_d_udp.sh"
        run_scenario "D-TCP (single hop TCP)" "$SCRIPT_DIR/scenarios/scenario_d_tcp.sh"
        run_scenario "E (direct/regression)" "$SCRIPT_DIR/scenarios/scenario_e.sh"
        run_scenario "F (data flow)" "$SCRIPT_DIR/scenarios/scenario_f_dataflow.sh"
        ;;
    ci)
        # CI-compatible subset: skip multi-hop scenarios that require UDP relay
        # or TCP bridge fixes not yet on this branch.
        run_scenario "E (direct/regression)" "$SCRIPT_DIR/scenarios/scenario_e.sh"
        ;;
    a) run_scenario "A" "$SCRIPT_DIR/scenarios/scenario_a.sh" ;;
    b) run_scenario "B" "$SCRIPT_DIR/scenarios/scenario_b.sh" ;;
    c) run_scenario "C" "$SCRIPT_DIR/scenarios/scenario_c.sh" ;;
    d-udp|d_udp) run_scenario "D-UDP" "$SCRIPT_DIR/scenarios/scenario_d_udp.sh" ;;
    d-tcp|d_tcp) run_scenario "D-TCP" "$SCRIPT_DIR/scenarios/scenario_d_tcp.sh" ;;
    e) run_scenario "E" "$SCRIPT_DIR/scenarios/scenario_e.sh" ;;
    f) run_scenario "F" "$SCRIPT_DIR/scenarios/scenario_f_dataflow.sh" ;;
    *)
        echo "Unknown scenario: $SCENARIO"
        echo "Usage: $0 {all|ci|a|b|c|d-udp|d-tcp|e|f}"
        exit 1
        ;;
esac

# Step 6: Summary.
echo ""
echo "========================================="
echo "  Results: $PASSED passed, $FAILED failed"
echo "========================================="

if [ $FAILED -gt 0 ]; then
    echo -e "\nFailed scenarios:\n$ERRORS"
fi

# Step 7: Teardown (unless KEEP_CONTAINERS is set).
if [ "${KEEP_CONTAINERS:-}" != "1" ]; then
    info "tearing down containers..."
    docker compose -f "$COMPOSE_FILE" down -v

    # Remove test SSH config block (portable across GNU/BSD sed).
    if [ -f "$SSH_CONFIG" ]; then
        sed -e "/$PLK_MARKER/,/$PLK_MARKER/d" "$SSH_CONFIG" > "$SSH_CONFIG.tmp"
        mv "$SSH_CONFIG.tmp" "$SSH_CONFIG"
    fi
else
    info "KEEP_CONTAINERS=1, leaving containers running"
    info "Teardown manually with: docker compose -f $COMPOSE_FILE down -v"
fi

# Exit with failure if any scenario failed.
[ $FAILED -eq 0 ]
