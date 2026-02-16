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
fail() { echo -e "${RED}FAIL${NC}: $1"; }

# Parse arguments.
SCENARIO="${1:-all}"

# Step 1: Ensure SSH keys exist.
info "checking SSH keys..."
bash "$SCRIPT_DIR/ssh/setup-keys.sh"

# Step 2: Build containers.
info "building Docker containers..."
docker compose -f "$COMPOSE_FILE" build

# Step 3: Start containers.
info "starting containers..."
docker compose -f "$COMPOSE_FILE" up -d

# Wait for SSH to be ready on all nodes.
info "waiting for SSH on all nodes..."
for container in plk-jump1 plk-jump2 plk-target; do
    for i in $(seq 1 30); do
        if docker exec "$container" pgrep -f sshd >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
done

# Give SSH a moment to fully initialize.
sleep 2

# Step 4: Run scenarios.
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
        fail "Scenario $name"
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
        ;;
    a) run_scenario "A" "$SCRIPT_DIR/scenarios/scenario_a.sh" ;;
    b) run_scenario "B" "$SCRIPT_DIR/scenarios/scenario_b.sh" ;;
    c) run_scenario "C" "$SCRIPT_DIR/scenarios/scenario_c.sh" ;;
    d-udp|d_udp) run_scenario "D-UDP" "$SCRIPT_DIR/scenarios/scenario_d_udp.sh" ;;
    d-tcp|d_tcp) run_scenario "D-TCP" "$SCRIPT_DIR/scenarios/scenario_d_tcp.sh" ;;
    e) run_scenario "E" "$SCRIPT_DIR/scenarios/scenario_e.sh" ;;
    *)
        echo "Unknown scenario: $SCENARIO"
        echo "Usage: $0 {all|a|b|c|d-udp|d-tcp|e}"
        exit 1
        ;;
esac

# Step 5: Summary.
echo ""
echo "========================================="
echo "  Results: $PASSED passed, $FAILED failed"
echo "========================================="

if [ $FAILED -gt 0 ]; then
    echo -e "\nFailed scenarios:\n$ERRORS"
fi

# Step 6: Teardown (unless KEEP_CONTAINERS is set).
if [ "${KEEP_CONTAINERS:-}" != "1" ]; then
    info "tearing down containers..."
    docker compose -f "$COMPOSE_FILE" down -v
else
    info "KEEP_CONTAINERS=1, leaving containers running"
    info "Teardown manually with: docker compose -f $COMPOSE_FILE down -v"
fi

# Exit with failure if any scenario failed.
[ $FAILED -eq 0 ]
