#!/bin/bash
# Setup script for integration test environment
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Setting up port-linker integration test environment ==="

# Generate test SSH keys if they don't exist
if [ ! -f "test_key" ]; then
    echo "Generating test SSH key pair..."
    ssh-keygen -t ed25519 -f test_key -N "" -C "port-linker-test"
    echo "Generated test_key and test_key.pub"
else
    echo "Test SSH keys already exist"
fi

# Build and start the Docker container
echo "Building Docker image..."
docker-compose build

echo "Starting SSH target container..."
docker-compose up -d

# Wait for container to be healthy
echo "Waiting for container to be ready..."
for i in {1..30}; do
    if docker-compose exec -T ssh-target nc -z localhost 22 2>/dev/null; then
        echo "Container is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "ERROR: Container failed to start within 60 seconds"
        docker-compose logs
        exit 1
    fi
    sleep 2
done

# Test SSH connection
echo "Testing SSH connection..."
if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       -i test_key -p 2222 testuser@localhost "echo 'SSH connection successful'" 2>/dev/null; then
    echo "SSH connection test passed!"
else
    echo "ERROR: SSH connection test failed"
    exit 1
fi

# Verify services are running
echo "Verifying test services..."
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -i test_key -p 2222 testuser@localhost "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"

echo ""
echo "=== Test environment ready ==="
echo "SSH target: localhost:2222"
echo "SSH user: testuser"
echo "SSH key: $SCRIPT_DIR/test_key"
echo ""
echo "To run tests: cargo test --test e2e"
echo "To stop: docker-compose down"
