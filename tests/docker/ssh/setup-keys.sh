#!/bin/bash
# Generate test SSH key pair (idempotent).
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_DIR="$SCRIPT_DIR/keys"

mkdir -p "$KEY_DIR"

if [ ! -f "$KEY_DIR/id_ed25519" ]; then
    echo "Generating test SSH key pair..."
    ssh-keygen -t ed25519 -f "$KEY_DIR/id_ed25519" -N "" -C "port-linker-test"
    echo "Key pair generated at $KEY_DIR/"
else
    echo "Test SSH key pair already exists at $KEY_DIR/"
fi
