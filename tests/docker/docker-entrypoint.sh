#!/bin/bash
set -e

# Copy authorized keys if mounted
if [ -f /tmp/ssh-keys/id_ed25519.pub ]; then
    cp /tmp/ssh-keys/id_ed25519.pub /home/testuser/.ssh/authorized_keys
    chmod 600 /home/testuser/.ssh/authorized_keys
    chown testuser:testuser /home/testuser/.ssh/authorized_keys
fi

# Apply firewall rules if specified
if [ "$BLOCK_UDP" = "true" ]; then
    echo "Blocking UDP traffic..."
    iptables -A INPUT -p udp -j DROP 2>/dev/null || true
    iptables -A OUTPUT -p udp -j DROP 2>/dev/null || true
    iptables -A FORWARD -p udp -j DROP 2>/dev/null || true
fi

# Start SSHD in the foreground
exec /usr/sbin/sshd -D -e
