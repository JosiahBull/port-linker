#!/bin/bash
set -e

echo "Starting SSH daemon..."
/usr/sbin/sshd

echo "Starting test services..."

# Service 1: Simple HTTP server on port 8080 (bound to 0.0.0.0)
python3 -m http.server 8080 --bind 0.0.0.0 &
echo "Started HTTP server on 0.0.0.0:8080"

# Service 2: Echo server on port 3000 (bound to 127.0.0.1)
while true; do
    echo "Echo server ready" | nc -l -p 3000 -s 127.0.0.1
done &
echo "Started echo server on 127.0.0.1:3000"

# Service 3: Another service on port 5432 (simulating postgres, bound to 0.0.0.0)
while true; do
    echo "Fake postgres" | nc -l -p 5432
done &
echo "Started fake postgres on 0.0.0.0:5432"

echo "All services started. Container ready for testing."
echo "SSH available on port 22"
echo "Test services on ports: 8080, 3000, 5432"

# Keep container running and show logs
tail -f /dev/null
