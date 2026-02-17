#!/bin/bash
# Block all UDP traffic on the current host.
set -e
iptables -A INPUT -p udp -j DROP
iptables -A OUTPUT -p udp -j DROP
iptables -A FORWARD -p udp -j DROP
echo "UDP traffic blocked"
