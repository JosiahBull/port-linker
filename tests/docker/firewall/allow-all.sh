#!/bin/bash
# Reset all firewall rules to allow all traffic.
set -e
iptables -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
echo "Firewall rules reset (all traffic allowed)"
