#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, and pipeline failures
IFS=$'\n\t'       # Stricter word splitting

# 1. Extract Docker DNS info BEFORE any flushing
DOCKER_DNS_RULES=$(iptables-save -t nat | grep "127\.0\.0\.11" || true)

# Flush existing rules and delete existing ipsets
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
ipset destroy allowed-domains 2>/dev/null || true

# 2. Selectively restore ONLY internal Docker DNS resolution
if [ -n "$DOCKER_DNS_RULES" ]; then
    echo "Restoring Docker DNS rules..."
    iptables -t nat -N DOCKER_OUTPUT 2>/dev/null || true
    iptables -t nat -N DOCKER_POSTROUTING 2>/dev/null || true
    echo "$DOCKER_DNS_RULES" | xargs -L 1 iptables -t nat
else
    echo "No Docker DNS rules to restore"
fi

# Auto-detect the actual DNS resolver (OrbStack uses 0.250.250.200, Docker Desktop uses 127.0.0.11)
DNS_RESOLVER=$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf)
if [ -z "$DNS_RESOLVER" ]; then
    DNS_RESOLVER="127.0.0.11"
    echo "WARNING: Could not detect DNS resolver, falling back to $DNS_RESOLVER"
fi
echo "DNS resolver detected as: $DNS_RESOLVER"

# Rate-limit and size-limit DNS to mitigate DNS tunneling exfiltration.
# DNS is pinned to the internal resolver (no direct external DNS), but the
# resolver forwards all queries — enabling data exfiltration via subdomain
# encoding (~50 bytes/query). These rules reduce tunneling throughput:
# - Drop oversized UDP DNS packets (>512 bytes, RFC 1035 standard limit)
# - Rate-limit to 10/sec sustained, burst 20 (sufficient for npm/git/curl)
# - At 10 queries/sec × ~50 bytes payload, tunneling drops to ~500 B/s
iptables -A OUTPUT -p udp --dport 53 -d "$DNS_RESOLVER" -m length --length 513:65535 -j DROP
iptables -A OUTPUT -p udp --dport 53 -d "$DNS_RESOLVER" -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -d "$DNS_RESOLVER" -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
# Block DNS to ALL other destinations (must come before general allowlist rules)
iptables -A OUTPUT -p udp --dport 53 -j DROP
iptables -A OUTPUT -p tcp --dport 53 -j DROP
# Allow inbound DNS responses from the detected resolver
iptables -A INPUT -p udp --sport 53 -s "$DNS_RESOLVER" -j ACCEPT
iptables -A INPUT -p tcp --sport 53 -s "$DNS_RESOLVER" -j ACCEPT
# Allow localhost
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Create ipset with CIDR support
ipset create allowed-domains hash:net

# Load allowlist from config file (resolves domains, fetches GitHub IPs, atomic ipset swap)
/usr/local/bin/reload-firewall.sh

# Get host IP from default route
HOST_IP=$(ip route | grep default | cut -d" " -f3)
if [ -z "$HOST_IP" ]; then
    echo "ERROR: Failed to detect host IP"
    exit 1
fi

HOST_NETWORK=$(echo "$HOST_IP" | sed "s/\.[0-9]*$/.0\/24/")
echo "Host network detected as: $HOST_NETWORK"

# Set up remaining iptables rules
iptables -A INPUT -s "$HOST_NETWORK" -j ACCEPT
iptables -A OUTPUT -d "$HOST_NETWORK" -j ACCEPT

# Set default policies to DROP first
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# First allow established connections for already approved traffic
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow outbound SSH only to allowlisted destinations (prevents tunneling to arbitrary servers)
iptables -A OUTPUT -p tcp --dport 22 -m set --match-set allowed-domains dst -j ACCEPT
# Allow other outbound traffic to allowed domains (HTTPS, etc.)
iptables -A OUTPUT -m set --match-set allowed-domains dst -j ACCEPT

# Explicitly REJECT all other outbound traffic for immediate feedback
iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited

echo "Firewall configuration complete"
echo "Verifying firewall rules..."
if curl --connect-timeout 5 https://example.com >/dev/null 2>&1; then
    echo "ERROR: Firewall verification failed - was able to reach https://example.com"
    exit 1
else
    echo "Firewall verification passed - unable to reach https://example.com as expected"
fi

# Verify GitHub API access
if ! curl --connect-timeout 5 https://api.github.com/zen >/dev/null 2>&1; then
    echo "ERROR: Firewall verification failed - unable to reach https://api.github.com"
    exit 1
else
    echo "Firewall verification passed - able to reach https://api.github.com as expected"
fi
