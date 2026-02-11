#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, and pipeline failures
IFS=$'\n\t'       # Stricter word splitting

_log() {
    echo "$1"
    if [ -n "${ENTRYPOINT_LOG:-}" ]; then
        echo "[sandbox] $1" >> "$ENTRYPOINT_LOG" || true
    fi
}

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
    _log "Restoring Docker DNS rules..."
    iptables -t nat -N DOCKER_OUTPUT 2>/dev/null || true
    iptables -t nat -N DOCKER_POSTROUTING 2>/dev/null || true
    echo "$DOCKER_DNS_RULES" | xargs -L 1 iptables -t nat
else
    _log "No Docker DNS rules to restore"
fi

# Auto-detect the actual DNS resolver (OrbStack uses 0.250.250.200, Docker Desktop uses 127.0.0.11)
DNS_RESOLVER=$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf)
if [ -z "$DNS_RESOLVER" ]; then
    DNS_RESOLVER="127.0.0.11"
    _log "WARNING: Could not detect DNS resolver, falling back to $DNS_RESOLVER"
fi
_log "DNS resolver detected as: $DNS_RESOLVER"

# Rate-limit and size-limit DNS to mitigate DNS tunneling exfiltration.
# DNS is pinned to the internal resolver (no direct external DNS), but the
# resolver forwards all queries — enabling data exfiltration via subdomain
# encoding (~50 bytes/query). These rules reduce tunneling throughput:
# - Drop oversized UDP DNS packets (>192 bytes — normal queries are <128 bytes)
# - Rate-limit claude user to 1/sec sustained, burst 2 (sufficient for npm/git/curl)
# - At 1 query/sec × ~50 bytes payload, tunneling drops to ~25 B/s
# - Root/system processes are unrestricted (needed during init for domain resolution
#   and firewall verification; root only runs during entrypoint, before privilege drop)
CLAUDE_UID=$(id -u claude)
iptables -A OUTPUT -p udp --dport 53 -d "$DNS_RESOLVER" -m length --length 193:65535 -j DROP
# Unrestricted DNS for root/system processes (init, firewall setup, verification)
iptables -A OUTPUT -p udp --dport 53 -d "$DNS_RESOLVER" -m owner ! --uid-owner "$CLAUDE_UID" -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -d "$DNS_RESOLVER" -m owner ! --uid-owner "$CLAUDE_UID" -j ACCEPT
# Rate-limited DNS for claude user (anti-tunneling)
iptables -A OUTPUT -p udp --dport 53 -d "$DNS_RESOLVER" -m owner --uid-owner "$CLAUDE_UID" -m limit --limit 1/sec --limit-burst 2 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -d "$DNS_RESOLVER" -m owner --uid-owner "$CLAUDE_UID" -m limit --limit 1/sec --limit-burst 2 -j ACCEPT
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
    _log "ERROR: Failed to detect host IP"
    exit 1
fi

# Derive actual CIDR from the default route interface (not hardcoded /24)
DEFAULT_IF=$(ip route | awk '/^default/ {print $5; exit}')
HOST_NETWORK=$(ip -4 addr show dev "$DEFAULT_IF" 2>/dev/null | awk '/inet / {print $2; exit}')
if [ -z "$HOST_NETWORK" ]; then
    HOST_NETWORK=$(echo "$HOST_IP" | sed "s/\.[0-9]*$/.0\/24/")
    _log "WARNING: Could not determine subnet CIDR, falling back to $HOST_NETWORK"
else
    _log "Host network detected as: $HOST_NETWORK (from $DEFAULT_IF)"
fi

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

# Block outbound SSH — this repo uses HTTPS for GitHub, and SSH port 22 is a
# data exfiltration channel (raw TCP accepted by github.com:22 without auth).
iptables -A OUTPUT -p tcp --dport 22 -j DROP
# Allow other outbound traffic to allowed domains (HTTPS, etc.)
iptables -A OUTPUT -m set --match-set allowed-domains dst -j ACCEPT

# Explicitly REJECT all other outbound traffic for immediate feedback
iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited

_log "Firewall configuration complete"
_log "Verifying firewall rules..."
if curl --connect-timeout 5 https://example.com >/dev/null 2>&1; then
    _log "ERROR: Firewall verification failed - was able to reach https://example.com"
    exit 1
else
    _log "Firewall verification passed - unable to reach https://example.com as expected"
fi

# Verify GitHub API access
if ! curl --connect-timeout 5 https://api.github.com/zen >/dev/null 2>&1; then
    _log "ERROR: Firewall verification failed - unable to reach https://api.github.com"
    exit 1
else
    _log "Firewall verification passed - able to reach https://api.github.com as expected"
fi

# Verify firewall rules work for the claude user (not just root, which is exempt
# from DNS rate limiting and packet size limits) (M5 fix)
if ! gosu claude curl --connect-timeout 10 https://api.github.com/zen >/dev/null 2>&1; then
    _log "WARNING: Claude user cannot reach GitHub API - DNS rate limit may be too aggressive"
fi
