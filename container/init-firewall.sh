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
    # R12-M07 fix: Replace xargs with while read loop (xargs without -0 is fragile).
    # Subshell resets IFS to default (script sets IFS=$'\n\t' which lacks space,
    # so unquoted $_rule wouldn't be word-split into separate iptables arguments).
    while IFS= read -r _rule; do
        [ -z "$_rule" ] && continue
        # shellcheck disable=SC2086  # $_rule must word-split into separate iptables arguments
        (IFS=$' \t\n'; iptables -t nat $_rule)
    done <<< "$DOCKER_DNS_RULES"
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

# DNS exfiltration prevention: block ALL DNS for the claude user.
# Allowlisted domains are pre-resolved on the host and injected into /etc/hosts
# via Docker --add-host flags. The container's glibc checks /etc/hosts before
# DNS (nsswitch.conf: hosts: files dns), so tools resolve from the static entries.
# Root/system processes retain DNS access for ipset population during init.
# Oversized DNS packets are still dropped as defense-in-depth.
CLAUDE_UID=$(id -u claude)
iptables -A OUTPUT -p udp --dport 53 -d "$DNS_RESOLVER" -m length --length 193:65535 -j DROP
# Unrestricted DNS for root/system processes (init, firewall setup, verification)
iptables -A OUTPUT -p udp --dport 53 -d "$DNS_RESOLVER" -m owner ! --uid-owner "$CLAUDE_UID" -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -d "$DNS_RESOLVER" -m owner ! --uid-owner "$CLAUDE_UID" -j ACCEPT
# Block ALL DNS for claude user — domains pre-resolved via /etc/hosts (--add-host)
iptables -A OUTPUT -p udp --dport 53 -m owner --uid-owner "$CLAUDE_UID" -j DROP
iptables -A OUTPUT -p tcp --dport 53 -m owner --uid-owner "$CLAUDE_UID" -j DROP
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

# R12-C03 fix: Block cloud metadata endpoints (AWS/GCP/Azure) — prevent credential
# leakage on cloud VMs. Must come before host network allow rules.
iptables -A OUTPUT -d 169.254.169.254/32 -j DROP
iptables -A OUTPUT -d 169.254.0.0/16 -j DROP

# R17-02 fix: Block dangerous ports to host subnet BEFORE general host network ACCEPT.
# SSH (port 22) is an exfiltration channel; Docker API (2375/2376) enables container escape.
# Must come before the host network ACCEPT rule (first-match-wins).
iptables -A OUTPUT -d "$HOST_NETWORK" -p tcp --dport 22 -j DROP
iptables -A OUTPUT -d "$HOST_NETWORK" -p tcp --dport 2375 -j DROP
iptables -A OUTPUT -d "$HOST_NETWORK" -p tcp --dport 2376 -j DROP

# Set up remaining iptables rules
iptables -A INPUT -s "$HOST_NETWORK" -j ACCEPT
# R19-02: TCP-only — Docker Desktop MCP proxy uses TCP; UDP/SCTP/raw not needed.
# Return traffic for TCP connections is handled by ESTABLISHED,RELATED (below).
iptables -A OUTPUT -p tcp -d "$HOST_NETWORK" -j ACCEPT

# Set default policies to DROP first
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# R12-M05 fix: Defense-in-depth — IPv6 disabled via sysctl, but set DROP policy as backup
ip6tables -P INPUT DROP 2>/dev/null || true
ip6tables -P OUTPUT DROP 2>/dev/null || true
ip6tables -P FORWARD DROP 2>/dev/null || true

# First allow established connections for already approved traffic
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Block outbound SSH — this repo uses HTTPS for GitHub, and SSH port 22 is a
# data exfiltration channel (raw TCP accepted by github.com:22 without auth).
iptables -A OUTPUT -p tcp --dport 22 -j DROP
# R19-07: Block SCTP — unnecessary protocol, already blocked by default DROP
# policy but explicit rule provides defense-in-depth and clear audit trail.
iptables -A OUTPUT -p sctp -j DROP
# H2 Round 10 fix: Restrict ipset to HTTPS (443) and HTTP (80) only.
# Previously allowed ALL protocols/ports to any IP in allowed-domains.
iptables -A OUTPUT -p tcp --dport 443 -m set --match-set allowed-domains dst -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -m set --match-set allowed-domains dst -j ACCEPT

# Explicitly REJECT all other outbound traffic for immediate feedback
iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited

# R19-06: Delete unused tunnel interfaces (kernel defaults, inoperable after
# privilege drop — NET_ADMIN is cleared from bounding set). Defense-in-depth.
ip link delete tunl0 2>/dev/null || true
ip link delete sit0 2>/dev/null || true
ip link delete ip6tnl0 2>/dev/null || true

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

# Verify firewall rules work for the claude user (not just root, which retains
# DNS access). Claude user resolves hostnames via /etc/hosts (pre-resolved on host).
if ! gosu claude curl --connect-timeout 10 https://api.github.com/zen >/dev/null 2>&1; then
    _log "FATAL: Claude user cannot reach GitHub API - check /etc/hosts entries (--add-host)"
    exit 1
fi
