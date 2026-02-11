#!/bin/bash
# reload-firewall.sh - Reload firewall allowlist from config file.
# Called by init-firewall.sh at startup and by 'docker exec' on host-triggered reload.
set -euo pipefail
IFS=$'\n\t'

_log() {
    echo "$1"
    if [ -n "${ENTRYPOINT_LOG:-}" ]; then
        echo "[sandbox] $1" >> "$ENTRYPOINT_LOG" || true
    fi
}

CONFIG="/etc/firewall-allowlist.conf"
IPSET_NAME="allowed-domains"
IPSET_TMP="${IPSET_NAME}-new"

if [ ! -f "$CONFIG" ]; then
    _log "ERROR: Config file not found: $CONFIG"
    exit 1
fi

# Clean up any stale temp ipset from a previous failed run
/usr/sbin/ipset destroy "$IPSET_TMP" 2>/dev/null || true

# Create temp ipset
/usr/sbin/ipset create "$IPSET_TMP" hash:net

ENTRY_COUNT=0
FAIL_COUNT=0

while IFS= read -r line; do
    # Strip leading/trailing whitespace
    line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    # Skip comments and blank lines
    [[ -z "$line" || "$line" == \#* ]] && continue

    if [[ "$line" == "@github" ]]; then
        _log "Fetching GitHub IP ranges..."
        gh_ranges=$(/usr/bin/curl -s --connect-timeout 10 https://api.github.com/meta)
        if [ -z "$gh_ranges" ]; then
            _log "WARNING: Failed to fetch GitHub IP ranges, skipping"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            continue
        fi

        if ! echo "$gh_ranges" | /usr/bin/jq -e '.web and .api and .git' >/dev/null 2>&1; then
            _log "WARNING: GitHub API response missing required fields, skipping"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            continue
        fi

        _log "Processing GitHub IPs..."
        while read -r cidr; do
            if [[ "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
                _prefix="${cidr##*/}"
                if [ "$_prefix" -gt 32 ] 2>/dev/null; then
                    _log "WARNING: Invalid CIDR prefix /$_prefix from GitHub meta: $cidr"
                    continue
                fi
                /usr/sbin/ipset add "$IPSET_TMP" "$cidr" 2>/dev/null || true
                ENTRY_COUNT=$((ENTRY_COUNT + 1))
            else
                _log "WARNING: Invalid CIDR from GitHub meta: $cidr"
            fi
        done < <(echo "$gh_ranges" | /usr/bin/jq -r '(.web + .api + .git)[]' | /usr/bin/aggregate -q)
    else
        # Regular domain entry — resolve via DNS
        _log "Resolving $line..."
        ips=$(/usr/bin/dig +noall +answer A "$line" | /usr/bin/awk '$4 == "A" {print $5}')
        if [ -z "$ips" ]; then
            _log "WARNING: Failed to resolve $line, skipping"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            continue
        fi

        while read -r ip; do
            if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                /usr/sbin/ipset add "$IPSET_TMP" "$ip" 2>/dev/null || true
                ENTRY_COUNT=$((ENTRY_COUNT + 1))
            else
                _log "WARNING: Invalid IP from DNS for $line: $ip"
            fi
        done < <(echo "$ips")
    fi
done < "$CONFIG"

if [ "$ENTRY_COUNT" -eq 0 ]; then
    _log "ERROR: No entries resolved, keeping existing ipset unchanged"
    /usr/sbin/ipset destroy "$IPSET_TMP" 2>/dev/null || true
    exit 1
fi

# Atomic swap: replace current ipset with new one
/usr/sbin/ipset swap "$IPSET_NAME" "$IPSET_TMP"
/usr/sbin/ipset destroy "$IPSET_TMP"

_log "Firewall allowlist reloaded: $ENTRY_COUNT entries ($FAIL_COUNT warnings)"
