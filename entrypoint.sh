#!/bin/bash
set -e

# Initialize firewall if NET_ADMIN capability is available
if sudo /usr/local/bin/init-firewall.sh 2>/dev/null; then
    echo "[sandbox] Firewall initialized"
else
    echo "[sandbox] Warning: Firewall not initialized (missing NET_ADMIN)"
fi

# Write credentials from environment variable into .claude directory
CREDS_FILE="$HOME/.claude/.credentials.json"
if [ -n "$CLAUDE_CREDENTIALS" ]; then
    if [ ! -f "$CREDS_FILE" ] || [ "${FORCE_CREDENTIALS:-}" = "1" ]; then
        echo "$CLAUDE_CREDENTIALS" > "$CREDS_FILE"
        chmod 600 "$CREDS_FILE"
        if [ "${FORCE_CREDENTIALS:-}" = "1" ]; then
            echo "[sandbox] Credentials force-refreshed from keychain"
        else
            echo "[sandbox] Credentials written (first run)"
        fi
    else
        echo "[sandbox] Using existing credentials from volume (pass --fresh-creds to override)"
    fi
    unset CLAUDE_CREDENTIALS
    unset FORCE_CREDENTIALS
elif [ -f "$CREDS_FILE" ]; then
    chmod 600 "$CREDS_FILE"
    echo "[sandbox] Credentials loaded (from volume)"
else
    echo "[sandbox] Warning: No credentials found. Run 'claude login' or mount credentials."
fi

# Build writable .gitconfig that includes host gitconfig + safe.directory
if [ -f /tmp/host-gitconfig ]; then
    cp /tmp/host-gitconfig "$HOME/.gitconfig"
    git config --global --add safe.directory /workspace
    echo "[sandbox] Git configured"
fi

exec "$@"
