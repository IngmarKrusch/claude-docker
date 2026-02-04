#!/bin/bash
set -e

# Initialize firewall if NET_ADMIN capability is available
if /usr/local/bin/init-firewall.sh 2>/dev/null; then
    echo "[sandbox] Firewall initialized"
else
    echo "[sandbox] Warning: Firewall not initialized (missing NET_ADMIN)"
fi

# Write credentials from environment variable into .claude directory
CREDS_FILE="/home/claude/.claude/.credentials.json"
if [ -n "$CLAUDE_CREDENTIALS" ]; then
    if [ ! -f "$CREDS_FILE" ] || [ "${FORCE_CREDENTIALS:-}" = "1" ]; then
        echo "$CLAUDE_CREDENTIALS" > "$CREDS_FILE"
        chown claude: "$CREDS_FILE"
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

# Ensure Claude Code's config file lives on the volume.
# Without this, config is written to ~/.claude.json (outside the volume mount)
# and lost when the container exits. ~/.claude/.config.json is the preferred
# path that Claude Code checks first.
CONFIG_FILE="/home/claude/.claude/.config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    echo '{}' > "$CONFIG_FILE"
    chown claude: "$CONFIG_FILE"
fi

# Build writable .gitconfig that includes host gitconfig + safe.directory
if [ -f /tmp/host-gitconfig ]; then
    cp /tmp/host-gitconfig /home/claude/.gitconfig
    chown claude: /home/claude/.gitconfig
    HOME=/home/claude git config --global --add safe.directory /workspace
    echo "[sandbox] Git configured"
fi

# Set user environment variables that 'USER claude' in Dockerfile would have
# provided. gosu only changes uid/gid, it does not set these.
export USER=claude
export LOGNAME=claude
export HOME=/home/claude
export SHELL=/bin/bash
export PATH="/home/claude/.local/bin:$PATH"

exec gosu claude "$@"
