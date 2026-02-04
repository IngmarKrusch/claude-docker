#!/bin/bash
set -e

# Log entrypoint messages (Claude Code clears the terminal, so we log to file too)
LOGFILE="/home/claude/.claude/entrypoint.log"
log() {
    echo "$1"
    echo "$(date '+%H:%M:%S') $1" >> "$LOGFILE"
}
echo "=== Entrypoint $(date) ===" >> "$LOGFILE"

# Initialize firewall if NET_ADMIN capability is available
if /usr/local/bin/init-firewall.sh 2>/dev/null; then
    log "[sandbox] Firewall initialized"
else
    log "[sandbox] Warning: Firewall not initialized (missing NET_ADMIN)"
fi

# Write credentials from environment variable into .claude directory
CREDS_FILE="/home/claude/.claude/.credentials.json"

# Check if existing credentials are expired
EXPIRED=false
if [ -f "$CREDS_FILE" ]; then
    EXPIRES_AT=$(jq -r '.claudeAiOauth.expiresAt // 0' "$CREDS_FILE" 2>/dev/null || echo 0)
    NOW_MS=$(($(date +%s) * 1000))
    if [ "$EXPIRES_AT" -le "$NOW_MS" ] && [ "$EXPIRES_AT" -ne 0 ]; then
        EXPIRED=true
        log "[sandbox] Existing credentials expired"
    fi
fi

if [ -n "$CLAUDE_CREDENTIALS" ]; then
    if [ ! -f "$CREDS_FILE" ] || [ "${FORCE_CREDENTIALS:-}" = "1" ] || [ "$EXPIRED" = true ]; then
        echo "$CLAUDE_CREDENTIALS" > "$CREDS_FILE"
        chown claude: "$CREDS_FILE"
        chmod 600 "$CREDS_FILE"
        if [ "${FORCE_CREDENTIALS:-}" = "1" ]; then
            log "[sandbox] Credentials force-refreshed from keychain"
        elif [ "$EXPIRED" = true ]; then
            log "[sandbox] Credentials auto-refreshed (expired)"
        else
            log "[sandbox] Credentials written (first run)"
        fi
    else
        log "[sandbox] Using existing credentials from volume (pass --fresh-creds to override)"
    fi
    unset CLAUDE_CREDENTIALS
    unset FORCE_CREDENTIALS
elif [ -f "$CREDS_FILE" ]; then
    chmod 600 "$CREDS_FILE"
    log "[sandbox] Credentials loaded (from volume)"
else
    log "[sandbox] Warning: No credentials found. Run 'claude login' or mount credentials."
fi

# Ensure Claude Code's config file lives on the volume.
# Without this, config is written to ~/.claude.json (outside the volume mount)
# and lost when the container exits. ~/.claude/.config.json is the preferred
# path that Claude Code checks first.
# Include required flags to skip interactive prompts in fresh volumes.
CONFIG_FILE="/home/claude/.claude/.config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    echo '{"hasCompletedOnboarding":true,"bypassPermissionsModeAccepted":true}' > "$CONFIG_FILE"
    chown claude: "$CONFIG_FILE"
fi

# Build writable .gitconfig that includes host gitconfig + safe.directory
if [ -f /tmp/host-gitconfig ]; then
    cp /tmp/host-gitconfig /home/claude/.gitconfig
    chown claude: /home/claude/.gitconfig
    HOME=/home/claude git config --global --add safe.directory /workspace
    log "[sandbox] Git configured"
fi

# Set user environment variables that 'USER claude' in Dockerfile would have
# provided. gosu only changes uid/gid, it does not set these.
export USER=claude
export LOGNAME=claude
export HOME=/home/claude
export SHELL=/bin/bash
export PATH="/home/claude/.local/bin:$PATH"

exec gosu claude "$@"
