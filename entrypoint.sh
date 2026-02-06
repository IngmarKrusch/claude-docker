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
    # Clear credentials from memory: unset and overwrite the variable
    CLAUDE_CREDENTIALS="$(head -c ${#CLAUDE_CREDENTIALS} /dev/urandom | base64)"
    unset CLAUDE_CREDENTIALS
    unset FORCE_CREDENTIALS
elif [ -f "$CREDS_FILE" ]; then
    chmod 600 "$CREDS_FILE"
    log "[sandbox] Credentials loaded (from volume)"
else
    log "[sandbox] Warning: No credentials found. Run 'claude login' or mount credentials."
fi

# Deferred credential scrub: overwrite and delete the plaintext credentials file
# after Claude Code has had time to read and cache them. We overwrite rather than
# chmod because virtiofs (macOS Docker mounts) ignores POSIX permission changes.
(sleep 3 && {
    CRED_SIZE=$(stat -c%s "$CREDS_FILE" 2>/dev/null || echo 0)
    if [ "$CRED_SIZE" -gt 0 ]; then
        dd if=/dev/urandom of="$CREDS_FILE" bs="$CRED_SIZE" count=1 conv=notrunc 2>/dev/null
    fi
    rm -f "$CREDS_FILE"
}) &

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

# Build writable .gitconfig on the volume (rootfs is read-only)
GITCONFIG="/home/claude/.claude/.gitconfig"
if [ -f /tmp/host-gitconfig ]; then
    cp /tmp/host-gitconfig "$GITCONFIG"
    chown claude: "$GITCONFIG"
    HOME=/home/claude GIT_CONFIG_GLOBAL="$GITCONFIG" git config --global --add safe.directory /workspace
    # Strip host credential helpers (e.g. macOS GCM) that don't exist in the container
    HOME=/home/claude GIT_CONFIG_GLOBAL="$GITCONFIG" \
        git config --global --unset-all credential.helper 2>/dev/null || true
    # Neutralise hooks from the mounted workspace — a compromised session must not
    # be able to plant hooks that execute on the host (or in future containers).
    HOME=/home/claude GIT_CONFIG_GLOBAL="$GITCONFIG" \
        git config --global core.hooksPath /dev/null
    log "[sandbox] Git configured"
fi
export GIT_CONFIG_GLOBAL="$GITCONFIG"

# Note: core.hooksPath and credential.helper are enforced by the git wrapper
# at /usr/local/bin/git, which force-sets GIT_CONFIG_COUNT on every invocation.
# The global gitconfig settings above serve as defense-in-depth only.

# Configure GitHub credentials for git push (in-memory only, never written to disk)
if [ -n "$GITHUB_TOKEN" ]; then
    CACHE_SOCK="/tmp/.git-credential-cache/sock"
    mkdir -p "$(dirname "$CACHE_SOCK")"
    chmod 700 "$(dirname "$CACHE_SOCK")"
    chown claude: "$(dirname "$CACHE_SOCK")"

    # Configure git to use the in-memory credential cache
    HOME=/home/claude GIT_CONFIG_GLOBAL="$GITCONFIG" \
        git config --global credential.helper "cache --timeout=86400 --socket=$CACHE_SOCK"

    # Scope the token to the workspace repo only.
    # With useHttpPath=true, git includes the repo path in credential lookups,
    # so a token stored for "github.com/owner/repo.git" won't be returned for
    # requests to other repos. This limits blast radius if the session is compromised.
    HOME=/home/claude GIT_CONFIG_GLOBAL="$GITCONFIG" \
        git config --global "credential.https://github.com.useHttpPath" true

    # Detect workspace repo path (e.g. "owner/repo") from git remote
    _REPO_PATH=""
    _REMOTE_URL=$(git -C /workspace remote get-url origin 2>/dev/null || true)
    if [[ "$_REMOTE_URL" =~ github\.com[:/](.+)$ ]]; then
        _REPO_PATH="${BASH_REMATCH[1]%.git}"
    fi

    # Scrub GITHUB_TOKEN from env BEFORE spawning the credential cache daemon.
    # git-credential-cache--daemon inherits the caller's environment and persists
    # for the container lifetime — leaving the token in /proc/<pid>/environ.
    _GH_TOKEN="$GITHUB_TOKEN"
    GITHUB_TOKEN="$(head -c ${#GITHUB_TOKEN} /dev/urandom | base64)"
    unset GITHUB_TOKEN

    # Feed token into cache daemon (run as claude so the socket is owned by claude)
    if [ -n "$_REPO_PATH" ]; then
        # Store credential WITH repo path — only serves token for this specific repo
        printf 'protocol=https\nhost=github.com\npath=%s.git\nusername=x-access-token\npassword=%s\n\n' \
            "$_REPO_PATH" "$_GH_TOKEN" | \
            gosu claude env -u GITHUB_TOKEN HOME=/home/claude GIT_CONFIG_GLOBAL="$GITCONFIG" git credential approve
        log "[sandbox] GitHub credentials configured (scoped to $_REPO_PATH)"
    else
        # Fallback: no GitHub remote detected, store without path restriction
        printf 'protocol=https\nhost=github.com\nusername=x-access-token\npassword=%s\n\n' "$_GH_TOKEN" | \
            gosu claude env -u GITHUB_TOKEN HOME=/home/claude GIT_CONFIG_GLOBAL="$GITCONFIG" git credential approve
        log "[sandbox] GitHub credentials configured (unscoped — no GitHub remote found)"
    fi

    # Scrub local variables
    _GH_TOKEN="$(head -c ${#_GH_TOKEN} /dev/urandom | base64)"
    unset _GH_TOKEN
    unset _REMOTE_URL _REPO_PATH
fi

# Fix ownership on tmpfs mounts (Docker creates them as root)
chown claude: /home/claude/.npm /home/claude/.config 2>/dev/null || true

# Set user environment variables that 'USER claude' in Dockerfile would have
# provided. gosu only changes uid/gid, it does not set these.
export USER=claude
export LOGNAME=claude
export HOME=/home/claude
export SHELL=/bin/bash
export PATH="/home/claude/.local/bin:$PATH"

# Disable core dumps to prevent secrets leaking via crash dumps to /workspace
ulimit -c 0

# Drop privileges and clear the bounding set in a single setpriv call.
# We can't exec gosu after clearing the bounding set because gosu needs
# CAP_SETUID/SETGID which are lost at the execve boundary. setpriv handles
# both: uid/gid change uses current effective caps, then the empty bounding
# set takes effect when exec'ing the final command.
#
# drop-dumpable calls prctl(PR_SET_DUMPABLE, 0) before exec'ing the real
# command. This prevents child processes (same UID) from reading/writing
# /proc/<pid>/mem of the claude process, even without CAP_SYS_PTRACE.
exec setpriv \
    --reuid="$(id -u claude)" \
    --regid="$(id -g claude)" \
    --init-groups \
    --inh-caps=-all \
    --bounding-set=-all \
    -- /usr/local/bin/drop-dumpable "$@"
