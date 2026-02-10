#!/bin/bash
set -e

# Log entrypoint messages (Claude Code clears the terminal, so we log to file too)
LOGFILE="/home/claude/.claude/entrypoint.log"
HOST_LOG="${ENTRYPOINT_LOG:-}"
log() {
    echo "$1"
    echo "$(date '+%H:%M:%S') $1" >> "$LOGFILE"
    if [ -n "$HOST_LOG" ]; then
        echo "$1" >> "$HOST_LOG" || true
    fi
}

# --- Mount isolation: populate writable tmpfs from read-only host mount ---
# When ~/.claude-host exists (read-only host mount), copy needed data into the
# writable tmpfs at ~/.claude. This runs BEFORE the log file is opened so that
# any host entrypoint.log doesn't conflict.
HOST_CLAUDE="/mnt/.claude-host"
CLAUDE_DIR="/home/claude/.claude"

if [ -d "$HOST_CLAUDE" ]; then
    # 1. Config (required for onboarding flags, user prefs, account info)
    cp "$HOST_CLAUDE/.config.json" "$CLAUDE_DIR/" 2>/dev/null || true

    # 2. Settings (copied as read snapshot — container edits don't propagate to host)
    cp "$HOST_CLAUDE/settings.json" "$CLAUDE_DIR/" 2>/dev/null || true
    cp "$HOST_CLAUDE/settings.local.json" "$CLAUDE_DIR/" 2>/dev/null || true

    # 2b. Status line script (referenced by settings.json statusLine command)
    cp "$HOST_CLAUDE/statusline-command.sh" "$CLAUDE_DIR/" 2>/dev/null || true

    # 3. User-level CLAUDE.md (project context, memory)
    cp "$HOST_CLAUDE/CLAUDE.md" "$CLAUDE_DIR/" 2>/dev/null || true

    # 4. Full history (needed for --continue/--resume to find past sessions)
    cp "$HOST_CLAUDE/history.jsonl" "$CLAUDE_DIR/" 2>/dev/null || true
    # Record baseline line count so sync-back can send only new entries
    wc -l < "$CLAUDE_DIR/history.jsonl" 2>/dev/null > "$CLAUDE_DIR/.history-baseline-lines" || true

    # 5. Current project data ONLY: memory + session transcripts
    #    Encode workspace path the same way Claude Code does (/ → -)
    WORKSPACE_PATH=$(readlink -f /workspace)
    ENCODED_PATH=$(echo "$WORKSPACE_PATH" | sed 's|/|-|g')
    if [ -d "$HOST_CLAUDE/projects/$ENCODED_PATH" ]; then
        mkdir -p "$CLAUDE_DIR/projects/$ENCODED_PATH"
        cp -r "$HOST_CLAUDE/projects/$ENCODED_PATH/." \
              "$CLAUDE_DIR/projects/$ENCODED_PATH/" 2>/dev/null || true
    fi
    # Also copy the -workspace project data (container's view of the path)
    if [ -d "$HOST_CLAUDE/projects/-workspace" ]; then
        mkdir -p "$CLAUDE_DIR/projects/-workspace"
        cp -r "$HOST_CLAUDE/projects/-workspace/." \
              "$CLAUDE_DIR/projects/-workspace/" 2>/dev/null || true
    fi

    # 6. Statsig cache (avoids re-fetching feature flags)
    if [ -d "$HOST_CLAUDE/statsig" ]; then
        cp -r "$HOST_CLAUDE/statsig" "$CLAUDE_DIR/" 2>/dev/null || true
    fi

    # 7. Plugins (if any installed)
    if [ -d "$HOST_CLAUDE/plugins" ]; then
        cp -r "$HOST_CLAUDE/plugins" "$CLAUDE_DIR/" 2>/dev/null || true
    fi

    # 8. Stats cache
    cp "$HOST_CLAUDE/stats-cache.json" "$CLAUDE_DIR/" 2>/dev/null || true
fi

echo "=== Entrypoint $(date) ===" >> "$LOGFILE"

if [ -d "$HOST_CLAUDE" ]; then
    log "[sandbox] Host state loaded (read-only mount isolation active)"
fi

# --- Sync-back: EXIT trap to stage data for host merge ---
sync_back_on_exit() {
    local SYNC_DIR="/home/claude/.claude-sync"
    if [ -d "$SYNC_DIR" ]; then
        local STAGING="$SYNC_DIR/data"
        mkdir -p "$STAGING"

        # Copy everything that changed, EXCLUDING blocked and transient files.
        # --no-links skips ALL symlinks to prevent symlink planting attacks
        # (e.g. ~/.claude/evil -> /etc/passwd on host). --safe-links only blocked
        # absolute symlinks, but relative symlinks like ../../../etc/passwd could
        # still escape. --no-links is the strictest option.
        rsync -a --no-links \
            --exclude='settings.json' \
            --exclude='settings.local.json' \
            --exclude='statusline-command.sh' \
            --exclude='CLAUDE.md' \
            --exclude='.credentials.json' \
            --exclude='.gitconfig' \
            --exclude='entrypoint.log' \
            --exclude='.history-baseline-lines' \
            "$CLAUDE_DIR/" "$STAGING/" 2>/dev/null || true
    fi
}

if [ "${SYNC_BACK:-}" = "1" ]; then
    trap sync_back_on_exit EXIT
fi

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
fi

# Build writable .gitconfig on the volume (rootfs is read-only)
GITCONFIG="/home/claude/.claude/.gitconfig"
if [ -f /tmp/host-gitconfig ]; then
    cp /tmp/host-gitconfig "$GITCONFIG"
    chmod 644 "$GITCONFIG"
    HOME=/home/claude GIT_CONFIG_GLOBAL="$GITCONFIG" git config --global --add safe.directory /workspace
    # Strip host credential helpers (e.g. macOS GCM) that don't exist in the container
    # Use wrapped-git directly: these keys are intentionally blocked by the git
    # wrapper to prevent Claude from overriding them, but the entrypoint is trusted
    # init code that needs to set the baseline values.
    HOME=/home/claude GIT_CONFIG_GLOBAL="$GITCONFIG" \
        /usr/libexec/wrapped-git config --global --unset-all credential.helper 2>/dev/null || true
    # Neutralise hooks from the mounted workspace — a compromised session must not
    # be able to plant hooks that execute on the host (or in future containers).
    HOME=/home/claude GIT_CONFIG_GLOBAL="$GITCONFIG" \
        /usr/libexec/wrapped-git config --global core.hooksPath /dev/null
    log "[sandbox] Git configured"
fi
export GIT_CONFIG_GLOBAL="$GITCONFIG"

# Note: core.hooksPath and credential.helper are enforced by the git wrapper
# at /usr/local/bin/git, which force-sets GIT_CONFIG_COUNT on every invocation.
# The global gitconfig settings above serve as defense-in-depth only.

# nodump.so and git-guard.so are loaded via /etc/ld.so.preload (read-only rootfs),
# which is kernel-enforced and cannot be bypassed by environment manipulation.
# No LD_PRELOAD export needed — /etc/ld.so.preload handles both libraries.

# Configure GitHub credentials for git push (in-memory only, never written to disk)
if [ -n "$GITHUB_TOKEN" ]; then
    CACHE_SOCK="/tmp/.git-credential-cache/sock"
    mkdir -p "$(dirname "$CACHE_SOCK")"
    chmod 700 "$(dirname "$CACHE_SOCK")"
    chown claude: "$(dirname "$CACHE_SOCK")"

    # Configure git to use the in-memory credential cache (bypass wrapper — blocked key)
    HOME=/home/claude GIT_CONFIG_GLOBAL="$GITCONFIG" \
        /usr/libexec/wrapped-git config --global credential.helper "cache --timeout=86400 --socket=$CACHE_SOCK"

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

# Transfer ownership of all tmpfs content to claude before privilege drop.
# Done here (not earlier) because root without CAP_DAC_OVERRIDE cannot write
# to directories/files owned by other users — all root writes must complete first.
chown -R claude: "$CLAUDE_DIR" /home/claude/.npm /home/claude/.config 2>/dev/null || true

# Set user environment variables that 'USER claude' in Dockerfile would have
# provided. gosu only changes uid/gid, it does not set these.
export USER=claude
export LOGNAME=claude
export HOME=/home/claude
export SHELL=/bin/bash
export PATH="/home/claude/.local/bin:$PATH"

# Disable core dumps to prevent secrets leaking via crash dumps to /workspace
ulimit -c 0

# Disable error reporting — sentry.io is removed from the firewall allowlist
# because it accepts arbitrary POST data (exfiltration channel). This env var
# ensures Claude Code doesn't attempt to send error reports even if the allowlist
# is accidentally widened in the future.
export DISABLE_ERROR_REPORTING=1

# Drop privileges and clear the bounding set in a single setpriv call.
# We can't exec gosu after clearing the bounding set because gosu needs
# CAP_SETUID/SETGID which are lost at the execve boundary. setpriv handles
# both: uid/gid change uses current effective caps, then the empty bounding
# set takes effect when exec'ing the final command.
#
# /proc/<pid>/mem protection is provided by two layers:
#   1. LD_PRELOAD=nodump.so (primary) — constructor calls prctl(PR_SET_DUMPABLE, 0)
#      AFTER exec, inside the new process. This is the only reliable method because
#      the kernel resets dumpable=1 on exec of readable binaries (would_dump).
#   2. drop-dumpable (defense-in-depth) — sets dumpable=0 BEFORE exec. Ineffective
#      alone (kernel resets it), but provides a fallback for statically-linked binaries
#      that don't load LD_PRELOAD.
#   3. chmod 711 on wrapped-git (belt-and-suspenders) — non-readable binaries
#      cause would_dump() to set dumpable=0 on exec, independent of LD_PRELOAD.
#      (claude is excluded: Bun single-file executables must read themselves.)

SETPRIV_CMD=(setpriv
    --reuid="$(id -u claude)"
    --regid="$(id -g claude)"
    --init-groups
    --inh-caps=-all
    --bounding-set=-all
    -- /usr/local/bin/drop-dumpable "$@")

if [ "${SYNC_BACK:-}" = "1" ]; then
    # Run as child process so the EXIT trap fires when it ends.
    # exec replaces the shell, so the trap would never run.
    "${SETPRIV_CMD[@]}" &
    CHILD_PID=$!
    # Forward signals to child
    trap 'kill -TERM $CHILD_PID 2>/dev/null' TERM
    trap 'kill -INT $CHILD_PID 2>/dev/null' INT
    wait $CHILD_PID
    EXIT_CODE=$?
    exit $EXIT_CODE   # triggers sync_back_on_exit via EXIT trap
else
    exec "${SETPRIV_CMD[@]}"
fi
