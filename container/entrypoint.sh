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
    cp -P "$HOST_CLAUDE/.config.json" "$CLAUDE_DIR/" 2>/dev/null || true

    # 2. Settings (copied as read snapshot — container edits don't propagate to host)
    cp -P "$HOST_CLAUDE/settings.json" "$CLAUDE_DIR/" 2>/dev/null || true
    cp -P "$HOST_CLAUDE/settings.local.json" "$CLAUDE_DIR/" 2>/dev/null || true

    # 2b. Status line script (referenced by settings.json statusLine command)
    cp -P "$HOST_CLAUDE/statusline-command.sh" "$CLAUDE_DIR/" 2>/dev/null || true

    # 3. User-level CLAUDE.md (project context, memory)
    cp -P "$HOST_CLAUDE/CLAUDE.md" "$CLAUDE_DIR/" 2>/dev/null || true

    # 4. Full history (needed for --continue/--resume to find past sessions)
    cp -P "$HOST_CLAUDE/history.jsonl" "$CLAUDE_DIR/" 2>/dev/null || true
    # Record baseline line count so sync-back can send only new entries
    wc -l < "$CLAUDE_DIR/history.jsonl" 2>/dev/null > "$CLAUDE_DIR/.history-baseline-lines" || true

    # 5. Current project data ONLY: memory + session transcripts
    #    Encode workspace path the same way Claude Code does (/ → -)
    WORKSPACE_PATH=$(readlink -f /workspace)
    ENCODED_PATH=$(echo "$WORKSPACE_PATH" | sed 's|/|-|g')
    # M12 Round 10 fix: Use host's real project path for data isolation.
    # Inside the container, /workspace always encodes to -workspace, causing
    # all projects to share the same data directory. PROJECT_PATH carries the
    # host-side path so each project gets its own encoded directory.
    if [ -n "${PROJECT_PATH:-}" ]; then
        HOST_ENCODED=$(echo "$PROJECT_PATH" | sed 's|/|-|g')
        if [ -d "$HOST_CLAUDE/projects/$HOST_ENCODED" ]; then
            mkdir -p "$CLAUDE_DIR/projects/$ENCODED_PATH"
            cp -rP "$HOST_CLAUDE/projects/$HOST_ENCODED/." \
                  "$CLAUDE_DIR/projects/$ENCODED_PATH/" 2>/dev/null || true
        fi
    elif [ -d "$HOST_CLAUDE/projects/$ENCODED_PATH" ]; then
        mkdir -p "$CLAUDE_DIR/projects/$ENCODED_PATH"
        cp -rP "$HOST_CLAUDE/projects/$ENCODED_PATH/." \
              "$CLAUDE_DIR/projects/$ENCODED_PATH/" 2>/dev/null || true
    fi

    # 6. Statsig cache (avoids re-fetching feature flags)
    if [ -d "$HOST_CLAUDE/statsig" ]; then
        cp -rP "$HOST_CLAUDE/statsig" "$CLAUDE_DIR/" 2>/dev/null || true
    fi

    # 7. Plugins (if any installed)
    if [ -d "$HOST_CLAUDE/plugins" ]; then
        cp -rP "$HOST_CLAUDE/plugins" "$CLAUDE_DIR/" 2>/dev/null || true
    fi

    # 7b. Plans (persist across sessions for plan-mode workflows)
    if [ -d "$HOST_CLAUDE/plans" ]; then
        cp -rP "$HOST_CLAUDE/plans" "$CLAUDE_DIR/" 2>/dev/null || true
    fi

    # 7c. Todos (persist across sessions)
    if [ -d "$HOST_CLAUDE/todos" ]; then
        cp -rP "$HOST_CLAUDE/todos" "$CLAUDE_DIR/" 2>/dev/null || true
    fi

    # 8. Stats cache
    cp -P "$HOST_CLAUDE/stats-cache.json" "$CLAUDE_DIR/" 2>/dev/null || true
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

        # M12 Round 10 fix: Relocate -workspace project data to host-encoded
        # path in staging so it syncs back to the correct project directory
        if [ -n "${PROJECT_PATH:-}" ]; then
            local HOST_ENCODED
            HOST_ENCODED=$(echo "$PROJECT_PATH" | sed 's|/|-|g')
            if [ "$HOST_ENCODED" != "-workspace" ] && [ -d "$STAGING/projects/-workspace" ]; then
                mkdir -p "$STAGING/projects/$HOST_ENCODED"
                cp -a "$STAGING/projects/-workspace/." "$STAGING/projects/$HOST_ENCODED/" 2>/dev/null || true
                rm -rf "$STAGING/projects/-workspace"
            fi
        fi
    fi
}

if [ "${SYNC_BACK:-}" = "1" ]; then
    trap sync_back_on_exit EXIT
fi

# Create push flag file (root-owned, immutable after privilege drop)
mkdir -p /run/sandbox-flags && chmod 755 /run/sandbox-flags
if [ "${ALLOW_GIT_PUSH:-}" = "1" ]; then
    touch /run/sandbox-flags/allow-git-push
    chmod 444 /run/sandbox-flags/allow-git-push
fi
unset ALLOW_GIT_PUSH

# Initialize firewall if NET_ADMIN capability is available
# L1 Round 10 fix: Make firewall init failure FATAL — without the firewall,
# the container has unrestricted network access, defeating the entire security model
if ! /usr/local/bin/init-firewall.sh 2>/dev/null; then
    log "[sandbox] FATAL: Firewall initialization failed"
    log "[sandbox] Container cannot start without network restrictions"
    exit 1
fi
log "[sandbox] Firewall initialized"

# Write credentials from environment variable into .claude directory
CREDS_FILE="/home/claude/.claude/.credentials.json"

# Check if existing credentials are expired
EXPIRED=false
if [ -f "$CREDS_FILE" ]; then
    EXPIRES_AT=$(jq -r '.claudeAiOauth.expiresAt // 0' "$CREDS_FILE" 2>/dev/null || echo 0)
    NOW_MS=$(($(date +%s) * 1000))
    # M10 Round 10 fix: Validate expiresAt is numeric to prevent crash under set -e
    if [[ "$EXPIRES_AT" =~ ^[0-9]+$ ]] && [ "$EXPIRES_AT" -le "$NOW_MS" ] && [ "$EXPIRES_AT" -ne 0 ]; then
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
(sleep 1 && {
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
    # Strip filter section from global gitconfig (same as workspace sanitization).
    # git-guard blocks 'git config filter.*' but the file can be edited directly
    # (sed, python, etc.) and git reads the raw config when executing filter commands.
    HOME=/home/claude GIT_CONFIG_GLOBAL="$GITCONFIG" \
        /usr/libexec/wrapped-git config --global --remove-section "filter" 2>/dev/null || true
    log "[sandbox] Git configured"
fi
export GIT_CONFIG_GLOBAL="$GITCONFIG"

# Sanitize workspace .git/config: strip dangerous keys that could execute code
# on the host after container exit. Use wrapped-git directly (root is exempt
# from git-guard) with -f to target only the repo-local config.
# M1 & H9 Round 10 fix: Expand to cover ALL git-guard blocked keys
if [ -f /workspace/.git/config ]; then
    # Unset exact-match keys
    for key in core.fsmonitor core.sshCommand core.hooksPath core.pager core.editor \
               core.gitProxy core.askPass credential.helper include.path; do
        /usr/libexec/wrapped-git config -f /workspace/.git/config --unset-all "$key" 2>/dev/null || true
    done
    # Remove entire sections (H3 Round 10 additions)
    for section in alias include filter url http remote credential diff merge; do
        /usr/libexec/wrapped-git config -f /workspace/.git/config --remove-section "$section" 2>/dev/null || true
    done
    # Remove all [includeIf "..."] sections. git stores these with quoted subsections
    # (e.g., [includeIf "gitdir:/path/"]) so --remove-section includeIf silently fails
    # (no bare [includeIf] section exists). Use awk to strip them from the raw file.
    if grep -q '^\[includeIf ' /workspace/.git/config 2>/dev/null; then
        _tmp="/workspace/.git/.includeif-strip.tmp"
        awk '/^\[includeIf /{ skip=1; next } /^\[/{ skip=0 } !skip{ print }' \
            /workspace/.git/config > "$_tmp" && mv "$_tmp" /workspace/.git/config
        rm -f "$_tmp"
    fi
    # Write post-sanitization hash so the host can compare against a clean baseline
    # (not the pre-sanitization snapshot). Written next to the entrypoint log mount.
    # M8 Round 10 fix: Make hash file immutable after creation to prevent tampering
    sha256sum /workspace/.git/config 2>/dev/null | cut -d' ' -f1 > /run/git-config-hash || true
    chmod 444 /run/git-config-hash 2>/dev/null || true
    chown root:root /run/git-config-hash 2>/dev/null || true
fi

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

    unset _GH_TOKEN
    unset _REMOTE_URL _REPO_PATH
fi

# Transfer ownership of all tmpfs content to claude before privilege drop.
# Done here (not earlier) because root without CAP_DAC_OVERRIDE cannot write
# to directories/files owned by other users — all root writes must complete first.
chown -R claude: "$CLAUDE_DIR" /home/claude/.npm /home/claude/.config 2>/dev/null || true

# Lock down gitconfig: prevent session from modifying git configuration.
# Must come AFTER the blanket chown (which sets everything to claude) and
# AFTER all git config --global writes (credential.helper, useHttpPath, etc.).
# Git only needs to READ the global config; GIT_CONFIG_COUNT env var overrides
# from the git wrapper don't write to the file.
chown root:root "$GITCONFIG" 2>/dev/null || true
chmod 444 "$GITCONFIG" 2>/dev/null || true

# Set user environment variables that 'USER claude' in Dockerfile would have
# provided. gosu only changes uid/gid, it does not set these.
export USER=claude
export LOGNAME=claude
export HOME=/home/claude
export SHELL=/bin/bash
export PATH="/home/claude/.local/bin:$PATH"

# Disable core dumps to prevent secrets leaking via crash dumps to /workspace
# L2 Round 10 fix: Set both hard and soft limits to prevent re-enabling
ulimit -Hc 0 2>/dev/null; ulimit -Sc 0

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
#   1. nodump.so via /etc/ld.so.preload (primary) — constructor calls
#      prctl(PR_SET_DUMPABLE, 0) AFTER exec, inside the new process.
#   2. chmod 711 on wrapped-git (belt-and-suspenders) — non-readable binaries
#      cause would_dump() to set dumpable=0 on exec, independent of LD_PRELOAD.
#      (claude is excluded: Bun single-file executables must read themselves.)

SETPRIV_CMD=(setpriv
    --reuid="$(id -u claude)"
    --regid="$(id -g claude)"
    --init-groups
    --inh-caps=-all
    --bounding-set=-all
    -- "$@")

if [ "${SYNC_BACK:-}" = "1" ]; then
    # Run as child process so the EXIT trap fires when it ends.
    # exec replaces the shell, so the trap would never run.
    "${SETPRIV_CMD[@]}" &
    CHILD_PID=$!
    # Forward signals to child
    # M11 Round 10 fix: Wait for child after TERM to prevent sync-back race
    trap 'kill -TERM $CHILD_PID 2>/dev/null; wait $CHILD_PID 2>/dev/null' TERM
    trap 'kill -INT $CHILD_PID 2>/dev/null' INT
    wait $CHILD_PID
    EXIT_CODE=$?
    exit $EXIT_CODE   # triggers sync_back_on_exit via EXIT trap
else
    exec "${SETPRIV_CMD[@]}"
fi
