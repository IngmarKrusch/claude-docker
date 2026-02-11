#!/bin/bash
# run-claude.sh - Launch Claude Code in a sandboxed Docker container
set -e

LAUNCH_LOG=""
log() { echo "$1"; LAUNCH_LOG+="$1"$'\n'; }

usage() {
    cat <<'EOF'
Usage: run-claude.sh [OPTIONS] [PROJECT_DIR] [CLAUDE_ARGS...]

Launch Claude Code in a hardened Docker container. Credentials are extracted
from the macOS keychain automatically. If PROJECT_DIR is omitted, the current
directory is used. Any additional arguments are passed through to Claude Code.

Options:
  -h, --help              Show this help message and exit
  --rebuild               Rebuild the Docker image (runs lint, checks the
                          latest Claude Code version, skips if already
                          up-to-date, uses targeted cache-bust via CACHE_BUST
                          build-arg). Use after editing the Dockerfile or to
                          pull a new Claude Code version.
  --fresh-creds           Force re-inject credentials from the macOS keychain,
                          even if unexpired credentials exist in the container.
                          Useful after running 'claude login' on the host.
  --isolate-claude-data   Use a named Docker volume ('claude-data') instead of
                          the default read-only host mount + writable tmpfs.
                          Required for Docker Desktop (see below).
  --no-sync-back          Disable sync-back of session data to host on exit.
                          By default, session artifacts (transcripts, memory,
                          plans, etc.) are synced back when the container
                          exits cleanly. settings.json and user-level CLAUDE.md
                          are NEVER synced back regardless of this flag.
  --with-gvisor           Use gVisor (runsc) runtime if available. By default
                          the standard runc runtime is used, which is best for
                          OrbStack. Note: the iptables firewall does not work
                          with gVisor's virtualized network stack.
  --allow-git-push        Enable git push from inside the container (blocked
                          by default for security). Consider using a fine-grained
                          GitHub PAT scoped to the target repo.
  --disallow-broad-gh-token
                          Reject broad-scope GitHub tokens (ghp_*/gho_*). Only
                          fine-grained PATs (github_pat_*) are accepted. The AI
                          agent can extract tokens from the credential cache
                          (same-UID limitation) — narrow-scope tokens limit
                          blast radius.
  --reload-firewall       Reload the firewall allowlist in all running
                          claude-sandbox containers. Edit firewall-allowlist.conf
                          then run this to apply changes without restarting.

Security layers:
  Read-only rootfs, custom seccomp allowlist (ptrace blocked), all capabilities
  dropped (except CHOWN/SETUID/SETGID/SETPCAP/NET_ADMIN/NET_RAW — bounding set
  cleared after init), iptables firewall (allowlist-only, DNS rate-limited),
  no-new-privileges, resource limits (memory/pids), no setuid binaries, privileged
  port binding blocked, --init (tini as PID 1, root-owned /proc/1/mem),
  nodump.so + git-guard.so via /etc/ld.so.preload (kernel-enforced, read-only
  rootfs), core dumps disabled (ulimit -c 0), git-guard.so via /etc/ld.so.preload
  (binary-level enforcement), hooksPath=/dev/null and credential.helper forced
  on every git invocation, GitHub token scoped to workspace repo (extractable
  by AI — use fine-grained PATs), privilege drop to UID 501 via setpriv,
  ~/.claude mount isolation (read-only host mount + writable tmpfs, settings.json
  and user-level CLAUDE.md never synced back to host), post-exit workspace audit.

Runtime compatibility:
  OrbStack (recommended):
    ./run-claude.sh ~/Projects/my-project
    Mounts host ~/.claude/ read-only with writable tmpfs overlay. Session
    data syncs back on clean exit. Firewall and all hardening layers work
    out of the box.

  Docker Desktop:
    ./run-claude.sh --isolate-claude-data ~/Projects/my-project
    Requires --isolate-claude-data because Docker Desktop's file sharing
    has permission issues with bind-mounts. Uses a named Docker volume
    instead. To reset state: docker volume rm claude-data

Argument routing:
  Script options (--rebuild, --fresh-creds, etc.) are consumed by the script.
  Everything else is passed through to Claude Code. The first argument that
  is an existing directory becomes PROJECT_DIR. All remaining arguments go
  to claude as CLAUDE_ARGS.

  Script flags:  --rebuild, --fresh-creds, --isolate-claude-data, --no-sync-back,
                 --with-gvisor, --reload-firewall, --allow-git-push,
                 --disallow-broad-gh-token
  Claude flags:  --continue, --resume, -p, --allowedTools, --model, etc.

Examples:
  ./run-claude.sh ~/Projects/my-project        Run on a specific project
  ./run-claude.sh                              Run on the current directory
  ./run-claude.sh --rebuild ~/Projects/x       Rebuild image, then run
  ./run-claude.sh --fresh-creds ~/Projects/x   Force-refresh credentials
  ./run-claude.sh ../my-project --continue     Continue last conversation
  ./run-claude.sh --continue                   Continue (current directory)
  ./run-claude.sh ../foo -p "fix the tests"    Run a one-shot prompt
  ./run-claude.sh ../foo --allow-dangerously-skip-permissions  Bypass permissions
  ./run-claude.sh --reload-firewall            Reload firewall in all containers
EOF
    exit 0
}

# Parse flags
REBUILD=false
FRESH_CREDS=false
ISOLATE_DATA=false
SYNC_BACK=true
WITH_GVISOR=false
RELOAD_FIREWALL=false
ALLOW_GIT_PUSH=false
DISALLOW_BROAD_TOKEN=false
ARGS=()
for arg in "$@"; do
    case "$arg" in
        -h|--help) usage ;;
        --rebuild) REBUILD=true ;;
        --fresh-creds) FRESH_CREDS=true ;;
        --isolate-claude-data) ISOLATE_DATA=true ;;
        --no-sync-back) SYNC_BACK=false ;;
        --with-gvisor) WITH_GVISOR=true ;;
        --reload-firewall) RELOAD_FIREWALL=true ;;
        --allow-git-push) ALLOW_GIT_PUSH=true ;;
        --disallow-broad-gh-token) DISALLOW_BROAD_TOKEN=true ;;
        *) ARGS+=("$arg") ;;
    esac
done

# Handle --reload-firewall: exec into all running containers and exit
if [ "$RELOAD_FIREWALL" = true ]; then
    CONTAINERS=$(docker ps -q -f ancestor=claude-sandbox)
    if [ -z "$CONTAINERS" ]; then
        echo "[sandbox] No running claude-sandbox containers found"
        exit 1
    fi
    FAIL=0
    for cid in $CONTAINERS; do
        SHORT="${cid:0:12}"
        echo "[sandbox] Reloading firewall in container $SHORT..."
        if docker exec "$cid" /usr/local/bin/reload-firewall.sh; then
            echo "[sandbox] Container $SHORT: OK"
        else
            echo "[sandbox] Container $SHORT: FAILED"
            FAIL=$((FAIL + 1))
        fi
    done
    if [ "$FAIL" -gt 0 ]; then
        echo "[sandbox] $FAIL container(s) failed to reload"
        exit 1
    fi
    echo "[sandbox] All containers reloaded successfully"
    exit 0
fi

# First positional arg that is a directory becomes PROJECT_DIR; rest go to claude
PROJECT_DIR="."
CLAUDE_ARGS=()
DIR_FOUND=false
for arg in "${ARGS[@]}"; do
    if [ "$DIR_FOUND" = false ] && [ -d "$arg" ]; then
        PROJECT_DIR="$arg"
        DIR_FOUND=true
    else
        CLAUDE_ARGS+=("$arg")
    fi
done
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"
IMAGE_NAME="claude-sandbox"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Extract credentials from macOS keychain
CREDS=$(security find-generic-password -s "Claude Code-credentials" -w 2>/dev/null || true)
if [ -z "$CREDS" ]; then
    echo "Error: No Claude Code credentials found in keychain."
    echo "Run 'claude login' on your Mac first."
    exit 1
fi

# Auto-refresh expired keychain credentials by running native claude on the host.
# The container can't update the macOS keychain, so only a host-side refresh works.
EXPIRES_AT=$(python3 -c "
import json, sys
creds = json.loads(sys.stdin.read())
print(creds.get('claudeAiOauth', {}).get('expiresAt', 0))
" <<< "$CREDS" 2>/dev/null || echo 0)
NOW_MS=$(( $(date +%s) * 1000 ))
BUFFER_MS=300000  # 5 minutes

if [ "$EXPIRES_AT" -gt 0 ] && [ "$EXPIRES_AT" -le $((NOW_MS + BUFFER_MS)) ]; then
    log "[sandbox] Keychain access token expired, refreshing via host claude..."
    if timeout 30 claude -p "." --max-turns 1 > /dev/null 2>&1; then
        # Re-extract refreshed credentials
        CREDS=$(security find-generic-password -s "Claude Code-credentials" -w 2>/dev/null || true)
        if [ -z "$CREDS" ]; then
            echo "Error: Keychain credentials lost during refresh."
            exit 1
        fi
        log "[sandbox] Credentials refreshed successfully"
    else
        log "[sandbox] Warning: Auto-refresh failed. If you get auth errors, run: claude login"
    fi
fi

# Extract GitHub token from host (for git push inside container)
GH_TOKEN=$(gh auth token 2>/dev/null || true)
if [ -n "$GH_TOKEN" ]; then
    case "$GH_TOKEN" in
        github_pat_*) log "[sandbox] Fine-grained GitHub token (good)" ;;
        gho_*|ghp_*)
            if [ "$DISALLOW_BROAD_TOKEN" = true ]; then
                log "[sandbox] Broad-scope GitHub token rejected (--disallow-broad-gh-token)."
                log "[sandbox] Create a fine-grained PAT: https://github.com/settings/personal-access-tokens/new"
                GH_TOKEN=""
            else
                log "[sandbox] WARNING: Broad-scope GitHub token detected."
                log "[sandbox] The AI agent can extract this token (same-UID limitation)."
                log "[sandbox] Create a fine-grained PAT scoped to this repo: https://github.com/settings/personal-access-tokens/new"
                log "[sandbox] Use --disallow-broad-gh-token to reject broad tokens."
            fi ;;
        *) log "[sandbox] GitHub token found" ;;
    esac
fi

LATEST_URL="https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases/latest"

# Build image if needed (or forced with --rebuild)
if [ "$REBUILD" = true ]; then
    log "[sandbox] Linting Dockerfile..."
    "$SCRIPT_DIR/lint.sh"

    # Check if Claude Code version is outdated (determines whether to bust npm cache)
    LATEST_VERSION=$(curl -fsSL "$LATEST_URL" 2>/dev/null || echo "unknown")
    INSTALLED_VERSION=$(docker run --rm --entrypoint claude "$IMAGE_NAME" --version 2>/dev/null | awk '{print $1}' || echo "none")

    # Persist CACHE_BUST so scripts-only rebuilds reuse the same value.
    # Docker treats "ARG not passed" and "ARG=empty" as different cache keys,
    # so we must replay the exact same --build-arg invocation as the last build.
    CACHE_FILE="$SCRIPT_DIR/.last-cache-bust"
    CACHE_BUST_FLAG=""
    if [ "$LATEST_VERSION" = "unknown" ] || [ "$LATEST_VERSION" != "$INSTALLED_VERSION" ]; then
        log "[sandbox] Rebuilding sandbox image (installed: ${INSTALLED_VERSION}, latest: ${LATEST_VERSION})..."
        CACHE_VAL=$(date +%s)
        echo "$CACHE_VAL" > "$CACHE_FILE"
        CACHE_BUST_FLAG="--build-arg CACHE_BUST=$CACHE_VAL"
    else
        log "[sandbox] Claude Code $INSTALLED_VERSION is current, rebuilding scripts only..."
        if [ -f "$CACHE_FILE" ]; then
            CACHE_BUST_FLAG="--build-arg CACHE_BUST=$(cat "$CACHE_FILE")"
        fi
    fi

    # Always rebuild — Docker layer cache handles unchanged layers efficiently.
    # CACHE_BUST only changes when Claude Code version is outdated.
    # shellcheck disable=SC2086
    docker build \
        --build-arg USER_ID=$(id -u) \
        --build-arg GROUP_ID=$(id -g) \
        $CACHE_BUST_FLAG \
        -t "$IMAGE_NAME" \
        "$SCRIPT_DIR"
elif ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    log "[sandbox] Building sandbox image..."
    docker build \
        --build-arg USER_ID=$(id -u) \
        --build-arg GROUP_ID=$(id -g) \
        -t "$IMAGE_NAME" \
        "$SCRIPT_DIR"
fi

# Detect runtime: use runc by default, gVisor only with --with-gvisor
RUNTIME_FLAG=""
if [ "$WITH_GVISOR" = true ]; then
    if docker info 2>/dev/null | grep -q runsc; then
        RUNTIME_FLAG="--runtime=runsc"
        log "[sandbox] Using gVisor runtime (note: firewall inactive with gVisor)"
    else
        log "[sandbox] Warning: --with-gvisor requested but runsc not available, using runc"
    fi
fi

# Pass credentials via --env-file to avoid exposure in 'ps aux' output (M1 fix).
# The entrypoint writes them to ~/.claude/.credentials.json and unsets the var
# before exec'ing Claude Code, so the credentials are not visible to child processes.
ENVFILE=$(mktemp)
chmod 600 "$ENVFILE"
printf 'CLAUDE_CREDENTIALS=%s\n' "$CREDS" >> "$ENVFILE"
if [ "$FRESH_CREDS" = true ]; then
    echo "FORCE_CREDENTIALS=1" >> "$ENVFILE"
fi
if [ -n "$GH_TOKEN" ]; then
    printf 'GITHUB_TOKEN=%s\n' "$GH_TOKEN" >> "$ENVFILE"
fi
if [ "$ALLOW_GIT_PUSH" = true ]; then
    echo "ALLOW_GIT_PUSH=1" >> "$ENVFILE"
    log "[sandbox] Git push enabled (--allow-git-push)"
fi

# Determine Claude data mount strategy
CLAUDE_MOUNT_FLAGS=""
SYNC_BACK_FLAGS=""
if [ "$ISOLATE_DATA" = true ]; then
    CLAUDE_MOUNT_FLAGS="-v claude-data:/home/claude/.claude"
    SYNC_BACK=false
    log "[sandbox] Using isolated data volume"
else
    # Ensure host ~/.claude directory exists with initial config
    mkdir -p "$HOME/.claude"
    if [ ! -f "$HOME/.claude/.config.json" ]; then
        echo '{"hasCompletedOnboarding":true,"bypassPermissionsModeAccepted":true}' > "$HOME/.claude/.config.json"
        log "[sandbox] Created initial config"
    fi

    # Read-only host mount at alternate path + writable tmpfs at real path
    CLAUDE_MOUNT_FLAGS="-v $HOME/.claude:/mnt/.claude-host:ro --tmpfs /home/claude/.claude:rw,nosuid,size=512m"
    log "[sandbox] Mounting ~/.claude read-only (writes go to tmpfs)"

    # Set up sync-back staging directory
    if [ "$SYNC_BACK" = true ]; then
        SYNC_DIR="$HOME/.claude/.sync-back"
        mkdir -p "$SYNC_DIR"
        SYNC_BACK_FLAGS="-v $SYNC_DIR:/home/claude/.claude-sync:rw -e SYNC_BACK=1"
        log "[sandbox] Sync-back enabled (use --no-sync-back to disable)"
    fi
fi

# Snapshot .git/config and hooks listing for post-exit tamper detection
GIT_CONFIG_BACKUP=$(mktemp)
cp "$PROJECT_DIR/.git/config" "$GIT_CONFIG_BACKUP" 2>/dev/null || true
# Note: macOS uses 'shasum -a 256'; the container uses 'sha256sum' (GNU).
# Both produce identical 64-char hex digests — cross-boundary comparison works.
# Pre-session hash used as fallback if entrypoint hash isn't available
GIT_CONFIG_HASH_PRE=$(shasum -a 256 "$PROJECT_DIR/.git/config" 2>/dev/null | cut -d' ' -f1)
# The entrypoint sanitizes .git/config (strips dangerous keys) which changes
# the hash. It writes the post-sanitization hash to GIT_CONFIG_HASH_FILE so
# we compare against the clean baseline, not the pre-sanitization state.
GIT_CONFIG_HASH_FILE=$(mktemp)
HOOKS_LISTING=$(ls -la "$PROJECT_DIR/.git/hooks/" 2>/dev/null || true)

ENTRYPOINT_LOG=$(mktemp)

# L1 fix: clean up all tempfiles on signal/early-exit
_cleanup_temps() { rm -f "$GIT_CONFIG_BACKUP" "$GIT_CONFIG_HASH_FILE" "$ENTRYPOINT_LOG" "$ENVFILE" 2>/dev/null; }
trap _cleanup_temps EXIT

# Delete env file shortly after docker reads it (minimizes on-disk exposure)
(sleep 2 && rm -f "$ENVFILE") &

set +e
# shellcheck disable=SC2086
docker run --rm -it \
    --init \
    $RUNTIME_FLAG \
    --cap-drop=ALL \
    --cap-add=CHOWN \
    --cap-add=SETUID \
    --cap-add=SETGID \
    --cap-add=SETPCAP \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --security-opt=no-new-privileges \
    --security-opt seccomp="$SCRIPT_DIR/seccomp-profile.json" \
    --sysctl net.ipv4.ip_unprivileged_port_start=1024 \
    --pids-limit=4096 \
    --memory=8g \
    --memory-swap=8g \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=512m \
    --tmpfs /home/claude/.config:rw,nosuid,size=64m \
    --tmpfs /home/claude/.npm:rw,noexec,nosuid,size=256m \
    --env-file "$ENVFILE" \
    --shm-size=64m \
    -v "$PROJECT_DIR":/workspace \
    -v "$HOME/.gitconfig":/tmp/host-gitconfig:ro \
    -v "$SCRIPT_DIR/firewall-allowlist.conf":/etc/firewall-allowlist.conf:ro \
    $CLAUDE_MOUNT_FLAGS \
    $SYNC_BACK_FLAGS \
    -v "$ENTRYPOINT_LOG":/run/entrypoint.log \
    -v "$GIT_CONFIG_HASH_FILE":/run/git-config-hash \
    -e ENTRYPOINT_LOG=/run/entrypoint.log \
    "$IMAGE_NAME" \
    claude "${CLAUDE_ARGS[@]}"
DOCKER_EXIT=$?
set -e

if [ -f "$ENTRYPOINT_LOG" ] && [ -s "$ENTRYPOINT_LOG" ]; then
    # Strip ANSI escape sequences to prevent terminal injection from container output.
    # Removes CSI sequences (ESC[...X), OSC sequences (ESC]...BEL), and bare escapes.
    LAUNCH_LOG+="$(LC_ALL=C sed 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\x1b\][^\x07]*\x07//g; s/\x1b[^[]\{0,2\}//g' "$ENTRYPOINT_LOG")"$'\n'
fi
rm -f "$ENTRYPOINT_LOG" 2>/dev/null || true

# Sync-back: merge staged data into host ~/.claude/
if [ "$SYNC_BACK" = true ] && [ -d "$HOME/.claude/.sync-back/data" ]; then
    # Audit staged data before syncing to host
    if [ -d "$HOME/.claude/.sync-back/data/projects" ]; then
        CLAUDE_MD_COUNT=$(find "$HOME/.claude/.sync-back/data/projects" -name "CLAUDE.md" 2>/dev/null | wc -l)
        MEMORY_COUNT=$(find "$HOME/.claude/.sync-back/data/projects" -path "*/memory/*" -type f 2>/dev/null | wc -l)
        [ "$CLAUDE_MD_COUNT" -gt 0 ] && echo "[sandbox] INFO: $CLAUDE_MD_COUNT project CLAUDE.md file(s) created during session (excluded from sync-back)."
        [ "$MEMORY_COUNT" -gt 0 ] && echo "[sandbox] INFO: $MEMORY_COUNT memory file(s) will be synced back."
    fi

    echo "[sandbox] Syncing session data back to host..."
    rsync -a --no-links \
        --exclude='settings.json' \
        --exclude='settings.local.json' \
        --exclude='CLAUDE.md' \
        "$HOME/.claude/.sync-back/data/" "$HOME/.claude/"
    echo "[sandbox] Sync complete"
fi
# Clean up sync staging directory
rm -rf "$HOME/.claude/.sync-back" 2>/dev/null || true

# Post-exit workspace audit: warn if the session planted files that could execute
# code on the host outside the sandbox (persistence via workspace write-back).

# 1. Hash-based .git/config tamper detection with auto-restore
# The entrypoint sanitizes .git/config (strips dangerous keys) then writes the
# post-sanitization hash to GIT_CONFIG_HASH_FILE. We compare against that baseline
# so the sanitization itself doesn't trigger a false positive.
ENTRYPOINT_HASH=""
if [ -f "$GIT_CONFIG_HASH_FILE" ] && [ -s "$GIT_CONFIG_HASH_FILE" ]; then
    ENTRYPOINT_HASH=$(cat "$GIT_CONFIG_HASH_FILE")
fi
rm -f "$GIT_CONFIG_HASH_FILE" 2>/dev/null || true
POST_GIT_CONFIG_HASH=$(shasum -a 256 "$PROJECT_DIR/.git/config" 2>/dev/null | cut -d' ' -f1)
if [ -n "$ENTRYPOINT_HASH" ]; then
    # Entrypoint sanitization ran. Compare current hash to post-sanitization baseline.
    # Both sha256sum (GNU) and shasum -a 256 (macOS) produce identical 64-char hex.
    if [ "$ENTRYPOINT_HASH" != "$POST_GIT_CONFIG_HASH" ]; then
        echo ""
        echo "[sandbox] WARNING: .git/config was modified during the session!"
        echo "[sandbox] Auto-restoring from pre-session backup and re-sanitizing..."
        cp "$GIT_CONFIG_BACKUP" "$PROJECT_DIR/.git/config"
        # Re-apply the same sanitization the entrypoint performed, so we don't
        # restore dangerous keys that were in the original config.
        for _key in core.fsmonitor core.sshCommand include.path; do
            git config -f "$PROJECT_DIR/.git/config" --unset-all "$_key" 2>/dev/null || true
        done
        git config -f "$PROJECT_DIR/.git/config" --remove-section alias 2>/dev/null || true
        git config -f "$PROJECT_DIR/.git/config" --remove-section include 2>/dev/null || true
        # Remove all [includeIf "..."] sections (--remove-section can't match these;
        # see entrypoint.sh comment for details)
        if grep -q '^\[includeIf ' "$PROJECT_DIR/.git/config" 2>/dev/null; then
            _tmp="$PROJECT_DIR/.git/.includeif-strip.tmp"
            awk '/^\[includeIf /{ skip=1; next } /^\[/{ skip=0 } !skip{ print }' \
                "$PROJECT_DIR/.git/config" > "$_tmp" && mv "$_tmp" "$PROJECT_DIR/.git/config"
            rm -f "$_tmp"
        fi
        echo "[sandbox] .git/config restored. Review with: git config --local --list"
    fi
elif [ -n "$GIT_CONFIG_HASH_PRE" ] && [ "$GIT_CONFIG_HASH_PRE" != "$POST_GIT_CONFIG_HASH" ]; then
    # No entrypoint hash (not a git repo that was sanitized). Fall back to pre-session comparison.
    echo ""
    echo "[sandbox] WARNING: .git/config was modified during the session!"
    echo "[sandbox] Auto-restoring .git/config from pre-session backup..."
    cp "$GIT_CONFIG_BACKUP" "$PROJECT_DIR/.git/config"
    echo "[sandbox] .git/config restored. Review with: git config --local --list"
fi
rm -f "$GIT_CONFIG_BACKUP" 2>/dev/null || true

# 2. Detect new hooks (non-.sample files added to .git/hooks/)
POST_HOOKS_LISTING=$(ls -la "$PROJECT_DIR/.git/hooks/" 2>/dev/null || true)
if [ "$HOOKS_LISTING" != "$POST_HOOKS_LISTING" ]; then
    NEW_HOOKS=""
    for hook in "$PROJECT_DIR/.git/hooks/"*; do
        [ -f "$hook" ] || continue
        case "$hook" in *.sample) continue ;; esac
        NEW_HOOKS+="  - $hook"$'\n'
    done
    if [ -n "$NEW_HOOKS" ]; then
        echo ""
        echo "[sandbox] WARNING: New git hooks detected — these execute automatically on git operations:"
        printf '%s' "$NEW_HOOKS"
    fi
fi

# 3. Scan .git/config for dangerous keys as final check
if [ -f "$PROJECT_DIR/.git/config" ]; then
    GIT_CONFIG_WARNINGS=""
    for key in core.fsmonitor core.sshCommand core.hooksPath include.path; do
        if git config -f "$PROJECT_DIR/.git/config" --get-all "$key" >/dev/null 2>&1; then
            GIT_CONFIG_WARNINGS+="  - $key"$'\n'
        fi
    done
    # Check for alias and includeIf sections
    for section in alias includeIf; do
        if git config -f "$PROJECT_DIR/.git/config" --get-regexp "^${section}\." >/dev/null 2>&1; then
            GIT_CONFIG_WARNINGS+="  - ${section}.* section"$'\n'
        fi
    done
    if [ -n "$GIT_CONFIG_WARNINGS" ]; then
        echo ""
        echo "[sandbox] WARNING: Dangerous keys found in .git/config:"
        printf '%s' "$GIT_CONFIG_WARNINGS"
        echo "[sandbox] Review with: git config --local --list"
    fi
fi

# 4. Suspect file existence warnings
AUDIT_WARNINGS=""
for suspect in \
    "$PROJECT_DIR/.envrc" \
    "$PROJECT_DIR/.vscode/settings.json" \
    "$PROJECT_DIR/.vscode/tasks.json" \
    "$PROJECT_DIR/Makefile" \
    "$PROJECT_DIR/.gitattributes" \
    "$PROJECT_DIR/.github/workflows"; do
    if [ -e "$suspect" ]; then
        AUDIT_WARNINGS+="  - $suspect"$'\n'
    fi
done
if [ -n "$AUDIT_WARNINGS" ]; then
    echo ""
    echo "[sandbox] WARNING: The following workspace files can execute code outside the sandbox."
    echo "[sandbox] Review these for unexpected changes before running build/IDE tools:"
    printf '%s' "$AUDIT_WARNINGS"
    echo "[sandbox] Use 'git diff' to inspect changes made during this session."
fi

if [ -n "$LAUNCH_LOG" ]; then
    echo ""
    echo "[sandbox] Launch log:"
    printf '%s' "$LAUNCH_LOG"
fi

exit $DOCKER_EXIT
