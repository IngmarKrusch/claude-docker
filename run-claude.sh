#!/bin/bash
# run-claude.sh - Launch Claude Code in a sandboxed Docker container
set -e

LAUNCH_LOG=""
log() { echo "$1"; LAUNCH_LOG+="$1"$'\n'; }

# M9 Round 10 fix: Sanitize ANSI escape sequences to prevent terminal injection
# Removes CSI sequences (ESC[...X), OSC sequences (ESC]...BEL), DCS sequences
# (ESC P...ST), 8-bit C1 control codes (0x80-0x9F), and bare escapes.
# R14 fix: BSD sed doesn't support \x hex escapes inside bracket expressions —
# [\x80-\x9f] matches literal chars including A-Z and 0-9. Use tr with octal
# escapes for 8-bit C1 stripping (works on both macOS BSD and GNU).
sanitize_ansi() {
    LC_ALL=C sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\x1b\][^\x07]*\x07//g; s/\x1bP[^\x1b]*\x1b\\//g; s/\x1b[^[]\{0,2\}//g' \
        | LC_ALL=C tr -d '\200-\237'
}

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
                          exits cleanly. settings.json, .config.json, and
                          user-level CLAUDE.md are NEVER synced back
                          regardless of this flag.
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
                          claude-sandbox containers. Edit config/firewall-allowlist.conf
                          then run this to apply changes without restarting.

Security layers:
  Read-only rootfs, custom seccomp allowlist (ptrace blocked), all capabilities
  dropped (except CHOWN/SETUID/SETGID/SETPCAP/NET_ADMIN/NET_RAW — bounding set
  cleared after init), iptables firewall (allowlist-only, DNS blocked for claude
  user with pre-resolved /etc/hosts), no-new-privileges, resource limits
  (memory/pids), no setuid binaries, privileged port binding blocked, --init
  (tini as PID 1, root-owned /proc/1/mem), nodump.so + git-guard.so via
  /etc/ld.so.preload (kernel-enforced, read-only rootfs), core dumps disabled
  (ulimit -c 0), hooksPath=/dev/null and credential.helper forced on every git
  invocation, global gitconfig locked (root:root 444), GitHub token scoped to
  workspace repo (extractable by AI — use fine-grained PATs), privilege drop to
  UID 501 via setpriv, ~/.claude host-side staging (only needed files exposed,
  writable tmpfs, settings.json and user-level CLAUDE.md never synced back to
  host), post-exit workspace audit.

Runtime compatibility:
  OrbStack (recommended):
    ./run-claude.sh ~/Projects/my-project
    Stages only needed ~/.claude/ files into temp dir (read-only mount). Session
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
                 --reload-firewall, --allow-git-push,
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

# M10 Round 10 fix: Validate expiresAt is numeric to prevent crash under set -e
if [[ "$EXPIRES_AT" =~ ^[0-9]+$ ]] && [ "$EXPIRES_AT" -gt 0 ] && [ "$EXPIRES_AT" -le $((NOW_MS + BUFFER_MS)) ]; then
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
# L3 Round 10 fix: Reject error text from gh auth token — valid tokens are
# single words without whitespace; error messages contain spaces/newlines
if [ -n "$GH_TOKEN" ] && [[ "$GH_TOKEN" =~ [[:space:]] ]]; then
    GH_TOKEN=""
fi
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
        --build-arg USER_ID="$(id -u)" \
        --build-arg GROUP_ID="$(id -g)" \
        $CACHE_BUST_FLAG \
        -t "$IMAGE_NAME" \
        "$SCRIPT_DIR"
elif ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    log "[sandbox] Building sandbox image..."
    docker build \
        --build-arg USER_ID="$(id -u)" \
        --build-arg GROUP_ID="$(id -g)" \
        -t "$IMAGE_NAME" \
        "$SCRIPT_DIR"
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
CLAUDE_MOUNT_FLAGS=()
SYNC_BACK_FLAGS=()
if [ "$ISOLATE_DATA" = true ]; then
    CLAUDE_MOUNT_FLAGS=(-v claude-data:/home/claude/.claude)
    SYNC_BACK=false
    log "[sandbox] Using isolated data volume"
else
    # Ensure host ~/.claude directory exists with initial config
    mkdir -p "$HOME/.claude"
    if [ ! -f "$HOME/.claude/.config.json" ]; then
        echo '{"hasCompletedOnboarding":true,"bypassPermissionsModeAccepted":true}' > "$HOME/.claude/.config.json"
        log "[sandbox] Created initial config"
    fi

    # Host-side staging: copy ONLY the files the entrypoint needs into a temp
    # directory and mount that — NOT the entire ~/.claude. This prevents a
    # compromised session from reading cross-project history, debug logs, config
    # backups, and other sensitive data. virtiofs on macOS ignores POSIX permission
    # changes, so chmod 700 on the mount point cannot restrict access.
    CLAUDE_STAGING=$(mktemp -d)

    # Individual files (matches entrypoint.sh lines 24-83)
    # R12-H04 fix: Use cp -L to dereference symlinks — prevents smuggling
    # malicious symlinks from ~/.claude into the container
    for f in .config.json settings.json settings.local.json statusline-command.sh \
             CLAUDE.md history.jsonl stats-cache.json; do
        cp -L "$HOME/.claude/$f" "$CLAUDE_STAGING/" 2>/dev/null || true
    done

    # Current project data only (matches entrypoint.sh lines 42-60)
    _HOST_ENCODED=${PROJECT_DIR//\//-}
    if [ -d "$HOME/.claude/projects/$_HOST_ENCODED" ]; then
        mkdir -p "$CLAUDE_STAGING/projects/$_HOST_ENCODED"
        cp -rL "$HOME/.claude/projects/$_HOST_ENCODED/." \
               "$CLAUDE_STAGING/projects/$_HOST_ENCODED/" 2>/dev/null || true
    fi
    # Also stage the -workspace directory if it exists — older sessions (before
    # M12 Round 10 path fix) wrote transcripts here and they were never relocated.
    # The entrypoint merges both into -workspace/ inside the container.
    if [ -d "$HOME/.claude/projects/-workspace" ] && [ "$_HOST_ENCODED" != "-workspace" ]; then
        mkdir -p "$CLAUDE_STAGING/projects/$_HOST_ENCODED"
        cp -rL "$HOME/.claude/projects/-workspace/." \
               "$CLAUDE_STAGING/projects/$_HOST_ENCODED/" 2>/dev/null || true
    fi

    # Directories (matches entrypoint.sh lines 63-80)
    for d in statsig plugins plans todos; do
        [ -d "$HOME/.claude/$d" ] && cp -rL "$HOME/.claude/$d" "$CLAUDE_STAGING/" 2>/dev/null || true
    done

    # shellcheck disable=SC2054  # commas are tmpfs mount options, not array separators
    CLAUDE_MOUNT_FLAGS=(-v "$CLAUDE_STAGING:/mnt/.claude-host:ro" --tmpfs /home/claude/.claude:rw,nosuid,size=512m)
    log "[sandbox] Staged ~/.claude data (host-side, read-only mount)"

    # Set up sync-back staging directory
    if [ "$SYNC_BACK" = true ]; then
        SYNC_DIR="$HOME/.claude/.sync-back"
        mkdir -p "$SYNC_DIR"
        SYNC_BACK_FLAGS=(-v "$SYNC_DIR:/home/claude/.claude-sync:rw" -e SYNC_BACK=1)
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
# R17-C5: Per-hook SHA-256 baseline for modification detection (interactive review)
PRE_HOOKS_HASHES=""
if [ -d "$PROJECT_DIR/.git/hooks" ]; then
    for _hf in "$PROJECT_DIR/.git/hooks/"*; do
        [ -f "$_hf" ] || continue
        case "$_hf" in *.sample) continue ;; esac
        _hh=$(shasum -a 256 "$_hf" 2>/dev/null | cut -d' ' -f1)
        PRE_HOOKS_HASHES+="$(basename "$_hf")=$_hh"$'\n'
    done
fi

# Snapshot pre-existing dangerous keys in .git/config for modification-based post-exit audit
# (mirrors the suspect-file pattern — avoids false positives on pre-existing keys like remote.origin)
PRE_GIT_CONFIG_KEYS=""
if [ -f "$PROJECT_DIR/.git/config" ]; then
    for key in core.fsmonitor core.sshCommand core.hooksPath core.pager core.editor \
               core.gitProxy core.askPass credential.helper include.path; do
        if git config -f "$PROJECT_DIR/.git/config" --get-all "$key" >/dev/null 2>&1; then
            PRE_GIT_CONFIG_KEYS+="$key"$'\n'
        fi
    done
    for section in alias include includeIf filter url http remote credential diff merge; do
        if git config -f "$PROJECT_DIR/.git/config" --get-regexp "^${section}\." >/dev/null 2>&1; then
            PRE_GIT_CONFIG_KEYS+="${section}.*"$'\n'
        fi
    done
fi

# H7 Round 10 fix: Snapshot suspect files for modification-based post-exit audit
# (avoids false positives on pre-existing files that weren't changed)
SUSPECT_FILES=(CLAUDE.md Justfile Taskfile.yml .envrc .vscode/settings.json .vscode/tasks.json Makefile .gitattributes .gitmodules .github/workflows package.json .npmrc .yarnrc.yml .eslintrc.js .eslintrc.cjs jest.config.js jest.config.ts vitest.config.ts vitest.config.js .prettierrc.js tsconfig.json setup.py setup.cfg pyproject.toml .pre-commit-config.yaml .tool-versions .node-version .nvmrc .python-version docker-compose.yml docker-compose.yaml lefthook.yml .husky CMakeLists.txt .cargo/config.toml)
PRE_SUSPECT=""
for _sf in "${SUSPECT_FILES[@]}"; do
    if [ -e "$PROJECT_DIR/$_sf" ]; then
        if [ -f "$PROJECT_DIR/$_sf" ]; then
            _h=$(shasum -a 256 "$PROJECT_DIR/$_sf" 2>/dev/null | cut -d' ' -f1)
        elif [ -d "$PROJECT_DIR/$_sf" ]; then
            _h="DIR:$(find "$PROJECT_DIR/$_sf" -type f -exec shasum -a 256 {} \; 2>/dev/null | sort | shasum -a 256 | cut -d' ' -f1)"
        else
            _h="other"
        fi
        PRE_SUSPECT+="$_sf=$_h"$'\n'
    fi
done

ENTRYPOINT_LOG=$(mktemp)

# L1 fix: clean up all tempfiles on signal/early-exit
# shellcheck disable=SC2329  # invoked via trap
_cleanup_temps() { rm -f "$GIT_CONFIG_BACKUP" "$GIT_CONFIG_HASH_FILE" "$ENTRYPOINT_LOG" "$ENVFILE" 2>/dev/null; rm -rf "${CLAUDE_STAGING:-}" 2>/dev/null; }
trap _cleanup_temps EXIT

# M4 Round 10 fix: Only mount ~/.gitconfig if it exists
GITCONFIG_MOUNT=()
if [ -f "$HOME/.gitconfig" ]; then
    GITCONFIG_MOUNT=(-v "$HOME/.gitconfig:/tmp/host-gitconfig:ro")
fi

# Pre-resolve allowlisted domains and inject into container /etc/hosts via
# --add-host. Combined with DNS blocking in init-firewall.sh, this completely
# eliminates DNS tunneling exfiltration (~25 B/s was possible with rate-limiting).
# The ipset (populated inside the container by root) still controls IP-level
# filtering; these entries only provide hostname resolution.
ADD_HOST_FLAGS=()
ALLOWLIST_CONF="$SCRIPT_DIR/config/firewall-allowlist.conf"
if [ -f "$ALLOWLIST_CONF" ]; then
    while IFS= read -r _fw_line; do
        _fw_line=$(echo "$_fw_line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$_fw_line" || "$_fw_line" == \#* ]] && continue
        if [ "$_fw_line" = "@github" ]; then
            # Resolve the specific GitHub hosts that git/gh CLI connect to
            for _gh_host in github.com api.github.com; do
                for _ip in $(dig +short A "$_gh_host" 2>/dev/null | grep -E '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'); do
                    ADD_HOST_FLAGS+=("--add-host=${_gh_host}:${_ip}")
                done
            done
        else
            for _ip in $(dig +short A "$_fw_line" 2>/dev/null | grep -E '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'); do
                ADD_HOST_FLAGS+=("--add-host=${_fw_line}:${_ip}")
            done
        fi
    done < "$ALLOWLIST_CONF"
fi

# Delete env file shortly after docker reads it (minimizes on-disk exposure)
(sleep 2 && rm -f "$ENVFILE") &

set +e
docker run --rm -it \
    --init \
    --cap-drop=ALL \
    --cap-add=CHOWN \
    --cap-add=SETUID \
    --cap-add=SETGID \
    --cap-add=SETPCAP \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --security-opt=no-new-privileges \
    --security-opt seccomp="$SCRIPT_DIR/config/seccomp-profile.json" \
    --sysctl net.ipv4.ip_unprivileged_port_start=1024 \
    --sysctl net.ipv6.conf.all.disable_ipv6=1 \
    --sysctl net.ipv6.conf.default.disable_ipv6=1 \
    --pids-limit=4096 \
    --memory=8g \
    --memory-swap=8g \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=512m \
    --tmpfs /home/claude/.config:rw,nosuid,size=64m \
    --tmpfs /home/claude/.npm:rw,noexec,nosuid,size=256m \
    --tmpfs /run:rw,nosuid,noexec,size=1m \
    --env-file "$ENVFILE" \
    --shm-size=64m \
    -v "$PROJECT_DIR":/workspace \
    "${GITCONFIG_MOUNT[@]}" \
    -v "$SCRIPT_DIR/config/firewall-allowlist.conf":/etc/firewall-allowlist.conf:ro \
    "${CLAUDE_MOUNT_FLAGS[@]}" \
    "${SYNC_BACK_FLAGS[@]}" \
    -v "$ENTRYPOINT_LOG":/run/entrypoint.log \
    -v "$GIT_CONFIG_HASH_FILE":/run/git-config-hash \
    -e ENTRYPOINT_LOG=/run/entrypoint.log \
    -e PROJECT_PATH="$PROJECT_DIR" \
    -e "TERM=${TERM:-xterm-256color}" \
    -e "TERM_PROGRAM=${TERM_PROGRAM:-}" \
    -e "COLORTERM=${COLORTERM:-}" \
    "${ADD_HOST_FLAGS[@]}" \
    "$IMAGE_NAME" \
    claude "${CLAUDE_ARGS[@]}"
DOCKER_EXIT=$?
set -e

if [ -f "$ENTRYPOINT_LOG" ] && [ -s "$ENTRYPOINT_LOG" ]; then
    # M9 Round 10 fix: Use centralized ANSI sanitization function
    LAUNCH_LOG+="$(sanitize_ansi < "$ENTRYPOINT_LOG")"$'\n'
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
    # H6 Round 10 fix: Align exclusions with entrypoint-side rsync
    rsync -a --no-links \
        --exclude='settings.json' \
        --exclude='settings.local.json' \
        --exclude='statusline-command.sh' \
        --exclude='CLAUDE.md' \
        --exclude='.credentials.json' \
        --exclude='.config.json' \
        --exclude='.config.json.backup.*' \
        --exclude='.gitconfig' \
        --exclude='entrypoint.log' \
        --exclude='.history-baseline-lines' \
        --exclude='history.jsonl' \
        "$HOME/.claude/.sync-back/data/" "$HOME/.claude/"
    echo "[sandbox] Sync complete"

    # R15 fix: Append-only history sync — cat new entries, extract session ID
    # from the append file directly (not from host history.jsonl which the
    # concurrent host-native session may overwrite between append and read).
    HISTORY_APPEND="$HOME/.claude/.sync-back/history-append.jsonl"
    CONTAINER_SESSION_ID=""
    if [ -f "$HISTORY_APPEND" ] && [ -s "$HISTORY_APPEND" ]; then
        APPEND_COUNT=$(wc -l < "$HISTORY_APPEND")
        cat "$HISTORY_APPEND" >> "$HOME/.claude/history.jsonl"
        echo "[sandbox] Appended $APPEND_COUNT history entries"
        CONTAINER_SESSION_ID=$(python3 -c "
import json, sys
project = sys.argv[1]
last = ''
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('project') == project:
            last = d.get('sessionId', '')
    except:
        pass
print(last)
" "$PROJECT_DIR" < "$HISTORY_APPEND" 2>/dev/null || true)
    fi
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
        # R12-H02 fix: Atomic restore — write to temp, mv replaces any symlink.
        # Eliminates TOCTOU race between symlink check and copy.
        _restore_tmp=$(mktemp "$PROJECT_DIR/.git/.config.restored.XXXXXX")
        cp "$GIT_CONFIG_BACKUP" "$_restore_tmp"
        mv -f "$_restore_tmp" "$PROJECT_DIR/.git/config"
        # Re-apply the same sanitization the entrypoint performed, so we don't
        # restore dangerous keys that were in the original config.
        # Updated to match entrypoint M1 & H9 fixes
        for _key in core.fsmonitor core.sshCommand core.hooksPath core.pager core.editor \
                    core.gitProxy core.askPass credential.helper include.path; do
            git config -f "$PROJECT_DIR/.git/config" --unset-all "$_key" 2>/dev/null || true
        done
        for _section in alias include filter url http remote credential diff merge; do
            git config -f "$PROJECT_DIR/.git/config" --remove-section "$_section" 2>/dev/null || true
        done
        # Remove all [includeIf "..."] sections (--remove-section can't match these;
        # see entrypoint.sh comment for details)
        if grep -q '^\[includeIf ' "$PROJECT_DIR/.git/config" 2>/dev/null; then
            # R12-H03 fix: Use mktemp instead of predictable temp file path
            _tmp=$(mktemp "$PROJECT_DIR/.git/.includeif-strip.XXXXXX")
            awk '/^\[includeIf /{ skip=1; next } /^\[/{ skip=0 } !skip{ print }' \
                "$PROJECT_DIR/.git/config" > "$_tmp" && mv "$_tmp" "$PROJECT_DIR/.git/config"
            rm -f "$_tmp"  # cleanup on awk failure
        fi
        echo "[sandbox] .git/config restored. Review with: git config --local --list"
    fi
elif [ -n "$GIT_CONFIG_HASH_PRE" ] && [ "$GIT_CONFIG_HASH_PRE" != "$POST_GIT_CONFIG_HASH" ]; then
    # No entrypoint hash (not a git repo that was sanitized). Fall back to pre-session comparison.
    echo ""
    echo "[sandbox] WARNING: .git/config was modified during the session!"
    echo "[sandbox] Auto-restoring .git/config from pre-session backup..."
    # R12-H02 fix: Atomic restore via temp + mv (safe against symlink attacks)
    _restore_tmp=$(mktemp "$PROJECT_DIR/.git/.config.restored.XXXXXX")
    cp "$GIT_CONFIG_BACKUP" "$_restore_tmp"
    mv -f "$_restore_tmp" "$PROJECT_DIR/.git/config"
    echo "[sandbox] .git/config restored. Review with: git config --local --list"
fi
rm -f "$GIT_CONFIG_BACKUP" 2>/dev/null || true

# 2. R17-C5: Interactive review of new/modified hooks (default: deny/delete)
if [ -d "$PROJECT_DIR/.git/hooks" ]; then
    for hook in "$PROJECT_DIR/.git/hooks/"*; do
        [ -f "$hook" ] || continue
        case "$hook" in *.sample) continue ;; esac
        _hook_name=$(basename "$hook")
        _hook_display=$(echo "$_hook_name" | sanitize_ansi)
        _hook_hash=$(shasum -a 256 "$hook" 2>/dev/null | cut -d' ' -f1)
        _pre_hash=$(printf '%s\n' "$PRE_HOOKS_HASHES" | grep -F "${_hook_name}=" | head -1 | cut -d= -f2-)

        # Skip hooks that existed before and haven't changed
        [ -n "$_pre_hash" ] && [ "$_pre_hash" = "$_hook_hash" ] && continue

        # This hook is NEW or MODIFIED — prompt user
        echo ""
        if [ -z "$_pre_hash" ]; then
            echo "[sandbox] WARNING: NEW git hook detected: .git/hooks/$_hook_display"
        else
            echo "[sandbox] WARNING: MODIFIED git hook detected: .git/hooks/$_hook_display"
        fi
        echo "[sandbox] Content preview:"
        # Sanitize content for display (first 15 lines)
        head -15 "$hook" | sanitize_ansi | sed 's/^/  /'
        _total_lines=$(wc -l < "$hook" 2>/dev/null || echo 0)
        [ "$_total_lines" -gt 15 ] && echo "  ... ($_total_lines lines total)"
        echo ""
        printf '[sandbox] Keep this hook? [y/N]: '
        read -r _answer < /dev/tty || _answer=""
        case "$_answer" in
            [yY]|[yY][eE][sS])
                echo "[sandbox] Hook kept: .git/hooks/$_hook_display"
                ;;
            *)
                rm -f "$hook"
                echo "[sandbox] Hook removed: .git/hooks/$_hook_display"
                ;;
        esac
    done
fi

# 3. Scan .git/config for dangerous keys — only warn about NEW keys (not pre-existing)
# H8 & H9 Round 10 fix: Expand scan to cover ALL git-guard blocked keys
if [ -f "$PROJECT_DIR/.git/config" ]; then
    GIT_CONFIG_WARNINGS=""
    # Exact match keys
    for key in core.fsmonitor core.sshCommand core.hooksPath core.pager core.editor \
               core.gitProxy core.askPass credential.helper include.path; do
        # Skip if key existed before the session
        printf '%s' "$PRE_GIT_CONFIG_KEYS" | grep -qxF "$key" && continue
        if git config -f "$PROJECT_DIR/.git/config" --get-all "$key" >/dev/null 2>&1; then
            GIT_CONFIG_WARNINGS+="  - $key"$'\n'
        fi
    done
    # Section/prefix-based keys (H3 Round 10 additions)
    for section in alias include includeIf filter url http remote credential diff merge; do
        # Skip if section existed before the session
        printf '%s' "$PRE_GIT_CONFIG_KEYS" | grep -qxF "${section}.*" && continue
        if git config -f "$PROJECT_DIR/.git/config" --get-regexp "^${section}\." >/dev/null 2>&1; then
            GIT_CONFIG_WARNINGS+="  - ${section}.* section"$'\n'
        fi
    done
    if [ -n "$GIT_CONFIG_WARNINGS" ]; then
        echo ""
        echo "[sandbox] WARNING: Dangerous keys found in .git/config:"
        # M9 Round 10 fix: Sanitize output to prevent ANSI injection
        printf '%s' "$GIT_CONFIG_WARNINGS" | sanitize_ansi
        echo "[sandbox] Review with: git config --local --list"
    fi
fi

# 4. Suspect file modification/creation warnings
# H7 Round 10 fix: Modification-based detection avoids false positives on
# pre-existing files (e.g., Makefile that wasn't changed during the session)
AUDIT_WARNINGS=""
for _sf in "${SUSPECT_FILES[@]}"; do
    _full="$PROJECT_DIR/$_sf"
    if [ -e "$_full" ]; then
        if [ -f "$_full" ]; then
            _post_h=$(shasum -a 256 "$_full" 2>/dev/null | cut -d' ' -f1)
        elif [ -d "$_full" ]; then
            _post_h="DIR:$(find "$_full" -type f -exec shasum -a 256 {} \; 2>/dev/null | sort | shasum -a 256 | cut -d' ' -f1)"
        else
            _post_h="other"
        fi
        _pre_h=$(printf '%s\n' "$PRE_SUSPECT" | grep -F "$_sf=" | head -1 | cut -d= -f2-)
        if [ -z "$_pre_h" ]; then
            AUDIT_WARNINGS+="  - $(echo "$_full" | sanitize_ansi) [CREATED]"$'\n'
        elif [ "$_pre_h" != "$_post_h" ]; then
            AUDIT_WARNINGS+="  - $(echo "$_full" | sanitize_ansi) [MODIFIED]"$'\n'
        fi
    fi
done
if [ -n "$AUDIT_WARNINGS" ]; then
    echo ""
    echo "[sandbox] WARNING: The following workspace files were created or modified during this session."
    echo "[sandbox] These files can execute code outside the sandbox — review before running build/IDE tools:"
    printf '%s' "$AUDIT_WARNINGS"
    echo "[sandbox] Use 'git diff' to inspect changes."
fi

# R15 fix: Use container session ID if available (from staging, race-free),
# otherwise fall back to scanning the host's history.jsonl
if [ -n "${CONTAINER_SESSION_ID:-}" ]; then
    SESSION_ID="$CONTAINER_SESSION_ID"
else
    SESSION_ID=$(python3 -c "
import json, sys
project = sys.argv[1]
last = ''
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('project') == project:
            last = d.get('sessionId', '')
    except:
        pass
print(last)
" "$PROJECT_DIR" < "$HOME/.claude/history.jsonl" 2>/dev/null || true)
fi

if [ -n "$LAUNCH_LOG" ] || [ -n "$SESSION_ID" ]; then
    echo ""
    echo "[sandbox] Launch log:"
    [ -n "$LAUNCH_LOG" ] && printf '%s' "$LAUNCH_LOG"
    if [ -n "$SESSION_ID" ]; then
        echo "[sandbox] Session ID: $SESSION_ID"
    fi
fi

exit $DOCKER_EXIT
