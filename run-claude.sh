#!/bin/bash
# run-claude.sh - Launch Claude Code in a sandboxed Docker container
set -e

usage() {
    cat <<'EOF'
Usage: run-claude.sh [OPTIONS] [PROJECT_DIR]

Launch Claude Code in a hardened Docker container. Credentials are extracted
from the macOS keychain automatically. If PROJECT_DIR is omitted, the current
directory is used.

Options:
  -h, --help              Show this help message and exit
  --rebuild               Rebuild the Docker image from scratch (runs lint
                          first, uses --no-cache). Use after editing the
                          Dockerfile or to pull a new Claude Code version.
  --fresh-creds           Force re-inject credentials from the macOS keychain,
                          even if unexpired credentials exist in the container.
                          Useful after running 'claude login' on the host.
  --isolate-claude-data   Use a named Docker volume ('claude-data') instead of
                          bind-mounting the host's ~/.claude/ directory.
                          Required for Docker Desktop (see below).
  --no-gvisor             Skip gVisor runtime even if available. All other
                          hardening layers (seccomp, read-only rootfs,
                          capabilities drop, firewall) remain active.

Security layers:
  Read-only rootfs, custom seccomp allowlist, all capabilities dropped
  (except CHOWN/SETUID/SETGID/NET_ADMIN/NET_RAW), iptables firewall
  (allowlist-only), no-new-privileges, and privilege drop to UID 501 via gosu.

Runtime compatibility:
  OrbStack (recommended):
    ./run-claude.sh ~/Projects/my-project
    Bind-mounts ~/.claude/ for shared state with the host. Firewall and all
    hardening layers work out of the box.

  Docker Desktop:
    ./run-claude.sh --isolate-claude-data ~/Projects/my-project
    Requires --isolate-claude-data because Docker Desktop's file sharing
    has permission issues with bind-mounted ~/.claude/. Uses a named Docker
    volume instead. To reset state: docker volume rm claude-data

Examples:
  ./run-claude.sh ~/Projects/my-project        Run on a specific project
  ./run-claude.sh                              Run on the current directory
  ./run-claude.sh --rebuild                    Rebuild image, then run
  ./run-claude.sh --fresh-creds ~/Projects/x   Force-refresh credentials
EOF
    exit 0
}

# Parse flags
REBUILD=false
FRESH_CREDS=false
ISOLATE_DATA=false
NO_GVISOR=false
ARGS=()
for arg in "$@"; do
    case "$arg" in
        -h|--help) usage ;;
        --rebuild) REBUILD=true ;;
        --fresh-creds) FRESH_CREDS=true ;;
        --isolate-claude-data) ISOLATE_DATA=true ;;
        --no-gvisor) NO_GVISOR=true ;;
        *) ARGS+=("$arg") ;;
    esac
done

PROJECT_DIR="${ARGS[0]:-.}"
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

# Build image if needed (or forced with --rebuild)
if [ "$REBUILD" = true ]; then
    echo "Linting Dockerfile..."
    "$SCRIPT_DIR/lint.sh"
    echo "Rebuilding sandbox image..."
    docker build --no-cache \
        --build-arg USER_ID=$(id -u) \
        --build-arg GROUP_ID=$(id -g) \
        -t "$IMAGE_NAME" \
        "$SCRIPT_DIR"
elif ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    echo "Building sandbox image..."
    docker build \
        --build-arg USER_ID=$(id -u) \
        --build-arg GROUP_ID=$(id -g) \
        -t "$IMAGE_NAME" \
        "$SCRIPT_DIR"
fi

# Detect runtime: prefer gVisor (runsc) if available
RUNTIME_FLAG=""
if [ "$NO_GVISOR" = true ]; then
    echo "[sandbox] gVisor disabled via --no-gvisor"
elif docker info 2>/dev/null | grep -q runsc; then
    RUNTIME_FLAG="--runtime=runsc"
    echo "[sandbox] Using gVisor runtime"
else
    echo "[sandbox] gVisor not available, using default runtime"
fi

# Run container with credentials passed via environment variable.
# The entrypoint writes them to ~/.claude/.credentials.json and unsets the var
# before exec'ing Claude Code, so the credentials are not visible to child processes.
FORCE_CREDS_FLAG=""
if [ "$FRESH_CREDS" = true ]; then
    FORCE_CREDS_FLAG="-e FORCE_CREDENTIALS=1"
fi

# Determine Claude data mount: bind-mount host ~/.claude by default, or use named volume with --isolate-claude-data
if [ "$ISOLATE_DATA" = true ]; then
    CLAUDE_DATA_MOUNT="claude-data:/home/claude/.claude"
    echo "[sandbox] Using isolated data volume"
else
    # Ensure host ~/.claude directory exists with initial config
    mkdir -p "$HOME/.claude"
    if [ ! -f "$HOME/.claude/.config.json" ]; then
        echo '{"hasCompletedOnboarding":true,"bypassPermissionsModeAccepted":true}' > "$HOME/.claude/.config.json"
        echo "[sandbox] Created initial config"
    fi
    CLAUDE_DATA_MOUNT="$HOME/.claude:/home/claude/.claude"
    echo "[sandbox] Sharing ~/.claude with host (use --isolate-claude-data for isolation)"
fi

docker run --rm -it \
    $RUNTIME_FLAG \
    --cap-drop=ALL \
    --cap-add=CHOWN \
    --cap-add=SETUID \
    --cap-add=SETGID \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --security-opt=no-new-privileges \
    --security-opt seccomp="$SCRIPT_DIR/seccomp-profile.json" \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=512m \
    --tmpfs /home/claude/.config:rw,nosuid,size=64m \
    --tmpfs /home/claude/.npm:rw,nosuid,size=256m \
    -e CLAUDE_CREDENTIALS="$CREDS" \
    $FORCE_CREDS_FLAG \
    -v "$PROJECT_DIR":/workspace \
    -v "$HOME/.gitconfig":/tmp/host-gitconfig:ro \
    -v "$CLAUDE_DATA_MOUNT" \
    "$IMAGE_NAME" \
    claude --allow-dangerously-skip-permissions
