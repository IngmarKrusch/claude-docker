#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Running hadolint on Dockerfile..."
docker run --rm -i hadolint/hadolint < "$SCRIPT_DIR/Dockerfile"

echo "Running shellcheck on shell scripts..."
SHELL_SCRIPTS=(
    run-claude.sh
    lint.sh
    container/entrypoint.sh
    container/init-firewall.sh
    container/reload-firewall.sh
    container/git-wrapper.sh
)
FAIL=0
for script in "${SHELL_SCRIPTS[@]}"; do
    if docker run --rm -v "$SCRIPT_DIR:/mnt:ro" koalaman/shellcheck:stable -x "/mnt/$script"; then
        echo "  $script: OK"
    else
        echo "  $script: ISSUES FOUND"
        FAIL=1
    fi
done
if [ "$FAIL" -ne 0 ]; then
    echo "shellcheck found issues (some may need # shellcheck disable= directives)"
    exit 1
fi
echo "All shell scripts passed shellcheck"
