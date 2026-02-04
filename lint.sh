#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
docker run --rm -i hadolint/hadolint < "$SCRIPT_DIR/Dockerfile"
