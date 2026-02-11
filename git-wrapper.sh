#!/bin/sh
# Git wrapper: forces security-critical config on every git invocation.
# Primary enforcement is git-guard.so via /etc/ld.so.preload (kernel-enforced,
# read-only rootfs). This wrapper only provides GIT_CONFIG_COUNT overrides as
# defense-in-depth for the narrow case of statically-linked callers.

export GIT_CONFIG_COUNT=4
export GIT_CONFIG_KEY_0=core.hooksPath
export GIT_CONFIG_VALUE_0=/dev/null
export GIT_CONFIG_KEY_1=credential.helper
export GIT_CONFIG_VALUE_1="cache --timeout=86400 --socket=/tmp/.git-credential-cache/sock"
export GIT_CONFIG_KEY_2=core.fsmonitor
export GIT_CONFIG_VALUE_2=false
export GIT_CONFIG_KEY_3=core.sshCommand
export GIT_CONFIG_VALUE_3=/bin/false
exec /usr/libexec/wrapped-git "$@"
