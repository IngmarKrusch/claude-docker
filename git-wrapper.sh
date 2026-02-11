#!/bin/sh
# Git wrapper: defense-in-depth enforcement layer (primary: git-guard.so via ld.so.preload)
# Blocks dangerous operations and forces security-critical config on every invocation.
# Rootfs is read-only so this wrapper can't be modified at runtime.

# --- Phase 1: Scan -c and --config-env arguments for blocked config keys ---
# git -c has the HIGHEST config precedence — above GIT_CONFIG_COUNT env vars.
# Without this check, "git -c core.fsmonitor='!evil' status" defeats all env overrides.
_skip=0
_check_c=0
for _arg in "$@"; do
  if [ "$_skip" = 1 ]; then _skip=0; continue; fi
  if [ "$_check_c" = 1 ]; then
    _check_c=0
    _ckey="${_arg%%=*}"
    _ckey_lower=$(printf '%s' "$_ckey" | tr '[:upper:]' '[:lower:]')
    case "$_ckey_lower" in
      core.fsmonitor|core.sshcommand|core.pager|core.editor|core.hookspath|\
      credential.helper|include.path|alias.*|filter.*|includeif.*.path|\
      diff.*.textconv|diff.*.command|merge.*.driver)
        printf 'error: git -c with blocked key '\''%s'\'' is disabled in the sandbox\n' "$_ckey" >&2
        exit 1 ;;
    esac
    continue
  fi
  case "$_arg" in
    -c|--config-env) _check_c=1 ;;
    --config-env=*)
      _cval="${_arg#--config-env=}"
      _ckey="${_cval%%=*}"
      _ckey_lower=$(printf '%s' "$_ckey" | tr '[:upper:]' '[:lower:]')
      case "$_ckey_lower" in
        core.fsmonitor|core.sshcommand|core.pager|core.editor|core.hookspath|\
        credential.helper|include.path|alias.*|filter.*|includeif.*.path|\
        diff.*.textconv|diff.*.command|merge.*.driver)
          printf 'error: git --config-env with blocked key '\''%s'\'' is disabled in the sandbox\n' "$_ckey" >&2
          exit 1 ;;
      esac ;;
    -C|--git-dir|--work-tree|--namespace|--super-prefix) _skip=1 ;;
  esac
done

# --- Phase 2: Find real subcommand (skip global flags) ---
_subcmd=""
_skip=0
for _arg in "$@"; do
  if [ "$_skip" = 1 ]; then _skip=0; continue; fi
  case "$_arg" in
    -c|-C|--git-dir|--work-tree|--namespace|--super-prefix|--config-env) _skip=1 ;;
    -*) ;;
    *) _subcmd="$_arg"; break ;;
  esac
done

# --- Phase 3: Block dangerous subcommands ---

# Helper: find the first non-flag argument after a given subcommand keyword
_find_action() {
  _target="$1"
  _found=0
  _fskip=0
  shift
  for _farg in "$@"; do
    if [ "$_fskip" = 1 ]; then _fskip=0; continue; fi
    case "$_farg" in
      -c|-C|--git-dir|--work-tree|--namespace|--super-prefix|--config-env) _fskip=1 ;;
      -*) ;;
      *)
        if [ "$_found" = 1 ]; then echo "$_farg"; return; fi
        if [ "$_farg" = "$_target" ]; then _found=1; fi
        ;;
    esac
  done
}

case "$_subcmd" in
  push)
    if [ ! -f /run/sandbox-flags/allow-git-push ]; then
      echo "error: git push is disabled in the sandbox (use --allow-git-push to enable)" >&2
      exit 1
    fi
    ;;
  remote)
    _action=$(_find_action remote "$@")
    case "$_action" in
      add|set-url|rename)
        echo "error: git remote modification is disabled in the sandbox" >&2
        exit 1 ;;
    esac
    ;;
  submodule)
    _action=$(_find_action submodule "$@")
    if [ "$_action" = "add" ]; then
      echo "error: git submodule add is disabled in the sandbox" >&2
      exit 1
    fi
    ;;
  credential)
    _action=$(_find_action credential "$@")
    case "$_action" in
      fill|get)
        echo "error: git credential extraction is disabled in the sandbox" >&2
        exit 1 ;;
    esac
    ;;
  credential-cache|credential-store)
    echo "error: direct git credential helper invocation is disabled in the sandbox" >&2
    exit 1
    ;;
  config)
    # Find the config key: first non-flag arg after "config", recognizing
    # flags that take value arguments (H2 fix: --file/-f bypass)
    _found_config=0
    _key=""
    _cskip=0
    for _carg in "$@"; do
      if [ "$_cskip" = 1 ]; then _cskip=0; continue; fi
      case "$_carg" in
        -c|-C|--git-dir|--work-tree|--namespace|--super-prefix|--config-env) _cskip=1 ;;
        -*)
          if [ "$_found_config" = 1 ]; then
            # config subcommand flags that take a value argument
            case "$_carg" in
              --file|-f|--blob|--type|--default|--fixed-value) _cskip=1 ;;
            esac
          fi ;;
        *)
          if [ "$_found_config" = 1 ] && [ -z "$_key" ]; then
            _key="$_carg"
            break
          fi
          if [ "$_carg" = "config" ]; then _found_config=1; fi
          ;;
      esac
    done
    _key_lower=$(printf '%s' "$_key" | tr '[:upper:]' '[:lower:]')
    case "$_key_lower" in
      core.fsmonitor|core.sshcommand|core.pager|core.editor|core.hookspath|\
      credential.helper|include.path|alias.*|filter.*|includeif.*.path|\
      diff.*.textconv|diff.*.command|merge.*.driver)
        printf 'error: setting '\''%s'\'' is blocked in the sandbox\n' "$_key" >&2
        exit 1 ;;
    esac
    ;;
esac

# --- Phase 4: Force security-critical config and exec ---
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
