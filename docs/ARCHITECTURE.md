# Architecture & Development Guide

For setup and usage, see the [README](../README.md). For security model and hardening details, see [Security Model](SECURITY.md).

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│ macOS Host                                           │
│                                                      │
│  run-claude.sh:                                      │
│   1. Extract OAuth creds from macOS keychain         │
│   2. Write to temp file, pass via --env-file         │
│   3. Stage ~/.claude data (only needed files)        │
│   4. Pre-resolve DNS → --add-host flags              │
│   5. Launch container with hardened flags             │
│   6. Post-exit: sync-back merge + workspace audit    │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │ OrbStack VM (Linux kernel boundary)            │  │
│  │  ┌──────────────────────────────────────────┐  │  │
│  │  │ Docker Container                         │  │  │
│  │  │  Read-only rootfs + seccomp + no caps    │  │  │
│  │  │  iptables allowlist (DNS blocked)        │  │  │
│  │  │                                          │  │  │
│  │  │  /etc/ld.so.preload (read-only rootfs):  │  │  │
│  │  │    git-guard.so — git op enforcement     │  │  │
│  │  │    nodump.so — /proc/mem protection      │  │  │
│  │  │                                          │  │  │
│  │  │  Starts as root → setpriv to UID 501     │  │  │
│  │  │  → bounding set cleared to empty         │  │  │
│  │  │  Claude Code CLI (native binary)         │  │  │
│  │  │                                          │  │  │
│  │  │  Mounts:                                 │  │  │
│  │  │   /workspace       ← project dir (rw)    │  │  │
│  │  │   /mnt/.claude-host← staged data (ro)     │  │  │
│  │  │   ~/.claude        ← tmpfs (nosuid,512m)  │  │  │
│  │  │   /tmp             ← tmpfs (noexec,nosuid,512m) │  │  │
│  │  │   ~/.npm           ← tmpfs (nosuid,256m)   │  │  │
│  │  │   ~/.config        ← tmpfs (nosuid,64m)  │  │  │
│  │  │   /run             ← tmpfs (nosuid,noexec,1m) │  │  │
│  │  │   /dev/shm         ← 64m                 │  │  │
│  │  │   /etc/firewall-allowlist.conf ← bind (ro)│  │  │
│  │  │   /tmp/host-gitconfig ← bind (ro,if exists)│  │  │
│  │  │   ~/.claude-sync   ← bind (rw, if sync)   │  │  │
│  │  │                                          │  │  │
│  │  │  Credential flow:                        │  │  │
│  │  │   --env-file (tmpfile, deleted 2s)       │  │  │
│  │  │     → ~/.claude/.credentials.json        │  │  │
│  │  │     → env var unset, scrub attempted     │  │  │
│  │  │       (1s, best-effort — may persist)    │  │  │
│  │  └──────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

## Entrypoint Lifecycle

1. **Mount isolation** — copy session data from host-side staging dir (`/mnt/.claude-host`, contains only needed files) to writable tmpfs (`~/.claude`). Uses `cp -L` (dereference symlinks — prevents symlink-following attacks). Project data loaded using host-side `PROJECT_PATH` encoding for per-project isolation.
2. **Sync-back trap** — register EXIT trap that stages session data for sync-back on clean exit (rsync to `/home/claude/.claude-sync/`). History entries appended via append-only mechanism. Project data relocated from container's `-workspace` encoding to host-encoded path.
3. **Push flag** — create `/run/sandbox-flags/allow-git-push` if `--allow-git-push` was passed (root-owned, immutable after privilege drop)
4. **Firewall** — initialize iptables allowlist, IPv6 disable, port restrictions (443/80), DNS blocked for claude user (pre-resolved via `/etc/hosts`), SSH blocking (including host subnet), connectivity verification. **Firewall init failure is fatal** — container exits if network restrictions cannot be established.
5. **Credentials** — write OAuth tokens to file, schedule background scrub (best-effort urandom overwrite + delete after 1s — may persist if CC re-creates the file)
6. **Git config** — build global gitconfig from host (`~/.gitconfig` mount guarded — only mounted if file exists on host), strip host credential helpers, set `core.hooksPath=/dev/null`, strip `filter` section (prevents command injection via LFS filter definitions)
7. **Git config sanitization** — strip dangerous keys from workspace `.git/config` (all git-guard blocked keys/sections), lock `.git/config` to `root:root` mode `444`. Write post-sanitization SHA-256 hash to **immutable root-owned file** (`chmod 444`, prevents tampering with tamper detection baseline)
8. **GitHub credentials** — feed token into `git credential-cache` (memory-only), scoped to workspace repo via `useHttpPath`
9. **Privilege drop** — `setpriv` to UID 501 with empty bounding set and no inheritable capabilities. Global gitconfig locked to `root:root` mode `444` before drop. When sync-back is enabled, child process is waited on SIGTERM to prevent sync-back racing with still-running child.

## Post-Exit Lifecycle

1. **Sync-back** — rsync session artifacts from container staging dir to host `~/.claude/` (if enabled). Uses `--no-links` (skips all symlinks). Project data relocated from `-workspace` to host-encoded path before sync. Excludes `settings.json`, `settings.local.json`, `statusline-command.sh`, `CLAUDE.md`, `.credentials.json`, `.config.json` / `.config.json.backup.*`, `.gitconfig`, `entrypoint.log`, `.history-baseline-lines`, `history.jsonl` (synced separately via append-only mechanism).
2. **`.git/config` tamper detection** — compare SHA-256 hash against immutable post-sanitization baseline; **atomic restore via mktemp+mv** (replaces any symlink at the target path, preventing arbitrary host file overwrite); auto-restore from pre-session backup and re-apply full sanitization if modified
3. **Interactive hook review** — for each new/modified non-`.sample` hook in `.git/hooks/`, show content preview (first 15 lines, ANSI-sanitized) and prompt keep/remove (default: remove). SHA-256 baseline prevents false positives on pre-existing hooks.
4. **Dangerous config scan** — check `.git/config` for **all git-guard blocked keys** (comprehensive coverage of exact keys and prefix-based sections)
5. **Suspect file warnings** — detect `CLAUDE.md` (prompt injection persistence), `Justfile`, `Taskfile.yml`, `.envrc`, `.vscode/settings.json`, `.vscode/tasks.json`, `Makefile`, `.gitattributes`, `.gitmodules`, `.github/workflows`, and others (52 patterns total) that were **created or modified** during the session (pre/post SHA-256 comparison). **ANSI escape sequences sanitized**.

## Persistent State

By default, the host's `~/.claude/` is mounted **read-only** into the container. A writable tmpfs overlay is used for the session. On clean exit, session data (transcripts, memory, plans, etc.) is synced back to the host — but `settings.json`, `.config.json`, and user-level `CLAUDE.md` are **never** synced back, preventing privilege escalation, config poisoning, and prompt injection attacks.

Use `--no-sync-back` to disable all sync-back. Use `--isolate-claude-data` for Docker Desktop compatibility (uses a named Docker volume instead).

Expired credentials are automatically detected on container start. The launcher runs a host-native `claude` prompt to trigger an OAuth refresh, then re-extracts the updated credentials from the keychain. If the refresh fails, the container refuses to start with a clear error. Use `--fresh-creds` with `--isolate-claude-data` to force re-injection into the named volume even when credentials haven't expired.

## File Reference

**Root** — build entry point, user-facing scripts, metadata:
- **Dockerfile** — Debian Bookworm slim base, Claude Code native binary, guard library compilation, `setpriv` for privilege drop
- **run-claude.sh** — Host launcher: keychain extraction, token refresh, host-side staging of `~/.claude`, DNS pre-resolution, image build, hardened container launch, post-exit workspace audit, sync-back merge
- **lint.sh** — Runs Hadolint on Dockerfile and shellcheck on all shell scripts via Docker
- **.githooks/pre-commit** — Runs lint on commit; enable with `git config core.hooksPath .githooks`

**container/** — files COPY'd into the Docker image:
- **container/entrypoint.sh** — Mount isolation (host state copy), firewall init, credential lifecycle, git config sanitization, sync-back trap, privilege drop
- **container/init-firewall.sh** — iptables chain setup, DNS blocked for claude user (pre-resolved via `/etc/hosts`), SSH blocking, ipset creation, connectivity verification
- **container/reload-firewall.sh** — Reads `config/firewall-allowlist.conf`, resolves domains, fetches GitHub IPs, atomic ipset swap
- **container/git-guard.c** — LD_PRELOAD library enforcing git operation restrictions (push, remote, submodule, config key blocking, `GIT_CONFIG_COUNT` forcing). Loaded via `/etc/ld.so.preload` on read-only rootfs.
- **container/git-wrapper.sh** — Shell wrapper forcing `GIT_CONFIG_COUNT` on every git invocation (defense-in-depth for statically-linked callers)
- **container/nodump.c** — LD_PRELOAD library setting `PR_SET_DUMPABLE=0` after exec (prevents `/proc/<pid>/mem` access)

**config/** — runtime config (mounted/referenced by `docker run`):
- **config/firewall-allowlist.conf** — Configurable domain allowlist for the container firewall
- **config/seccomp-profile.json** — Custom seccomp allowlist (Docker default minus ptrace, process_vm, perf_event, memfd, io_uring, userfaultfd, personality; AF_VSOCK blocked; clone namespace flags including CLONE_NEWTIME blocked)

**docs/** — documentation:
- **docs/SECURITY.md** — Security model, threat model, hardening layers, known limitations, audit methodology
- **docs/ARCHITECTURE.md** — This file: architecture overview, entrypoint lifecycle, file reference, development guide
- **docs/audit/SECURITY-AUDIT-REPORT.md** — Initial comprehensive security audit report
- **docs/audit/ROUND-10-IMPLEMENTATION.md** — Round 10 implementation notes
- **docs/audit/FINDINGS.md** — Cumulative audit findings
- **docs/audit/AUDIT-ROUND-{10,11,12,13,16}.md** — Per-round audit details

## Development Workflow

### Building

```bash
./run-claude.sh --rebuild
```

This checks the latest Claude Code version, skips the rebuild if the image is already up-to-date, and uses targeted cache invalidation to pull only the Claude Code binary layer. Linting runs automatically before the build.

### Linting

```bash
./lint.sh
```

Runs Hadolint on Dockerfile and shellcheck on all shell scripts (`run-claude.sh`, `lint.sh`, `entrypoint.sh`, `init-firewall.sh`, `reload-firewall.sh`, `git-wrapper.sh`) via Docker.

### Pre-commit hooks

```bash
git config core.hooksPath .githooks
```

Runs lint on commit.

### Testing changes

No automated test suite. Testing is manual:

1. **Build:** `./run-claude.sh --rebuild ~/Projects/test-project`
2. **Verify firewall:** curl a blocked site (should fail), curl an allowed site (should work)
3. **Verify git restrictions:** attempt `git push` without `--allow-git-push` (should be blocked)
4. **Verify git-guard:** attempt `git remote add`, `git config core.fsmonitor`, etc. (should be blocked)
5. **Verify credential lifecycle:** check env vars are unset after startup, credential file is scrubbed
6. **Verify post-exit audit:** create a `.envrc` in workspace, exit cleanly, check for warning
7. **Run a security audit round** (see [Security Model](SECURITY.md#running-a-security-audit))
