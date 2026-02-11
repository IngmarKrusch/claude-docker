# Claude Code Docker Sandbox

Run Claude Code CLI in a hardened Docker container with defense-in-depth isolation. Use your Claude Max subscription credentials extracted from macOS keychain — no API key required.

## Prerequisites

- macOS with Docker runtime:
  - **OrbStack** (recommended) — best compatibility with bind-mounts, VM-level isolation
  - **Docker Desktop** — works with `--isolate-claude-data` flag
- Claude Code installed on host (`curl -fsSL https://claude.ai/install.sh | bash`)
- Logged in via `claude login` (credentials stored in keychain)
- (Optional) GitHub CLI authenticated (`gh auth login`) — enables `git push` from the container. **Strongly recommended:** create a [fine-grained PAT](https://github.com/settings/personal-access-tokens/new) scoped to only the target repo. The AI agent can extract the token from the credential cache (same-UID limitation); narrow scope limits blast radius. Use `--disallow-broad-gh-token` to reject classic/OAuth tokens.

## Quick Start

```bash
# Run on any project
./run-claude.sh ~/Projects/my-project

# Run on current directory
cd ~/Projects/some-project && ../claude-docker/run-claude.sh

# Force rebuild (after editing Dockerfile or updating Claude Code)
./run-claude.sh --rebuild ~/Projects/my-project

# Force re-inject credentials from keychain
./run-claude.sh --fresh-creds ~/Projects/my-project
```

The first run builds the Docker image. Subsequent runs reuse the cached image.

## Security Model

The sandbox provides defense-in-depth isolation through multiple orthogonal hardening layers.

| Layer | Protection |
|-------|-----------|
| **Filesystem** | Read-only rootfs. `/workspace` is writable. `~/.claude` is a writable tmpfs populated from a read-only host mount (`/mnt/.claude-host`, root-only) at startup — container writes never reach the host directly. `/tmp` is a noexec tmpfs. |
| **Git operations** | `git push` blocked by default (opt in with `--allow-git-push`). `git remote add/set-url/rename` blocked. Dangerous `git config` keys blocked (`core.fsmonitor`, `core.sshCommand`, `filter.*`, etc.). Hook execution neutralized via `hooksPath=/dev/null`. **Enforced at binary level** via `git-guard.so` (`/etc/ld.so.preload`). Note: the GitHub token is extractable by the AI agent (same-UID limitation) — use fine-grained PATs. |
| **Seccomp** | Custom allowlist profile. Blocks io_uring, userfaultfd, personality, process_vm_readv/writev, perf_event_open, memfd_create/memfd_secret, and other high-risk syscalls. |
| **Capabilities** | All dropped except CHOWN/SETUID/SETGID/SETPCAP (entrypoint setup) and NET_ADMIN/NET_RAW (firewall). Bounding set cleared after init. |
| **Network** | iptables allowlist from configurable `firewall-allowlist.conf`. Non-essential domains removed (statsig, VS Code marketplace — CDN domain fronting risk). DNS rate-limited to 1 query/sec (burst 2) to mitigate tunneling exfiltration (~50 B/s max). Outbound SSH (port 22) blocked. Error reporting disabled via `DISABLE_ERROR_REPORTING=1`. |
| **Privilege drop** | Starts as root for setup, drops to UID 501 via `setpriv` with empty bounding set. No `sudo` in image. `no-new-privileges` prevents escalation. |
| **Credentials** | OAuth tokens written to file inside container (tmpfs); env var cleared before exec. GitHub token stored in `git credential-cache` daemon memory (never on disk), but **extractable by the AI agent** via the cache socket (fundamental same-UID limitation). Use fine-grained PATs scoped to the workspace repo. |
| **VM isolation** | OrbStack's lightweight VM provides a kernel-level boundary between container and macOS host. |

### `~/.claude/` mount isolation

The host's `~/.claude/` is mounted **read-only** at `/mnt/.claude-host` (a root-only path, `chmod 700`) inside the container. A writable **tmpfs** is mounted at `~/.claude`. At startup, the entrypoint (running as root) copies only the data needed for the current session. After privilege drop to UID 501, `/mnt/.claude-host` is inaccessible:

- `.config.json`, `settings.json`, `settings.local.json`, `CLAUDE.md` (read snapshots)
- `history.jsonl` (for `--continue`/`--resume`)
- Current project's `projects/<path>/` data (memory + transcripts)
- `statsig/`, `plugins/`, `stats-cache.json`

**What this protects against:**

| Attack | Protection |
|--------|-----------|
| **Settings escalation** — write `{"permissions":{"allow":["Bash(*)"]}}` to `settings.json` | Writes go to tmpfs; `settings.json` is never synced back to host |
| **CLAUDE.md poisoning** — inject malicious instructions into user-level `~/.claude/CLAUDE.md` | Writes go to tmpfs; user-level `CLAUDE.md` is never synced back to host |
| **Plugin injection** — modify host plugins for persistent compromise | Writes go to tmpfs; lost on exit (plugins do sync back by default) |
| **Cross-project data leakage** — read other projects' memories, sessions, history | Host mount at root-only path (`/mnt/.claude-host`), inaccessible after init; only current project data copied |

**Sync-back (default: on):** On clean container exit, session artifacts are synced back to the host for continuity (transcripts, memory, plans, history, etc.). Sync-back uses `rsync --no-links` to prevent symlink planting attacks (all symlinks are silently skipped — both absolute and relative). Two files are **never** synced back regardless of settings:

- `settings.json` / `settings.local.json` — prevents tool auto-approval escalation
- `CLAUDE.md` (user-level) — prevents persistent prompt injection

Use `--no-sync-back` to disable all sync-back. Project-level `/workspace/CLAUDE.md` is unaffected by this protection (writable via the workspace mount).

**Note:** `--resume <session-id>` from a *different* project won't work because only the current project's transcripts are copied. Sync-back only fires on clean exit (Ctrl+C, `/exit`, `docker stop`); `docker kill` or OOM kills skip it.

### Known trade-offs

Some attack surfaces are intentionally left open because closing them would break core functionality:

- **`~/.npm` tmpfs requires `exec`** — npx downloads and runs binaries from `~/.npm/_npx/` (e.g. MCP servers). Using `noexec` on this mount (commit `60ca5b1`) broke MCP servers; commit `666c2bc` restored `exec`. The firewall allowlist limits what can be downloaded and executed.
- **npm postinstall scripts** — `npm install` runs arbitrary postinstall scripts. Blocking via `--ignore-scripts` would break MCP servers that rely on npx. Mitigated by the firewall allowlist restricting network access.
- **History readable** — The container receives host `history.jsonl` (needed for `--continue`). DNS rate-limiting (~50 B/s) makes exfiltration impractical but does not prevent it entirely.
- **Workspace write-back** — `/workspace` is writable (required for code editing). A compromised session could plant files (`.envrc`, `Makefile`, `.vscode/tasks.json`) that execute when the host opens the project. Post-exit audit warnings are displayed for known dangerous files.
- **GitHub token extractable** — The AI agent runs as the same UID as git. Any mechanism that makes the token available to git also makes it available to the AI. Mitigated by using fine-grained PATs with minimal scope.

## Firewall Configuration

The container's outbound network allowlist is defined in `firewall-allowlist.conf` in the project directory. The file is bind-mounted read-only into the container — Claude cannot modify it.

### Config format

```
# One domain per line. Comments start with #. Empty lines ignored.
# @github fetches IP ranges from api.github.com/meta

@github
api.anthropic.com
registry.npmjs.org
api.todoist.com
```

### Adding or removing domains

Edit `firewall-allowlist.conf` on the host, then apply to running containers:

```bash
# Edit the config
echo "httpbin.org" >> firewall-allowlist.conf

# Reload all running containers
./run-claude.sh --reload-firewall
```

The reload performs an atomic ipset swap — no traffic interruption and no window where all traffic is blocked. If a domain fails to resolve, it is skipped with a warning and all other domains still load.

### `@github` keyword

The special `@github` entry fetches GitHub's published IP ranges from their [meta API](https://api.github.com/meta), aggregates the CIDRs, and adds them to the allowlist. This covers `github.com`, `api.github.com`, `raw.githubusercontent.com`, and other GitHub services.

## Usage

### Basic usage

```bash
./run-claude.sh ~/Projects/my-project      # Specific project
./run-claude.sh ~/Work/client-repo         # Any directory
./run-claude.sh                            # Current directory
```

Only the specified directory is mounted at `/workspace`. Claude cannot see other directories on your Mac.

### Script flags

These are consumed by `run-claude.sh` itself:

- `--rebuild` — Rebuild image (runs lint, skips if already up-to-date, uses targeted cache bust)
- `--fresh-creds` — Overwrite credentials with current keychain values
- `--isolate-claude-data` — Use isolated Docker volume instead of read-only host mount + tmpfs (required for Docker Desktop)
- `--no-sync-back` — Disable sync-back of session data to host on clean exit
- `--with-gvisor` — Use gVisor (runsc) runtime if available (note: firewall doesn't work with gVisor)
- `--allow-git-push` — Enable `git push` from inside the container (blocked by default for security)
- `--disallow-broad-gh-token` — Reject broad-scope GitHub tokens (ghp_*/gho_*). Only fine-grained PATs (github_pat_*) accepted.
- `--reload-firewall` — Reload `firewall-allowlist.conf` in all running containers

### Passing arguments to Claude Code

Everything that isn't a script flag or the project directory is passed through to `claude`:

```bash
./run-claude.sh ../my-project --continue               # Resume last conversation
./run-claude.sh --continue                              # Resume (current directory)
./run-claude.sh ../foo -p "fix the tests"               # One-shot prompt
./run-claude.sh ../foo --allow-dangerously-skip-permissions   # Allow Bypass permission prompts
./run-claude.sh ../foo --resume SESSION_ID               # Resume specific session
```

The first argument that is an existing directory becomes the project dir. All other non-script arguments go to claude. Run `./run-claude.sh -h` for full details.

### Git push from the container

**`git push` is blocked by default** to prevent data exfiltration through the project repo. To enable it, pass `--allow-git-push`:

```bash
./run-claude.sh --allow-git-push ~/Projects/my-project
```

When enabled, the sandbox extracts your GitHub token from the host's `gh` CLI and configures `git credential-cache` inside the container. The token lives in the credential-cache daemon's memory (never on disk). The cache socket resides on `/tmp` (tmpfs), gone when the container exits. The `GITHUB_TOKEN` env var is unset before Claude Code starts.

Additionally, `git remote add/set-url/rename` is always blocked (prevents adding exfiltration targets), and dangerous `git config` keys (`core.fsmonitor`, `core.sshCommand`, `filter.*`, `credential.helper`, etc.) are blocked.

**Security limitation:** The AI agent runs as the same UID as git. Any mechanism that makes the token available to git (credential cache, env vars) also makes it extractable by the AI (e.g., via `net.connect` to the cache socket). This is a fundamental same-UID constraint. **Mitigation:** Use [fine-grained PATs](https://github.com/settings/personal-access-tokens/new) scoped to only the target repo. Use `--disallow-broad-gh-token` to reject classic/OAuth tokens at launch.

Requirements:
- `gh` CLI installed on host
- Authenticated via `gh auth login`
- `--allow-git-push` flag passed to `run-claude.sh`

If `gh` is not installed or not authenticated, the container starts normally — git operations other than push work without credentials.

### Shell alias

Add to `~/.zshrc` or `~/.bashrc`:

```bash
alias dclaude='/path/to/claude-docker/run-claude.sh'
```

Then: `dclaude ~/Projects/my-project` or `dclaude --rebuild ~/Projects/my-project --continue`

## How It Works

### Architecture

```
┌──────────────────────────────────────────────────────┐
│ macOS Host                                           │
│                                                      │
│  run-claude.sh:                                      │
│   1. Extract OAuth creds from macOS keychain         │
│   2. Pass as env var CLAUDE_CREDENTIALS              │
│   3. Launch container with hardened flags             │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │ OrbStack VM (Linux kernel boundary)            │  │
│  │  ┌──────────────────────────────────────────┐  │  │
│  │  │ Docker Container                         │  │  │
│  │  │  Read-only rootfs + seccomp + no caps    │  │  │
│  │  │  iptables allowlist (Anthropic/GitHub/npm/Todoist) │  │  │
│  │  │                                          │  │  │
│  │  │  Starts as root → setpriv drops to claude   │  │  │
│  │  │  Claude Code CLI (native binary)         │  │  │
│  │  │                                          │  │  │
│  │  │  Mounts:                                 │  │  │
│  │  │   /workspace ← project dir (rw)          │  │  │
│  │  │   /mnt/.claude-host ← host ~/.claude (ro, root-only) │  │  │
│  │  │   ~/.claude ← tmpfs (rw, 512m)          │  │  │
│  │  │   /tmp ← tmpfs (noexec, 512m)           │  │  │
│  │  │                                          │  │  │
│  │  │  Credential flow:                        │  │  │
│  │  │   env CLAUDE_CREDENTIALS                 │  │  │
│  │  │     → entrypoint writes to               │  │  │
│  │  │       ~/.claude/.credentials.json        │  │  │
│  │  │     → env var unset before exec          │  │  │
│  │  └──────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

### Credential flow

Claude Max uses OAuth stored in macOS keychain under `"Claude Code-credentials"`. The `run-claude.sh` script extracts this, passes it via env var, and the entrypoint writes it to `~/.claude/.credentials.json`. The env var is then unset so credentials aren't visible in `/proc/*/environ`.

### Persistent state

By default, the host's `~/.claude/` is mounted **read-only** into the container. A writable tmpfs overlay is used for the session. On clean exit, session data (transcripts, memory, plans, etc.) is synced back to the host — but `settings.json` and user-level `CLAUDE.md` are **never** synced back, preventing privilege escalation and prompt injection attacks.

Use `--no-sync-back` to disable all sync-back. Use `--isolate-claude-data` for Docker Desktop compatibility (uses a named Docker volume instead).

Expired credentials are automatically detected on container start and replaced with fresh ones from keychain. Use `--fresh-creds` to force re-injection even when credentials haven't expired.

## Updating Claude Code

```bash
./run-claude.sh --rebuild
```

This checks the latest Claude Code version, skips the rebuild if the image is already up-to-date, and uses targeted cache invalidation to pull only the Claude Code binary layer. Linting runs automatically before the build.

## Troubleshooting

### "No Claude Code credentials found in keychain"

Log in to Claude Code on your Mac first:

```bash
claude login
```

Verify the keychain entry exists:

```bash
security find-generic-password -s "Claude Code-credentials" -w 2>/dev/null && echo "OK" || echo "NOT FOUND"
```

### Token expired / auth errors

OAuth tokens expire. The sandbox automatically detects expired credentials and re-injects fresh ones from keychain on container start. You'll see `[sandbox] Credentials auto-refreshed (expired)` in the output.

If auto-refresh fails or you see auth errors mid-session:

1. Re-run `claude login` on your Mac to refresh keychain credentials
2. Re-launch with `--fresh-creds` to force re-injection:
   ```bash
   ./run-claude.sh --fresh-creds ~/Projects/my-project
   ```

### "Firewall not initialized" warning

The iptables firewall requires NET_ADMIN capability. If you see this warning, check that `--cap-add=NET_ADMIN` is present in the docker run command. With gVisor runtime, the firewall does not work due to gVisor's virtualized network stack — this is expected.

### Permission denied on project files

The container user (UID 501) must match your macOS user:

```bash
id -u  # should be 501
```

If different, rebuild:

```bash
docker rmi claude-sandbox
./run-claude.sh ~/Projects/whatever  # auto-rebuilds with your UID
```

### Container won't start with gVisor

```bash
docker run --rm --runtime=runsc hello-world
```

If gVisor is broken, `run-claude.sh` falls back to runc automatically. You can also explicitly disable gVisor with `--no-gvisor`.

### Bash commands fail with Docker Desktop

Docker Desktop's file sharing (VirtioFS/gRPC FUSE) has permission issues with read-only bind-mounts.

**Solutions:**
1. **Switch to OrbStack** (recommended) — OrbStack's file sharing handles permissions correctly
2. **Use isolated data volume** — Run with `--isolate-claude-data` flag:
   ```bash
   ./run-claude.sh --isolate-claude-data ~/Projects/my-project
   ```

| Runtime | Default (ro mount + tmpfs) | `--isolate-claude-data` |
|---------|---------------------------|-------------------------|
| OrbStack | ✅ Works | ✅ Works |
| Docker Desktop | ❌ Permission errors | ✅ Works |

### Resetting Claude Code state

Session data is synced back to `~/.claude/` on clean exit. To reset, remove files there directly.

If using `--isolate-claude-data`, the state lives in a Docker volume:

```bash
docker volume rm claude-data
```

Removes conversation history, settings, and cached data. Credentials are re-injected from keychain on next run.

## Alternatives Comparison

| Approach | Auth | Sandboxing | macOS Keychain |
|----------|------|-----------|----------------|
| **This setup** | Claude Max OAuth | Read-only rootfs, seccomp, capabilities drop, iptables firewall, VM isolation | Yes |
| [addt (dclaude)](https://github.com/anthropics/claude-code/tree/main/packages/addt) | API key only | Docker + firewall | No |
| [Anthropic devcontainer](https://github.com/anthropics/claude-code/tree/main/.devcontainer) | Manual login | Docker + iptables | No |
| [claude-code-docker](https://github.com/decisional/claude-code-docker) | Keychain extraction | Docker only | Yes |
| Native `claude` | Claude Max OAuth | None | Native |

## File Reference

- **Dockerfile** — Debian Bookworm slim base, Claude Code native binary, `setpriv` for privilege drop
- **entrypoint.sh** — Mount isolation (host state copy), firewall init, credential setup, gitconfig, sync-back trap, privilege drop
- **run-claude.sh** — Host launcher: keychain extraction, image build, hardened container launch, post-exit workspace audit, sync-back merge
- **init-firewall.sh** — iptables chain setup, DNS rate limiting, calls `reload-firewall.sh`, connectivity verification
- **reload-firewall.sh** — Reads `firewall-allowlist.conf`, resolves domains, atomic ipset swap
- **firewall-allowlist.conf** — Configurable domain allowlist for the container firewall
- **seccomp-profile.json** — Custom seccomp allowlist (Docker default minus high-risk syscalls)
- **git-guard.c** — LD_PRELOAD library enforcing git operation restrictions (push, remote, submodule, config key blocking, GIT_CONFIG_COUNT forcing). Loaded via `/etc/ld.so.preload`.
- **git-wrapper.sh** — Shell wrapper forcing GIT_CONFIG_COUNT on every git invocation (defense-in-depth for statically-linked callers)
- **nodump.c** — LD_PRELOAD library setting PR_SET_DUMPABLE=0 (prevents `/proc/<pid>/mem` access)
- **lint.sh** — Runs Hadolint on Dockerfile via Docker
- **.githooks/pre-commit** — Runs lint on commit; enable with `git config core.hooksPath .githooks`
