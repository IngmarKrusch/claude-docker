# Claude Code Docker Sandbox

Run Claude Code CLI in a hardened Docker container with defense-in-depth isolation. Use your Claude Max subscription credentials extracted from macOS keychain — no API key required.

## Prerequisites

- macOS with Docker runtime:
  - **OrbStack** (recommended) — best compatibility with bind-mounts, VM-level isolation
  - **Docker Desktop** — works with `--isolate-claude-data` flag
- Claude Code installed on host (`curl -fsSL https://claude.ai/install.sh | bash`)
- Logged in via `claude login` (credentials stored in keychain)
- (Optional) GitHub CLI authenticated (`gh auth login`) — enables `git push` from inside the container

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
| **Filesystem** | Read-only rootfs. Only `/workspace` and `~/.claude` are writable. `/tmp` is a noexec tmpfs. |
| **Seccomp** | Custom allowlist profile. Blocks io_uring, userfaultfd, personality, process_vm_readv/writev, perf_event_open, memfd_create/memfd_secret, and other high-risk syscalls. |
| **Capabilities** | All dropped except CHOWN/SETUID/SETGID/SETPCAP (entrypoint setup) and NET_ADMIN/NET_RAW (firewall). Bounding set cleared after init. |
| **Network** | iptables allowlist from configurable `firewall-allowlist.conf`. Only listed domains reachable. All other outbound traffic blocked. |
| **Privilege drop** | Starts as root for setup, drops to UID 501 via `setpriv` with empty bounding set. No `sudo` in image. `no-new-privileges` prevents escalation. |
| **Credentials** | OAuth tokens written to file inside container; env var cleared before exec. Tokens persist in `~/.claude/` (shared with host by default). GitHub token stored only in `git credential-cache` daemon memory (never on disk). |
| **VM isolation** | OrbStack's lightweight VM provides a kernel-level boundary between container and macOS host. |

### Known trade-offs

Some attack surfaces are intentionally left open because closing them would break core functionality:

- **`~/.npm` tmpfs requires `exec`** — npx downloads and runs binaries from `~/.npm/_npx/` (e.g. MCP servers). Using `noexec` on this mount (commit `60ca5b1`) broke MCP servers; commit `666c2bc` restored `exec`. The firewall allowlist limits what can be downloaded and executed.
- **npm postinstall scripts** — `npm install` runs arbitrary postinstall scripts. Blocking via `--ignore-scripts` would break MCP servers that rely on npx. Mitigated by the firewall allowlist restricting network access.

## Firewall Configuration

The container's outbound network allowlist is defined in `firewall-allowlist.conf` in the project directory. The file is bind-mounted read-only into the container — Claude cannot modify it.

### Config format

```
# One domain per line. Comments start with #. Empty lines ignored.
# @github fetches IP ranges from api.github.com/meta

@github
api.anthropic.com
registry.npmjs.org
sentry.io
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
- `--isolate-claude-data` — Use isolated Docker volume instead of host `~/.claude/` (required for Docker Desktop)
- `--with-gvisor` — Use gVisor (runsc) runtime if available (note: firewall doesn't work with gVisor)
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

If the GitHub CLI (`gh`) is authenticated on your host, the sandbox automatically extracts your GitHub token and configures `git credential-cache` inside the container. This enables `git push` over HTTPS without any manual setup.

The token **never touches disk** — it lives only in the credential-cache daemon's memory. The cache socket resides on `/tmp` (tmpfs), which is ephemeral and gone when the container exits. The `GITHUB_TOKEN` env var is overwritten with random data and unset before Claude Code starts.

Requirements:
- `gh` CLI installed on host
- Authenticated via `gh auth login`

If `gh` is not installed or not authenticated, the container starts normally — git push just won't have credentials pre-configured.

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
│  │  │  iptables allowlist (Anthropic/GitHub/…) │  │  │
│  │  │                                          │  │  │
│  │  │  Starts as root → setpriv drops to claude   │  │  │
│  │  │  Claude Code CLI (native binary)         │  │  │
│  │  │                                          │  │  │
│  │  │  Mounts:                                 │  │  │
│  │  │   /workspace ← project dir (rw)          │  │  │
│  │  │   ~/.claude ← host ~/.claude or volume   │  │  │
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

By default, the container bind-mounts the host's `~/.claude/` directory. This shares memory files, session history, and settings between the host and container. **This requires OrbStack** — Docker Desktop has permission issues with this bind-mount.

For Docker Desktop compatibility (or harder isolation), use `--isolate-claude-data` to use a separate Docker volume (`claude-data`) instead.

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

Docker Desktop's file sharing (VirtioFS/gRPC FUSE) has permission issues with bind-mounts when Claude Code writes to shell-snapshots or session-env directories.

**Solutions:**
1. **Switch to OrbStack** (recommended) — OrbStack's file sharing handles permissions correctly
2. **Use isolated data volume** — Run with `--isolate-claude-data` flag:
   ```bash
   ./run-claude.sh --isolate-claude-data ~/Projects/my-project
   ```

| Runtime | Bind-mount `~/.claude` | `--isolate-claude-data` |
|---------|------------------------|-------------------------|
| OrbStack | ✅ Works | ✅ Works |
| Docker Desktop | ❌ Permission errors | ✅ Works |

### Resetting Claude Code state

By default, state is shared with the host in `~/.claude/`. To reset, remove files there directly.

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
- **entrypoint.sh** — Firewall init, credential setup, gitconfig (on volume), privilege drop
- **run-claude.sh** — Host launcher: keychain extraction, image build, hardened container launch
- **init-firewall.sh** — iptables chain setup, calls `reload-firewall.sh`, connectivity verification
- **reload-firewall.sh** — Reads `firewall-allowlist.conf`, resolves domains, atomic ipset swap
- **firewall-allowlist.conf** — Configurable domain allowlist for the container firewall
- **seccomp-profile.json** — Custom seccomp allowlist (Docker default minus high-risk syscalls)
- **lint.sh** — Runs Hadolint on Dockerfile via Docker
- **.githooks/pre-commit** — Runs lint on commit; enable with `git config core.hooksPath .githooks`
