# Claude Code Docker Sandbox

Run Claude Code CLI in a sandboxed Docker container with gVisor isolation. Use your Claude Max subscription credentials extracted from macOS keychain — no API key required.

## Prerequisites

- macOS with Docker runtime:
  - **OrbStack** (recommended) — best compatibility with bind-mounts
  - **Docker Desktop** — works with `--isolate-claude-data` flag
- gVisor runtime configured (optional, for additional syscall isolation)
- Claude Code installed on host (`curl -fsSL https://claude.ai/install.sh | bash`)
- Logged in via `claude login` (credentials stored in keychain)

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

The sandbox provides filesystem isolation and syscall interception while allowing network access.

| Layer | Protection |
|-------|-----------|
| **Filesystem** | Only the specified project directory is mounted. Claude cannot see `~`, `.ssh`, `.env`, or other projects. |
| **gVisor** | Syscall interception via user-space kernel. All system calls go through gVisor, not the host kernel. |
| **Privilege drop** | Starts as root for setup, drops to UID 501 via `gosu`. No `sudo` in image. `no-new-privileges` prevents escalation. |
| **Credentials** | OAuth tokens written to file inside container; env var cleared before exec. Tokens persist in `~/.claude/` (shared with host by default). |

### Network (NOT sandboxed)

The container has full outbound internet access. Claude Code can reach any host, not just Anthropic's API.

The included iptables firewall script does not work with gVisor's virtualized network stack. For defense-in-depth, use host-level tools like [Little Snitch](https://www.obdev.at/products/littlesnitch/) or [LuLu](https://objective-see.org/products/lulu.html) to restrict Docker's outbound connections.

## Usage

### Basic usage

```bash
./run-claude.sh ~/Projects/my-project      # Specific project
./run-claude.sh ~/Work/client-repo         # Any directory
./run-claude.sh                            # Current directory
```

Only the specified directory is mounted at `/workspace`. Claude cannot see other directories on your Mac.

### Flags

- `--rebuild` — Rebuild image with `--no-cache` (runs lint first)
- `--fresh-creds` — Overwrite credentials with current keychain values
- `--isolate-claude-data` — Use isolated Docker volume instead of host `~/.claude/` (required for Docker Desktop)
- `--no-gvisor` — Disable gVisor runtime even if available (firewall works without gVisor)

### Shell alias

Add to `~/.zshrc` or `~/.bashrc`:

```bash
alias dclaude='/path/to/claude-docker/run-claude.sh'
```

Then: `dclaude ~/Projects/my-project` or `dclaude --rebuild`

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────┐
│ macOS Host                                      │
│                                                 │
│  run-claude.sh:                                 │
│   1. Extract OAuth creds from macOS keychain    │
│   2. Pass as env var CLAUDE_CREDENTIALS         │
│   3. Launch container                           │
│                                                 │
│  ┌───────────────────────────────────────────┐  │
│  │ Docker Container (gVisor runtime)         │  │
│  │                                           │  │
│  │  Starts as root → gosu drops to claude    │  │
│  │  Claude Code CLI (native binary)          │  │
│  │                                           │  │
│  │  Mounts:                                  │  │
│  │   /workspace ← project dir (rw)           │  │
│  │   ~/.claude ← host ~/.claude (bind-mount) │  │
│  │              or claude-data volume        │  │
│  │              (with --isolate-claude-data) │  │
│  │                                           │  │
│  │  Credential flow:                         │  │
│  │   env CLAUDE_CREDENTIALS                  │  │
│  │     → entrypoint writes to                │  │
│  │       ~/.claude/.credentials.json         │  │
│  │     → env var unset before exec           │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
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

This rebuilds the image with `--no-cache`, pulling the latest Claude Code binary. Linting runs automatically before the build.

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

Expected with gVisor runtime. The container works normally. See Security Model above.

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
| **This setup** | Claude Max OAuth | gVisor + filesystem isolation | Yes |
| [addt (dclaude)](https://github.com/anthropics/claude-code/tree/main/packages/addt) | API key only | Docker + firewall | No |
| [Anthropic devcontainer](https://github.com/anthropics/claude-code/tree/main/.devcontainer) | Manual login | Docker + iptables | No |
| [claude-code-docker](https://github.com/decisional/claude-code-docker) | Keychain extraction | Docker only | Yes |
| Native `claude` | Claude Max OAuth | None | Native |

## File Reference

- **Dockerfile** — Debian Bookworm slim base, Claude Code native binary, `gosu` for privilege drop
- **entrypoint.sh** — Firewall attempt, credential setup, gitconfig copy, privilege drop
- **run-claude.sh** — Host launcher: keychain extraction, image build, container launch
- **init-firewall.sh** — Anthropic's iptables allowlist (inactive with gVisor)
- **lint.sh** — Runs Hadolint on Dockerfile via Docker
- **.githooks/pre-commit** — Runs lint on commit; enable with `git config core.hooksPath .githooks`
