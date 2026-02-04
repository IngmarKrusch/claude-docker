# Claude Code Docker Sandbox

Run Claude Code CLI inside a sandboxed Docker container on macOS, using your Claude Max subscription (OAuth credentials from macOS keychain).

## Quick Start

```bash
# Run on any project
~/Projects/claude-docker/run-claude.sh ~/Projects/my-project

# Run on current directory
cd ~/Projects/some-project
~/Projects/claude-docker/run-claude.sh

# Force rebuild (e.g., after editing Dockerfile or updating Claude Code)
~/Projects/claude-docker/run-claude.sh --rebuild ~/Projects/my-project

# Force re-inject credentials from keychain (overrides volume)
~/Projects/claude-docker/run-claude.sh --fresh-creds ~/Projects/my-project

# Lint the Dockerfile (runs hadolint via Docker)
~/Projects/claude-docker/lint.sh
```

The first run builds the Docker image (installs Claude Code native binary and tools). Subsequent runs reuse the cached image.

## Working With Projects

### Example: a specific project

```bash
~/Projects/claude-docker/run-claude.sh ~/Projects/my-project
```

This mounts `~/Projects/my-project` at `/workspace` inside the container. Claude Code sees the full project tree, can read/write files, run git commands, and make commits. Your `.gitconfig` is copied in at startup (with `safe.directory=/workspace` added) so git identity and commands work.

### Any other project

```bash
~/Projects/claude-docker/run-claude.sh ~/Projects/other-project
~/Projects/claude-docker/run-claude.sh ~/Work/client-repo
~/Projects/claude-docker/run-claude.sh /absolute/path/to/anything
```

The argument is any directory on your Mac. Only that directory is mounted -- Claude cannot see your home directory, other projects, or system files.

### No argument (current directory)

```bash
cd ~/Projects/whatever
~/Projects/claude-docker/run-claude.sh
```

Uses `.` (current directory) as the project.

### Tip: shell alias

Add to `~/.zshrc` or `~/.bashrc`:

```bash
alias dclaude='~/Projects/claude-docker/run-claude.sh'
```

Then:

```bash
dclaude ~/Projects/my-project
dclaude .
dclaude --rebuild ~/Projects/my-project
dclaude --fresh-creds ~/Projects/my-project
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│ macOS Host                                      │
│                                                 │
│  run-claude.sh:                                 │
│   1. Extract OAuth creds from macOS keychain    │
│   2. Pass as env var CLAUDE_CREDENTIALS         │
│   3. Launch container                           │
│                                                 │
│  ┌───────────────────────────────────────────┐   │
│  │ Docker Container (gVisor runtime)        │   │
│  │                                          │   │
│  │  Starts as root → gosu drops to claude    │   │
│  │  Claude Code CLI (native binary)          │   │
│  │  --allow-dangerously-skip-permissions     │   │
│  │                                          │   │
│  │  Mounts:                                 │   │
│  │   /workspace ← project dir (rw)          │   │
│  │   /tmp/host-gitconfig ← gitconfig (ro)   │   │
│  │   ~/.claude ← claude-data volume (rw)    │   │
│  │                                          │   │
│  │  Credential flow:                        │   │
│  │   env CLAUDE_CREDENTIALS                 │   │
│  │     → entrypoint writes to               │   │
│  │       ~/.claude/.credentials.json        │   │
│  │     → env var unset before exec          │   │
│  │     → Claude Code reads file normally    │   │
│  └───────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

### Credential Flow

Claude Max uses OAuth, stored in macOS keychain under the service name `"Claude Code-credentials"`. This is not a file on disk -- it is only accessible via the `security` command on macOS.

`run-claude.sh` extracts the credential JSON from keychain, passes it to the container via the `CLAUDE_CREDENTIALS` environment variable, and the entrypoint writes it to `~/.claude/.credentials.json` inside the container. The env var is then `unset` before `exec`-ing Claude Code, so the raw credential string is not visible to child processes or `/proc/*/environ`.

Why an env var instead of a file mount? Docker bind-mounting a macOS temp file into a gVisor container with an overlapping named volume (`claude-data` on `~/.claude`) is unreliable. The env var approach works consistently across runtimes.

### Persistent State

The named volume `claude-data` persists Claude Code's state (conversation history, settings, credentials, etc.) across container runs. On the first run, credentials are written from the keychain to the volume. On subsequent runs, the volume's credentials are used as-is, preserving any token refreshes that Claude Code performed. Use `--fresh-creds` to force re-injection from the keychain.

To reset Claude Code state:

```bash
docker volume rm claude-data
```

## Security Model

### What is sandboxed

| Layer | Protection |
|-------|-----------|
| **Filesystem isolation** | Only the specified project directory is mounted. Claude cannot see `~`, other projects, `.ssh`, `.env` files, or system directories. |
| **gVisor (runsc)** | Syscall interception. The container runs on a user-space kernel that intercepts all system calls. Even if Claude Code executes arbitrary commands, they go through gVisor's restricted syscall implementation, not the real host kernel. |
| **Privilege drop via gosu** | Container starts as root for firewall setup, then drops to UID 501 (matching your macOS user) via `gosu`. No `sudo` binary exists in the image. |
| **`no-new-privileges`** | Docker's `--security-opt=no-new-privileges` prevents any process from gaining privileges via setuid binaries. Once dropped to the claude user, escalation back to root is impossible. |
| **Gitconfig isolation** | Host `.gitconfig` is mounted read-only to a staging path, then copied into the container. Claude gets your git identity but cannot modify your host git config. |
| **Credential scoping** | OAuth credentials are written to a file inside the container and the env var is cleared. Credentials persist on the named volume so token refreshes survive across runs. |
| **`--allow-dangerously-skip-permissions`** | This flag is safe inside the sandbox. It tells Claude Code to skip its own permission prompts (tool approvals), which makes sense because the container itself is the security boundary. |

### What is NOT sandboxed: network

The container has **full outbound internet access**. Claude Code can reach any host on the internet, not just Anthropic's API.

This is a known limitation. The Anthropic devcontainer includes an iptables-based firewall (allowlist for Anthropic API, GitHub, npm, Sentry), but it does not work in this setup:

- **gVisor** virtualizes the network stack and does not support iptables/netfilter.
- **runc on Docker Desktop macOS** runs inside a Linux VM where iptables rules are set but traffic still flows through the VM's NAT layer, bypassing the rules.

Claude Code requires internet access to call the Anthropic API, so `--network=none` is not viable.

**Practical risk**: Claude Code running `curl` or `wget` to arbitrary URLs. This is the same risk as running Claude Code on your host Mac with `--allow-dangerously-skip-permissions`. The sandbox adds filesystem isolation on top, which is the main value.

**Host-level mitigation**: Tools like [Little Snitch](https://www.obdev.at/products/littlesnitch/) or [LuLu](https://objective-see.org/products/lulu.html) can restrict outbound connections from Docker containers to an allowlist (e.g., `*.anthropic.com`, `github.com`, `registry.npmjs.org`). This provides defense-in-depth while the in-container iptables firewall remains non-functional under gVisor.

### Firewall script (included but inactive)

The `init-firewall.sh` script from [Anthropic's official devcontainer](https://github.com/anthropics/claude-code/blob/main/.devcontainer/init-firewall.sh) is included in the image and attempted at startup. When it fails (as it does with gVisor), the entrypoint logs a warning and continues. If Docker Desktop or gVisor adds iptables support in the future, the firewall will activate automatically.

## File Reference

### Dockerfile

```
FROM debian:bookworm-slim
```

- Debian Bookworm slim base (no Node.js needed)
- System packages: `git`, `curl`, `gosu`, `zsh`, `fzf`, `ripgrep`, `jq`, `aggregate`, `ca-certificates`, `iptables`, `ipset`, `dnsutils`, `iproute2`
- User `claude` created with host UID/GID (default 501:20, macOS standard)
- Claude Code installed as a native binary via `https://claude.ai/install.sh`
- `DISABLE_AUTOUPDATER=1`: container images are immutable; updates happen via `--rebuild`
- Firewall and entrypoint scripts copied in
- No `USER` directive: container starts as root so the entrypoint can run the firewall script directly, then drops to `claude` via `gosu`
- Build args: `USER_ID`, `GROUP_ID`

### entrypoint.sh

1. Runs as root: attempts to initialize the firewall via `init-firewall.sh` directly (warns on failure)
2. Writes credentials from `CLAUDE_CREDENTIALS` env var to `/home/claude/.claude/.credentials.json` only on first run (or when `FORCE_CREDENTIALS=1`); chowns the file to `claude`; skips if the file already exists on the volume
3. Unsets the env var
4. Copies host gitconfig from `/tmp/host-gitconfig` to `/home/claude/.gitconfig` and adds `safe.directory=/workspace`
5. Drops privileges via `exec gosu claude` and runs the CMD (default: `claude`)

### init-firewall.sh

Anthropic's official firewall script. Sets up iptables allowlist for:
- Anthropic API (`api.anthropic.com`)
- GitHub (fetches IP ranges from GitHub meta API)
- npm registry (`registry.npmjs.org`)
- Sentry (`sentry.io`)
- Statsig (`statsig.anthropic.com`, `statsig.com`)
- VS Code Marketplace (for devcontainer use)

Not functional with gVisor runtime. Included for forward compatibility.

### run-claude.sh

Host-side launcher script. Handles:
1. Extracting OAuth credentials from macOS keychain
2. Building the Docker image on first run (or with `--rebuild`)
3. Detecting gVisor runtime availability
4. Launching the container with correct mounts and capabilities

**Arguments:**
- First positional arg: project directory (default: current directory)
- `--rebuild`: lint Dockerfile then force Docker image rebuild with `--no-cache`
- `--fresh-creds`: force overwrite credentials on the volume with current keychain values

### lint.sh

Runs [Hadolint](https://github.com/hadolint/hadolint) on the Dockerfile via the `hadolint/hadolint` Docker image. Called automatically during `--rebuild` and by the pre-commit hook.

### .githooks/pre-commit

Git pre-commit hook that runs `lint.sh`. Enable with `git config core.hooksPath .githooks`.

## Linting

The Dockerfile is linted with [Hadolint](https://github.com/hadolint/hadolint), run via its official Docker image (no host install needed).

```bash
# Run manually
./lint.sh

# Automatically on rebuild (lint runs before docker build)
./run-claude.sh --rebuild ~/Projects/my-project
```

### Pre-commit hook

To lint automatically on every git commit:

```bash
git config core.hooksPath .githooks
```

This configures git to use the `.githooks/pre-commit` hook, which runs `lint.sh` and blocks the commit if the Dockerfile has lint issues.

## Updating Claude Code

To update Claude Code inside the container to the latest version:

```bash
~/Projects/claude-docker/run-claude.sh --rebuild
```

This rebuilds the image with `--no-cache`, which re-runs the native installer and pulls the latest Claude Code binary.

## Troubleshooting

### "No Claude Code credentials found in keychain"

You need to log in to Claude Code on your Mac first:

```bash
claude login
```

This stores OAuth credentials in macOS keychain under `"Claude Code-credentials"`.

To verify the entry exists:

```bash
security find-generic-password -s "Claude Code-credentials" -w 2>/dev/null && echo "OK" || echo "NOT FOUND"
```

### Token expired / auth errors

OAuth tokens expire. Claude Code normally refreshes them automatically, and the refreshed tokens persist on the `claude-data` volume. If you still get auth errors:

1. Re-run `claude login` on your Mac
2. Re-launch with `--fresh-creds` to overwrite the volume's stale tokens:
   ```bash
   ~/Projects/claude-docker/run-claude.sh --fresh-creds ~/Projects/my-project
   ```

### "Firewall not initialized" warning

Expected with gVisor runtime. The container works normally without the firewall. See the Security Model section for details.

### Permission denied on project files

The container user (UID 501, GID 20) must match your macOS user. Verify:

```bash
id -u  # should be 501
id -g  # should be 20
```

If different, rebuild with your actual IDs:

```bash
docker rmi claude-sandbox
~/Projects/claude-docker/run-claude.sh ~/Projects/whatever
# (auto-rebuilds with current id -u / id -g)
```

### Container won't start with gVisor

If you see `OCI runtime create failed`:

```bash
# Check gVisor is installed and working
docker run --rm --runtime=runsc hello-world
```

If gVisor is broken, `run-claude.sh` auto-falls back to the default runtime (runc). You can also force runc by editing the script.

### Resetting Claude Code state

```bash
docker volume rm claude-data
```

This removes conversation history, settings, and cached data. Credentials are re-injected from keychain on next run.

## How It Differs From Alternatives

| Approach | Auth | Sandboxing | macOS Keychain |
|----------|------|-----------|----------------|
| **This setup** | Claude Max OAuth (keychain extraction) | gVisor + filesystem isolation | Yes |
| [addt (dclaude)](https://github.com/anthropics/claude-code/tree/main/packages/addt) | API key only | Docker + firewall | No (can't read keychain) |
| [Anthropic devcontainer](https://github.com/anthropics/claude-code/tree/main/.devcontainer) | Manual login inside container | Docker + iptables firewall | No (VS Code based) |
| [claude-code-docker](https://github.com/decisional/claude-code-docker) | Keychain extraction (inspiration for this) | Docker only | Yes |
| Native `claude` on macOS | Claude Max OAuth | None (full host access) | Native |

## Prerequisites

- macOS with Docker Desktop installed
- gVisor runtime configured in Docker Desktop (recommended, not required)
- Claude Code installed on host (via `curl -fsSL https://claude.ai/install.sh | bash`)
- Logged in via `claude login` (credentials in keychain)
