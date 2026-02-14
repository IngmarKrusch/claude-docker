# Claude Code Docker Sandbox

Run Claude Code CLI in a hardened Docker container with defense-in-depth isolation. Use your Claude Max subscription credentials extracted from macOS keychain — no API key required.

## Prerequisites

- macOS with OrbStack (recommended for VM-level isolation and bind-mount compatibility)
- Docker Desktop is supported with `--isolate-claude-data` (see [Troubleshooting](#bash-commands-fail-with-docker-desktop))
- Claude Code installed on host (`curl -fsSL https://claude.ai/install.sh | bash`)
- Logged in via `claude login` (credentials stored in keychain)
- (Optional) GitHub CLI authenticated (`gh auth login`) — enables `git push` from the container
- (Optional) `dig` command on host — used to pre-resolve DNS for allowlisted domains. Installed by default on macOS. If missing, the container falls back to internal DNS resolution.

## Setup

### 1. Harden the OrbStack kernel

OrbStack uses a single Linux VM with a shared kernel for all containers and machines. The custom seccomp profile blocks dangerous syscalls at container level; these kernel settings provide a fallback if seccomp is bypassed.

```bash
# Create a lightweight Linux machine (if you don't have one)
orb create ubuntu hardening

# Set kernel hardening parameters (as root)
orb -m hardening -u root sh -c '
  # Restrict ptrace to admin only (defense-in-depth; seccomp already blocks ptrace)
  sysctl -w kernel.yama.ptrace_scope=2

  # Disable unprivileged userfaultfd (defense-in-depth; seccomp already blocks it)
  sysctl -w vm.unprivileged_userfaultfd=1

  # Make persistent across VM restarts
  cat > /etc/sysctl.d/99-claude-sandbox.conf << EOF
kernel.yama.ptrace_scope = 2
vm.unprivileged_userfaultfd = 1
EOF
'
```

**Note:** These are defense-in-depth measures. The custom seccomp profile already blocks `ptrace`, `userfaultfd`, `process_vm_readv/writev`, `perf_event_open`, `memfd_create`, and `memfd_secret` syscalls at the container level. The kernel-level settings provide a fallback if the seccomp profile is ever bypassed. OrbStack may reset kernel parameters on updates — re-run the commands above after OrbStack updates if needed.

### 2. Set up GitHub access (for git push)

> Skip this step if you don't need git push from the container.

**Strongly recommended:** create a [fine-grained PAT](https://github.com/settings/personal-access-tokens/new) scoped to only the target repo. The AI agent can extract the token from the credential cache (same-UID limitation); narrow scope limits blast radius.

1. Create a fine-grained PAT at [github.com/settings/personal-access-tokens/new](https://github.com/settings/personal-access-tokens/new) scoped to only the target repo
2. Authenticate: `gh auth login`
3. Use `--disallow-broad-gh-token` to reject classic/OAuth tokens at launch — only fine-grained PATs (`github_pat_*`) accepted. Classic (`ghp_*`) and OAuth (`gho_*`) tokens are rejected.

Requirements:
- `gh` CLI installed on host
- Authenticated via `gh auth login`
- `--allow-git-push` flag passed to `run-claude.sh`

If `gh` is not installed or not authenticated, the container starts normally — git operations other than push work without credentials.

### 3. Launch

```bash
./run-claude.sh --allow-git-push --disallow-broad-gh-token ~/Projects/my-project
./run-claude.sh ~/Projects/my-project   # Without git push
cd ~/Projects/some-project && ../claude-docker/run-claude.sh  # Current directory
./run-claude.sh                          # Current directory (from claude-docker/)
./run-claude.sh --rebuild ~/Projects/my-project  # Force rebuild
./run-claude.sh --fresh-creds ~/Projects/my-project  # Re-inject credentials
```

The first run builds the Docker image. Subsequent runs reuse the cached image. Only the specified directory is mounted at `/workspace`. Claude cannot see other directories on your Mac.

After setup, the container runs with: read-only rootfs, network allowlist with DNS blocked for the AI user, seccomp syscall filtering, all capabilities dropped, git operation restrictions at the binary level, credential isolation with auto-scrub, and post-exit workspace audit.

> For the full threat model, hardening layer details, and known limitations, see [Security Model](docs/SECURITY.md).

## Usage

### Script flags

These are consumed by `run-claude.sh` itself:

- `--rebuild` — Rebuild image (runs lint, skips if already up-to-date, uses targeted cache bust)
- `--fresh-creds` — Overwrite credentials with current keychain values
- `--isolate-claude-data` — Use isolated Docker volume instead of read-only host mount + tmpfs (required for Docker Desktop)
- `--no-sync-back` — Disable sync-back of session data to host on clean exit
- `--with-gvisor` — Use gVisor (runsc) runtime if available (note: firewall doesn't work with gVisor)
- `--allow-git-push` — Enable `git push` from inside the container (blocked by default for security)
- `--disallow-broad-gh-token` — Reject broad-scope GitHub tokens (`ghp_*`/`gho_*`). Only fine-grained PATs (`github_pat_*`) accepted.
- `--reload-firewall` — Reload `config/firewall-allowlist.conf` in all running containers

### Passing arguments to Claude Code

Everything that isn't a script flag or the project directory is passed through to `claude`:

```bash
./run-claude.sh ../my-project --continue               # Resume last conversation
./run-claude.sh --continue                              # Resume (current directory)
./run-claude.sh ../foo -p "fix the tests"               # One-shot prompt
./run-claude.sh ../foo --allow-dangerously-skip-permissions   # Bypass permission prompts
./run-claude.sh ../foo --resume SESSION_ID               # Resume specific session
```

The first argument that is an existing directory becomes the project dir. All other non-script arguments go to claude. Run `./run-claude.sh -h` for full details.

### Resuming sessions

Sessions can be resumed across container restarts and between the container and host:

```bash
# Continue last session (same project)
./run-claude.sh ~/Projects/my-project --continue

# Resume a specific session by ID
./run-claude.sh ~/Projects/my-project --resume SESSION_ID
```

Sessions created inside the container are resumable from the host (`claude --continue`), and host-native sessions are resumable from inside the container. The `project` field in `history.jsonl` is automatically translated between the host path and `/workspace` at container boundaries.

**Caveats:**

- **Same project only** — only the current project's transcripts are staged into the container. You cannot resume a session from a different project.
- **Clean exit required** — sync-back runs on `/exit`, Ctrl+C, or `docker stop`. If the container is killed (`docker kill`, OOM, crash), session data on the tmpfs is lost.
- **`--no-sync-back` disables resume** — without sync-back, session data is not written to the host and cannot be resumed in the next run.
- **`--isolate-claude-data`** — uses a persistent Docker volume instead of sync-back. Sessions persist across container restarts automatically, but are not accessible from the host.

### Firewall configuration

The container's outbound network allowlist is defined in `config/firewall-allowlist.conf`. The file is bind-mounted read-only into the container — Claude cannot modify it. Domains are pre-resolved on the host at launch and injected into the container's `/etc/hosts` via `--add-host`. DNS is completely blocked for the claude user inside the container — all hostname resolution comes from `/etc/hosts`. Root retains DNS access for ipset population during init.

#### Default allowlist

```
@github                    # GitHub IPs (fetched from api.github.com/meta)
api.anthropic.com          # Claude API
registry.npmjs.org         # npm packages (MCP servers)
api.todoist.com            # Todoist MCP server
```

#### Config format

```
# One domain per line. Comments start with #. Empty lines ignored.
# @github fetches IP ranges from api.github.com/meta

@github
api.anthropic.com
registry.npmjs.org
api.todoist.com
```

#### Adding or removing domains

Edit `config/firewall-allowlist.conf` on the host, then apply to running containers:

```bash
# Edit the config
echo "httpbin.org" >> config/firewall-allowlist.conf

# Reload all running containers
./run-claude.sh --reload-firewall
```

The reload performs an atomic ipset swap — no traffic interruption and no window where all traffic is blocked. If a domain fails to resolve, it is skipped with a warning and all other domains still load.

#### `@github` keyword

The special `@github` entry fetches GitHub's published IP ranges from their [meta API](https://api.github.com/meta), aggregates the CIDRs, and adds them to the allowlist. This covers `github.com`, `api.github.com`, `raw.githubusercontent.com`, and other GitHub services.

See [Security Model](docs/SECURITY.md#network-firewall) for why certain domains were removed from the default allowlist.

### Shell alias

Add to `~/.zshrc` or `~/.bashrc`:

```bash
alias dclaude='/path/to/claude-docker/run-claude.sh'
```

Then: `dclaude ~/Projects/my-project` or `dclaude --rebuild ~/Projects/my-project --continue`

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

### "FATAL: Firewall initialization failed"

The iptables firewall requires NET_ADMIN capability. Firewall init failure is now **fatal** — the container will not start without network restrictions in place. If you see this error, check that `--cap-add=NET_ADMIN` is present in the docker run command. With gVisor runtime, the firewall does not work due to gVisor's virtualized network stack — this is expected (use default runc runtime instead).

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

If gVisor is broken, `run-claude.sh` falls back to runc automatically. gVisor is only used when explicitly requested via `--with-gvisor`; the default runtime is runc.

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
| OrbStack | Works | Works |
| Docker Desktop | Permission errors | Works |

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

## Further Reading

- [Security Model](docs/SECURITY.md) — threat model, all hardening layers, known limitations, what we tried and removed, audit methodology
- [Architecture & Development](docs/ARCHITECTURE.md) — internals, entrypoint lifecycle, file reference, contributor guide
- [Security Audit Reports](docs/audit/) — findings and fixes from 11+ audit rounds
