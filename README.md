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

### Threat model

This sandbox defends against an AI agent that may attempt to:

- **Escape the container** — break out via kernel exploits, mount manipulation, namespace abuse, or capability escalation
- **Exfiltrate data** — leak workspace code, credentials, or conversation history via network (HTTP, DNS tunneling, SSH), git push, or workspace file planting
- **Persist beyond the session** — plant malicious files (`.envrc`, hooks, CI configs) that execute when the host opens the project, or poison `~/.claude/` settings and CLAUDE.md for future sessions
- **Escalate privileges or steal credentials** — read other processes' memory, access the macOS keychain, extract OAuth/GitHub tokens, or auto-approve dangerous tool permissions

Each hardening layer below addresses one or more of these threats. Layers are designed to be orthogonal — bypassing one should not compromise the others.

### Hardening layers

#### Container isolation

| What | Why |
|------|-----|
| Read-only rootfs (`--read-only`) | Prevents modifying system binaries, config, or security libraries (`/etc/ld.so.preload`) |
| Custom seccomp profile | Blocks io_uring, userfaultfd, personality, ptrace, process_vm_readv/writev, perf_event_open, memfd_create/memfd_secret. AF_VSOCK blocked (VM escape vector). Clone namespace flags blocked (CLONE_NEWNS/NEWUTS/NEWIPC/NEWUSER/NEWPID/NEWNET/NEWCGROUP/NEWTIME) |
| All capabilities dropped | Only CHOWN/SETUID/SETGID/SETPCAP (entrypoint setup) and NET_ADMIN/NET_RAW (firewall) retained at launch; bounding set cleared to empty after init |
| `no-new-privileges` | Prevents gaining capabilities via setuid binaries or ambient caps |
| `--init` (tini as PID 1) | Proper signal handling and zombie reaping. PID 1 is root-owned so the AI can't read `/proc/1/mem` |
| Resource limits | `--memory=8g --memory-swap=8g` (no swap), `--pids-limit=4096`, `--shm-size=64m` |
| Unprivileged port binding blocked | `net.ipv4.ip_unprivileged_port_start=1024` prevents binding to privileged ports |
| Setuid/setgid bits stripped | All setuid/setgid binaries have bits removed at build time |
| Namespace tools removed | `nsenter`, `unshare`, `chroot`, `pivot_root` deleted from image |
| Compiler toolchain purged | `gcc`/`libc6-dev` removed after building guard libraries — prevents compiling exploit code or LD_PRELOAD injections at runtime |

#### Network firewall

Outbound traffic is restricted to an allowlist of resolved IPs via iptables + ipset. Default policy is DROP with explicit REJECT for immediate feedback.

| Rule | Purpose |
|------|---------|
| **IPv6 completely disabled** | Kernel sysctls `net.ipv6.conf.all.disable_ipv6=1` and `net.ipv6.conf.default.disable_ipv6=1` prevent IPv6 firewall bypass |
| IP allowlist (`firewall-allowlist.conf`) | Only resolved IPs from configured domains are reachable (Anthropic API, GitHub, npm registry) |
| **Port restriction: TCP 443/80 only** | ipset rules restrict allowlisted domains to HTTPS (443) and HTTP (80) — prevents exfiltration via non-standard ports |
| DNS pinned to container resolver | All DNS goes through the internal resolver; direct external DNS blocked |
| DNS rate limit: 1 query/sec, burst 2 | Anti-tunneling — limits DNS exfiltration to ~25 B/s (sufficient for npm/git/curl, impractical for bulk data) |
| DNS packet size cap: 192 bytes | Drops oversized UDP DNS packets (normal queries are <128 bytes; large packets indicate tunneling payloads) |
| SSH (port 22) blocked | Prevents raw TCP exfiltration via `github.com:22` (accepts connections without auth) |
| Removed domains | `sentry.io` (arbitrary POST data), `statsig.com`/`statsig.anthropic.com` (arbitrary POST data), VS Code marketplace/blob/update domains (Azure CDN shared IPs — domain fronting risk) |
| `DISABLE_ERROR_REPORTING=1` | Prevents Claude Code from attempting error reports even if allowlist is accidentally widened |
| **Firewall init failure is fatal** | Container exits if firewall initialization fails — cannot start without network restrictions in place |
| Firewall verification | Init verifies a blocked site (`example.com`) is unreachable and an allowed site (`api.github.com`) works as root; also verifies the claude user can reach allowed sites through DNS rate limiting |

#### Git operations

Two-layer enforcement prevents the AI from using git as an exfiltration or persistence channel.

**Layer 1: `git-guard.so`** (primary enforcement) — an LD_PRELOAD library loaded via `/etc/ld.so.preload` on a read-only rootfs. Cannot be removed or overridden at runtime. Detects when the current process is the real git binary (`/usr/libexec/wrapped-git`) and enforces:

- `git push` blocked unless `/run/sandbox-flags/allow-git-push` exists (root-created flag file)
- `git remote add/set-url/rename` blocked (prevents adding exfiltration targets)
- `git submodule add` blocked (prevents pulling arbitrary repos)
- **`git config` with dangerous keys blocked** (comprehensive list covering all documented git escape vectors):
  - **Exact keys:** `core.fsmonitor`, `core.sshCommand`, `core.pager`, `core.editor`, `core.hooksPath`, `credential.helper`, `include.path`, `core.gitProxy`, `core.askPass`
  - **Prefix-based blocking:** `url.*` (URL rewriting), `http.*` (proxy/SSL bypass), `remote.*` (remote manipulation), `credential.*` (all credential helper forms), `filter.*`, `alias.*`, `diff.*`, `merge.*`
  - **Complex patterns:** `includeIf.*.path` (conditional includes)
- **`git -c` and `git --config-env` with blocked keys rejected** — detects both separated (`-c key=value`) and concatenated (`-ckey=value`) forms to prevent flag-level config override
- **Dangerous git environment variables cleared** on every invocation: `GIT_SSH_COMMAND`, `GIT_SSH`, `GIT_EXTERNAL_DIFF`, `GIT_ASKPASS`, `GIT_EDITOR`, `GIT_EXEC_PATH`, `GIT_TEMPLATE_DIR`, `GIT_CONFIG_SYSTEM`, `GIT_PROXY_COMMAND`
- Command lines >=64KB rejected (prevents bypassing validation via truncation)
- **Argument count overflow blocked** — if args exceed the 256-entry parsing buffer, execution is blocked (prevents pushing blocked keys past the validation boundary)
- Forces `GIT_CONFIG_COUNT=4` environment overrides on every invocation:
  - `core.hooksPath=/dev/null` — neutralizes git hooks
  - `credential.helper=cache --timeout=86400 --socket=/tmp/.git-credential-cache/sock` — pins credential source
  - `core.fsmonitor=false` — prevents filesystem monitor code execution
  - `core.sshCommand=/bin/false` — blocks SSH-based operations
- Root (UID 0) is exempt — entrypoint is trusted init code

**Layer 2: `git-wrapper.sh`** (defense-in-depth) — a 16-line shell wrapper at `/usr/local/bin/git` that force-sets the same `GIT_CONFIG_COUNT` overrides and then execs `/usr/libexec/wrapped-git`. Provides coverage for the narrow case of statically-linked callers that bypass `ld.so.preload`.

**Startup sanitization:** The entrypoint strips dangerous keys from the workspace `.git/config` at startup (all keys/sections listed above), then writes a post-sanitization SHA-256 hash for tamper detection.

#### Credential protection

| Mechanism | Details |
|-----------|---------|
| OAuth tokens via `--env-file` | Credentials written to a `chmod 600` temp file, passed via `--env-file` (not `-e`), temp file deleted 2s after launch. Not visible in `ps aux` or `docker inspect`. |
| Entrypoint credential lifecycle | Writes credentials to `~/.claude/.credentials.json` (tmpfs), unsets the env var. Background process overwrites the file with urandom and deletes it after 1s — credentials exist on disk for ~1s only. |
| GitHub token in memory only | Stored in `git credential-cache` daemon memory (never on disk). Cache socket on `/tmp` (tmpfs), gone when the container exits. `GITHUB_TOKEN` env var unset before the credential cache daemon starts (prevents leaking via `/proc/<pid>/environ`). |
| Token scoped to workspace repo | `credential.https://github.com.useHttpPath=true` + token stored with the workspace repo path — won't serve the token for requests to other repos |
| `--disallow-broad-gh-token` | Rejects `ghp_*` (classic) and `gho_*` (OAuth) tokens at launch. Only fine-grained PATs (`github_pat_*`) accepted. |
| Token format validation | `gh auth token` output validated — strings containing whitespace (error messages) are rejected. GHES tokens with non-standard prefixes are accepted. |
| Credential expiry validation | `expiresAt` field validated as numeric before comparison — prevents script crash on malformed credential data. |

**Security limitation:** The AI agent runs as the same UID as git. Any mechanism that makes the token available to git (credential cache, env vars) also makes it extractable by the AI (e.g., via `net.connect` to the credential cache socket). This is a fundamental same-UID constraint. Fine-grained PATs scoped to the workspace repo limit blast radius.

#### Mount isolation (`~/.claude/`)

The host's `~/.claude/` is mounted **read-only** at `/mnt/.claude-host` (root-only, `chmod 700`) inside the container. A writable **tmpfs** (512MB) is mounted at `~/.claude`. At startup, the entrypoint (running as root) copies only the data needed for the current session. After privilege drop to UID 501, `/mnt/.claude-host` is inaccessible:

- `.config.json`, `settings.json`, `settings.local.json`, `CLAUDE.md` (read snapshots)
- `history.jsonl` (for `--continue`/`--resume`)
- Current project's `projects/<path>/` data (memory + transcripts) — **host project path** (`PROJECT_PATH`) is used for encoding to prevent cross-project data leakage (container's `/workspace` encoding is shared across all projects without this)
- `statsig/`, `plugins/`, `plans/`, `todos/`, `stats-cache.json`

| Attack | Protection |
|--------|-----------|
| **Settings escalation** — write `{"permissions":{"allow":["Bash(*)"]}}` to `settings.json` | Writes go to tmpfs; `settings.json` is never synced back to host |
| **CLAUDE.md poisoning** — inject malicious instructions into user-level `~/.claude/CLAUDE.md` | Writes go to tmpfs; user-level `CLAUDE.md` is never synced back to host |
| **Plugin injection** — modify host plugins for persistent compromise | Writes go to tmpfs; lost on exit (plugins do sync back by default) |
| **Cross-project data leakage** — read other projects' memories, sessions, history | Host mount at root-only path (`/mnt/.claude-host`), inaccessible after init; only current project data copied. `PROJECT_PATH` env var carries host-side path for per-project encoding — sync-back writes to project-specific directory, not shared `-workspace` |

**Sync-back (default: on):** On clean container exit, session artifacts are synced back to the host for continuity (transcripts, memory, plans, history, etc.). Sync-back uses `rsync --no-links` to prevent symlink planting attacks (all symlinks are silently skipped — both absolute and relative). **Project data is relocated** from the container's generic `-workspace` encoding to the host's real project path encoding before sync, preventing cross-project leakage. Multiple files are **never** synced back regardless of settings:

- `settings.json` / `settings.local.json` — prevents tool auto-approval escalation
- `statusline-command.sh` — prevents command injection via status line
- `CLAUDE.md` (user-level) — prevents persistent prompt injection
- `.credentials.json`, `.gitconfig`, `entrypoint.log`, `.history-baseline-lines` — internal state files

Use `--no-sync-back` to disable all sync-back. Project-level `/workspace/CLAUDE.md` is unaffected by this protection (writable via the workspace mount).

**Note:** `--resume <session-id>` from a *different* project won't work because only the current project's transcripts are copied. Sync-back only fires on clean exit (Ctrl+C, `/exit`, `docker stop`); `docker kill` or OOM kills skip it.

#### `/proc/<pid>/mem` protection

Two independent mechanisms prevent the AI from reading other processes' memory (e.g., extracting credentials from the credential cache daemon):

| Layer | How it works |
|-------|-------------|
| `nodump.so` via `/etc/ld.so.preload` (primary) | Constructor calls `prctl(PR_SET_DUMPABLE, 0)` **after** exec completes — making `/proc/<pid>/mem` inaccessible to same-UID processes without CAP_SYS_PTRACE |
| `chmod 711` on `wrapped-git` (belt-and-suspenders) | Non-readable binaries cause the kernel's `would_dump()` to set `dumpable=0` on exec, independent of LD_PRELOAD |

Note: The `claude` binary is excluded from `chmod 711` — it's a Bun single-file executable that must read itself to extract embedded JavaScript. Its `/proc/<pid>/mem` protection comes from `nodump.so` only.

#### Privilege drop

The entrypoint starts as root for setup (mount isolation, firewall, credentials, git config), then drops to UID 501 via `setpriv`:

```
setpriv --reuid=501 --regid=20 --init-groups --inh-caps=-all --bounding-set=-all -- claude
```

After this point: no capabilities in the bounding set, no inheritable caps, `no-new-privileges` prevents regaining them. Core dumps disabled via both hard and soft ulimits (prevents re-enabling). No `sudo` exists in the image.

#### Post-exit audit

After the container exits, `run-claude.sh` performs a workspace audit on the host:

1. **`.git/config` tamper detection** — compares SHA-256 hash against the entrypoint's post-sanitization baseline (immutable root-owned file, prevents tampering). If modified during the session, **checks for symlink attacks** (prevents arbitrary host file overwrite), then auto-restores from pre-session backup and re-applies sanitization (strips all git-guard blocked keys/sections).
2. **Hook detection** — scans `.git/hooks/` for new non-`.sample` files added during the session. Output is **sanitized for ANSI escape sequences** to prevent terminal injection via crafted filenames.
3. **Dangerous config key scan** — checks `.git/config` for **all git-guard blocked keys** (exact keys, prefix-based sections like `url.*`, `http.*`, `remote.*`, `credential.*`, `filter.*`, `alias.*`, `diff.*`, `merge.*`, `includeIf.*`) as a final safety net.
4. **Suspect file warnings** — detects workspace files **created or modified during the session** that can execute code outside the sandbox: `.envrc`, `.vscode/settings.json`, `.vscode/tasks.json`, `Makefile`, `.gitattributes`, `.gitmodules`, `.github/workflows`. Uses pre/post session SHA-256 comparison — pre-existing unchanged files produce no warning. Output is **sanitized for ANSI escape sequences**.

### What we tried and removed

Honest disclosure of defenses that were found ineffective and replaced or removed:

| What | Why it failed | Replaced with |
|------|--------------|---------------|
| `drop-dumpable.c` (wrapper: set `PR_SET_DUMPABLE=0` then exec git) | Kernel's `would_dump()` in `fs/exec.c` unconditionally resets `dumpable=1` on exec of readable binaries — the flag was overwritten before git even started | `nodump.so` via `/etc/ld.so.preload` — runs **after** exec, inside the new process |
| Shell-level git credential `fill`/`get` blocking | Same-UID bypass: AI can `net.connect` directly to the credential cache socket, making git-level blocks cosmetic | Acknowledge limitation openly; recommend fine-grained PATs; add `--disallow-broad-gh-token` |
| 157-line `git-wrapper.sh` with 4-phase validation | Redundant with `git-guard.so` (binary-level enforcement); shell wrapper bypassable via direct `/usr/libexec/wrapped-git` call | 16-line wrapper that only forces `GIT_CONFIG_COUNT` env vars |
| urandom overwrite of credential env vars | Bash doesn't guarantee in-place memory overwrite; process is about to `exec()` anyway | Simple `unset` before exec |
| `sentry.io` in firewall allowlist | Accepts arbitrary POST data — usable as an exfiltration channel | Removed from allowlist + `DISABLE_ERROR_REPORTING=1` |
| `statsig.com`, `statsig.anthropic.com` in allowlist | Accept arbitrary POST data — usable as exfiltration channels | Removed from allowlist |
| VS Code marketplace/blob/update domains in allowlist | Azure CDN shared IPs — domain fronting risk (traffic to allowed IPs could be routed to attacker-controlled origins) | Removed from allowlist |
| `/proc/kallsyms`, `/sys/kernel` bind-mount masking | OrbStack/runc rejects bind-mounts inside `/proc` and `/sys` | Removed; kernel info leaks are low-risk inside a container |

### Known limitations

| Severity | Issue | Mitigation |
|----------|-------|-----------|
| **HIGH** | **GitHub token extractable** — AI runs as same UID as git; can `net.connect` to credential cache socket | Use [fine-grained PATs](https://github.com/settings/personal-access-tokens/new) scoped to workspace repo. `--disallow-broad-gh-token` rejects classic/OAuth tokens. |
| **HIGH** | **API endpoint exfiltration** (accepted risk) — `api.anthropic.com` accepts 200K tokens/request (~800KB), `api.github.com` accepts gists/issues/repos, `registry.npmjs.org` accepts `npm publish` | Inherent to Claude Code operation — cannot function without API access. Mitigations: fine-grained GitHub PATs, session transcript review, `git diff` after sessions. |
| **MEDIUM** | **Workspace write-back** — `/workspace` is writable; session could plant `.envrc`, hooks, CI configs that execute on host | Post-exit audit warns about dangerous files. Review `git diff` after sessions. |
| **LOW** | **DNS tunneling** — ~25 B/s at 1 query/sec with 192-byte packet cap | Impractical for bulk exfiltration. Rate limiting + size cap reduce throughput to levels unsuitable for code/credential theft. |
| **LOW** | **History readable** — container receives host `history.jsonl` for `--continue` | DNS rate limiting makes exfiltration impractical (~25 B/s). |
| **LOW** | **npm/npx execution** — MCP servers rely on npx, which downloads and runs packages from the npm registry | Firewall allowlist limits what can be downloaded. `~/.npm` is mounted with `noexec`. |
| **INFO** | **noexec bypass via interpreter** — `python3 script.py` works on noexec mounts | Fundamental to how interpreters work; the interpreter binary (not the script) is what the kernel executes. |
| **INFO** | **NETLINK sockets allowed** — seccomp allows socket creation (AF_NETLINK) | No capabilities to use them meaningfully (NET_ADMIN/NET_RAW cleared after init). |

## Firewall Configuration

The container's outbound network allowlist is defined in `firewall-allowlist.conf` in the project directory. The file is bind-mounted read-only into the container — Claude cannot modify it.

### Default allowlist

```
@github                    # GitHub IPs (fetched from api.github.com/meta)
api.anthropic.com          # Claude API
registry.npmjs.org         # npm packages (MCP servers)
api.todoist.com            # Todoist MCP server
```

**Removed domains** (documented in `firewall-allowlist.conf` comments):
- `sentry.io` — accepts arbitrary POST data (exfiltration channel)
- `statsig.com`, `statsig.anthropic.com` — accept arbitrary POST data
- `marketplace.visualstudio.com`, `vscode.blob.core.windows.net`, `update.code.visualstudio.com` — Azure CDN shared IPs (domain fronting risk)

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
- `--disallow-broad-gh-token` — Reject broad-scope GitHub tokens (`ghp_*`/`gho_*`). Only fine-grained PATs (`github_pat_*`) accepted.
- `--reload-firewall` — Reload `firewall-allowlist.conf` in all running containers

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

### Git push from the container

**`git push` is blocked by default** to prevent data exfiltration through the project repo. To enable it, pass `--allow-git-push`:

```bash
./run-claude.sh --allow-git-push ~/Projects/my-project
```

When enabled, the sandbox extracts your GitHub token from the host's `gh` CLI and configures `git credential-cache` inside the container. The token lives in the credential-cache daemon's memory (never on disk). The cache socket resides on `/tmp` (tmpfs), gone when the container exits. The `GITHUB_TOKEN` env var is unset before the credential cache daemon starts (prevents leaking via `/proc/<pid>/environ`).

The token is scoped to the workspace repo via `useHttpPath` — it won't be served for requests to other repos. `git remote add/set-url/rename` is always blocked (prevents adding exfiltration targets), and dangerous `git config` keys are blocked at the binary level.

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
│   2. Write to temp file, pass via --env-file         │
│   3. Launch container with hardened flags             │
│   4. Post-exit: sync-back merge + workspace audit    │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │ OrbStack VM (Linux kernel boundary)            │  │
│  │  ┌──────────────────────────────────────────┐  │  │
│  │  │ Docker Container                         │  │  │
│  │  │  Read-only rootfs + seccomp + no caps    │  │  │
│  │  │  iptables allowlist (DNS rate-limited)   │  │  │
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
│  │  │   /mnt/.claude-host← ~/.claude (ro,700)  │  │  │
│  │  │   ~/.claude        ← tmpfs (rw, 512m)    │  │  │
│  │  │   /tmp             ← tmpfs (noexec,512m) │  │  │
│  │  │   ~/.npm           ← tmpfs (noexec,256m) │  │  │
│  │  │   ~/.config        ← tmpfs (64m)         │  │  │
│  │  │   /dev/shm         ← 64m                 │  │  │
│  │  │                                          │  │  │
│  │  │  Credential flow:                        │  │  │
│  │  │   --env-file (tmpfile, deleted 2s)       │  │  │
│  │  │     → ~/.claude/.credentials.json        │  │  │
│  │  │     → env var unset, file scrubbed (1s)  │  │  │
│  │  └──────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

### Entrypoint lifecycle

1. **Mount isolation** — copy session data from read-only host mount (`/mnt/.claude-host`) to writable tmpfs (`~/.claude`). Uses `cp -P` (no symlink dereferencing). Project data loaded using host-side `PROJECT_PATH` encoding for per-project isolation.
2. **Push flag** — create `/run/sandbox-flags/allow-git-push` if `--allow-git-push` was passed (root-owned, immutable after privilege drop)
3. **Firewall** — initialize iptables allowlist, IPv6 disable, port restrictions (443/80), DNS rate limiting, SSH blocking, connectivity verification. **Firewall init failure is fatal** — container exits if network restrictions cannot be established.
4. **Credentials** — write OAuth tokens to file, schedule background scrub (urandom overwrite + delete after 1s)
5. **Git config** — build global gitconfig from host (`~/.gitconfig` mount guarded — only mounted if file exists on host), strip host credential helpers, set `core.hooksPath=/dev/null`
6. **Git config sanitization** — strip dangerous keys from workspace `.git/config` (all git-guard blocked keys/sections), write post-sanitization SHA-256 hash to **immutable root-owned file** (`chmod 444`, prevents tampering with tamper detection baseline)
7. **GitHub credentials** — feed token into `git credential-cache` (memory-only), scoped to workspace repo via `useHttpPath`
8. **Privilege drop** — `setpriv` to UID 501 with empty bounding set and no inheritable capabilities. When sync-back is enabled, child process is waited on SIGTERM to prevent sync-back racing with still-running child.

### Post-exit lifecycle

1. **Sync-back** — rsync session artifacts from container staging dir to host `~/.claude/` (if enabled). Uses `--no-links` (skips all symlinks). Project data relocated from `-workspace` to host-encoded path before sync. Excludes `settings.json`, `settings.local.json`, `statusline-command.sh`, `CLAUDE.md`, `.credentials.json`, `.gitconfig`, `entrypoint.log`, `.history-baseline-lines`.
2. **`.git/config` tamper detection** — compare SHA-256 hash against immutable post-sanitization baseline; **check for symlink attacks** before restore (prevents arbitrary host file overwrite); auto-restore from pre-session backup and re-apply full sanitization if modified
3. **Hook detection** — warn about new non-`.sample` files in `.git/hooks/`. **ANSI escape sequences sanitized** to prevent terminal injection.
4. **Dangerous config scan** — check `.git/config` for **all git-guard blocked keys** (comprehensive coverage of exact keys and prefix-based sections)
5. **Suspect file warnings** — detect `.envrc`, `.vscode/settings.json`, `.vscode/tasks.json`, `Makefile`, `.gitattributes`, `.gitmodules`, `.github/workflows` that were **created or modified** during the session (pre/post SHA-256 comparison). **ANSI escape sequences sanitized**.

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

## File Reference

- **Dockerfile** — Debian Bookworm slim base, Claude Code native binary, guard library compilation, `setpriv` for privilege drop
- **entrypoint.sh** — Mount isolation (host state copy), firewall init, credential lifecycle, git config sanitization, sync-back trap, privilege drop
- **run-claude.sh** — Host launcher: keychain extraction, token refresh, image build, hardened container launch, post-exit workspace audit, sync-back merge
- **init-firewall.sh** — iptables chain setup, DNS rate limiting (1/sec burst 2, 192-byte cap), SSH blocking, ipset creation, connectivity verification
- **reload-firewall.sh** — Reads `firewall-allowlist.conf`, resolves domains, fetches GitHub IPs, atomic ipset swap
- **firewall-allowlist.conf** — Configurable domain allowlist for the container firewall
- **seccomp-profile.json** — Custom seccomp allowlist (Docker default minus ptrace, process_vm, perf_event, memfd, io_uring, userfaultfd, personality; AF_VSOCK blocked; clone namespace flags including CLONE_NEWTIME blocked)
- **git-guard.c** — LD_PRELOAD library enforcing git operation restrictions (push, remote, submodule, config key blocking, `GIT_CONFIG_COUNT` forcing). Loaded via `/etc/ld.so.preload` on read-only rootfs.
- **git-wrapper.sh** — Shell wrapper forcing `GIT_CONFIG_COUNT` on every git invocation (defense-in-depth for statically-linked callers)
- **nodump.c** — LD_PRELOAD library setting `PR_SET_DUMPABLE=0` after exec (prevents `/proc/<pid>/mem` access)
- **lint.sh** — Runs Hadolint on Dockerfile via Docker
- **.githooks/pre-commit** — Runs lint on commit; enable with `git config core.hooksPath .githooks`
