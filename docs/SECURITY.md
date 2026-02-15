# Security Model

For setup instructions, see the [README](../README.md). For architecture and code details, see [Architecture](ARCHITECTURE.md).

## Threat Model

This sandbox defends against an AI agent that may attempt to:

- **Escape the container** — break out via kernel exploits, mount manipulation, namespace abuse, or capability escalation
- **Exfiltrate data** — leak workspace code, credentials, or conversation history via network (HTTP, DNS tunneling, SSH), git push, or workspace file planting
- **Persist beyond the session** — plant malicious files (`.envrc`, hooks, CI configs) that execute when the host opens the project, or poison `~/.claude/` settings and CLAUDE.md for future sessions
- **Escalate privileges or steal credentials** — read other processes' memory, access the macOS keychain, extract OAuth/GitHub tokens, or auto-approve dangerous tool permissions

Each hardening layer below addresses one or more of these threats. Layers are designed to be orthogonal — bypassing one should not compromise the others.

## Hardening Layers

### Container Isolation

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

### Network Firewall

Outbound traffic is restricted to an allowlist of resolved IPs via iptables + ipset. Default policy is DROP with explicit REJECT for immediate feedback.

| Rule | Purpose |
|------|---------|
| **IPv6 completely disabled** | Kernel sysctls `net.ipv6.conf.all.disable_ipv6=1` and `net.ipv6.conf.default.disable_ipv6=1` prevent IPv6 firewall bypass |
| IP allowlist (`config/firewall-allowlist.conf`) | Only resolved IPs from configured domains are reachable (Anthropic API, GitHub, npm registry) |
| **Port restriction: TCP 443/80 only** | ipset rules restrict allowlisted domains to HTTPS (443) and HTTP (80) — prevents exfiltration via non-standard ports |
| DNS pinned to container resolver | All DNS goes through the internal resolver; direct external DNS blocked |
| **DNS blocked for claude user** | All DNS queries from the claude user are dropped. Allowlisted domains are pre-resolved on the host and injected via `--add-host` (`/etc/hosts`). Root retains DNS for ipset population during init. Eliminates DNS tunneling exfiltration entirely. |
| DNS packet size cap: 192 bytes | Defense-in-depth: drops oversized UDP DNS packets (normal queries are <128 bytes) |
| **SSH (port 22) blocked** | Blocked to all destinations including host subnet (R17-02). Prevents raw TCP exfiltration via `github.com:22` (accepts connections without auth). |
| Removed domains | `sentry.io` (arbitrary POST data), `statsig.com`/`statsig.anthropic.com` (arbitrary POST data), VS Code marketplace/blob/update domains (Azure CDN shared IPs — domain fronting risk) |
| `DISABLE_ERROR_REPORTING=1` | Prevents Claude Code from attempting error reports even if allowlist is accidentally widened |
| **Firewall init failure is fatal** | Container exits if firewall initialization fails — cannot start without network restrictions in place |
| Firewall verification | Init verifies a blocked site (`example.com`) is unreachable and an allowed site (`api.github.com`) works as root; also verifies the claude user can reach allowed sites via pre-resolved `/etc/hosts` entries |
| **Cloud metadata endpoints blocked** | `169.254.169.254/32` and `169.254.0.0/16` dropped — prevents credential leakage on cloud VMs (AWS/GCP/Azure instance metadata) |
| **Host subnet allowed** | Docker gateway subnet (e.g. `192.168.1.0/24`) is reachable — needed for Docker gateway and local MCP services; on shared networks this permits LAN-wide access. SSH (22) and Docker API (2375/2376) are blocked to the host subnet. |

**Removed domains** (documented in `config/firewall-allowlist.conf` comments):
- `sentry.io` — accepts arbitrary POST data (exfiltration channel)
- `statsig.com`, `statsig.anthropic.com` — accept arbitrary POST data
- `marketplace.visualstudio.com`, `vscode.blob.core.windows.net`, `update.code.visualstudio.com` — Azure CDN shared IPs (domain fronting risk)

### Git Operations

Two-layer enforcement prevents the AI from using git as an exfiltration or persistence channel.

**Layer 1: `git-guard.so`** (primary enforcement) — an LD_PRELOAD library loaded via `/etc/ld.so.preload` on a read-only rootfs. Cannot be removed or overridden at runtime. Detects when the current process is the real git binary (`/usr/libexec/wrapped-git`) and enforces:

- `git push` blocked unless `/run/sandbox-flags/allow-git-push` exists (root-created flag file)
- `git remote add/set-url/rename` blocked (prevents adding exfiltration targets)
- `git submodule add` blocked (prevents pulling arbitrary repos)
- `git clone --config` with blocked keys rejected (prevents config injection via clone)
- `git credential fill` blocked (prevents trivial token extraction — see credential limitation below)
- **`git config` with dangerous keys blocked** (comprehensive list covering all documented git escape vectors):
  - **Exact keys:** `core.fsmonitor`, `core.sshCommand`, `core.pager`, `core.editor`, `core.hooksPath`, `credential.helper`, `include.path`, `core.gitProxy`, `core.askPass`
  - **Prefix-based blocking:** `url.*` (URL rewriting), `http.*` (proxy/SSL bypass), `remote.*` (remote manipulation), `credential.*` (all credential helper forms), `filter.*`, `alias.*`
  - **Specific diff/merge keys:** `diff.<driver>.textconv`, `diff.<driver>.command`, `merge.<driver>.driver`
  - **Complex patterns:** `includeIf.*.path` (conditional includes)
- **`git -c` and `git --config-env` with blocked keys rejected** — detects both separated (`-c key=value`) and concatenated (`-ckey=value`) forms to prevent flag-level config override
- **Dangerous git environment variables cleared** on every invocation: `GIT_SSH_COMMAND`, `GIT_SSH`, `GIT_EXTERNAL_DIFF`, `GIT_ASKPASS`, `GIT_EDITOR`, `GIT_EXEC_PATH`, `GIT_TEMPLATE_DIR`, `GIT_CONFIG_SYSTEM`, `GIT_PROXY_COMMAND`, `GIT_PAGER`, `GIT_SEQUENCE_EDITOR`, `VISUAL`, `EDITOR`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG`, `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_COMMON_DIR`, `PAGER`, `LESSOPEN`, `LESSCLOSE`
- Command lines >=64KB rejected (prevents bypassing validation via truncation)
- **Argument count overflow blocked** — if args exceed the 256-entry parsing buffer, execution is blocked (prevents pushing blocked keys past the validation boundary)
- Forces `GIT_CONFIG_COUNT=4` environment overrides on every invocation:
  - `core.hooksPath=/dev/null` — neutralizes git hooks
  - `credential.helper=cache --timeout=86400 --socket=/tmp/.git-credential-cache/sock` — pins credential source
  - `core.fsmonitor=false` — prevents filesystem monitor code execution
  - `core.sshCommand=/bin/false` — blocks SSH-based operations
- Root (UID 0) is exempt — entrypoint is trusted init code

**Layer 2: `git-wrapper.sh`** (defense-in-depth) — a 16-line shell wrapper at `/usr/local/bin/git` that force-sets the same `GIT_CONFIG_COUNT` overrides and then execs `/usr/libexec/wrapped-git`. Provides coverage for the narrow case of statically-linked callers that bypass `ld.so.preload`.

**Startup sanitization:** The entrypoint strips dangerous keys from both the workspace `.git/config` and the global gitconfig at startup (all keys/sections listed above, including `filter.*`), then writes a post-sanitization SHA-256 hash for tamper detection. The global gitconfig is locked to `root:root` with mode `444` after setup — the session cannot modify git configuration even via direct file editing.

### Credential Protection

| Mechanism | Details |
|-----------|---------|
| OAuth tokens via `--env-file` | Credentials written to a `chmod 600` temp file, passed via `--env-file` (not `-e`), temp file deleted 2s after launch. Not visible in `ps aux` or `docker inspect`. |
| Entrypoint credential lifecycle | Writes credentials to `~/.claude/.credentials.json` (tmpfs), unsets the env var. Background process attempts to overwrite the file with urandom and delete it after 1s — however, Claude Code may re-create the file, so credentials may persist on tmpfs for the session lifetime. True protection: excluded from sync-back, firewall limits exfiltration targets, tmpfs is ephemeral. |
| GitHub token in memory only | Stored in `git credential-cache` daemon memory (never on disk). Cache socket on `/tmp` (tmpfs), gone when the container exits. `GITHUB_TOKEN` env var unset before the credential cache daemon starts (prevents leaking via `/proc/<pid>/environ`). |
| Token scoped to workspace repo | `credential.https://github.com.useHttpPath=true` + token stored with the workspace repo path — won't serve the token for requests to other repos |
| `--disallow-broad-gh-token` | Rejects `ghp_*` (classic) and `gho_*` (OAuth) tokens at launch. Only fine-grained PATs (`github_pat_*`) accepted. |
| Token format validation | `gh auth token` output validated — strings containing whitespace (error messages) are rejected. GHES tokens with non-standard prefixes are accepted. |
| Credential expiry validation | `expiresAt` field validated as numeric before comparison — prevents script crash on malformed credential data. |

**Security limitation:** The AI agent runs as the same UID as git. Any mechanism that makes the token available to git (credential cache, env vars) also makes it extractable by the AI (e.g., via `net.connect` to the credential cache socket). This is a fundamental same-UID constraint. Fine-grained PATs scoped to the workspace repo limit blast radius.

### Mount Isolation (`~/.claude/`)

Only the files needed for the current session are exposed to the container. `run-claude.sh` creates a **host-side staging directory** (temp dir) containing only the required files, and mounts that at `/mnt/.claude-host:ro`. A writable **tmpfs** (512MB) is mounted at `~/.claude`. At startup, the entrypoint copies data from the staging dir to tmpfs. The staging dir is cleaned up after the container exits.

Staged files (only these are visible inside the container):

- `.config.json`, `settings.json`, `settings.local.json`, `statusline-command.sh`, `CLAUDE.md` (read snapshots)
- `history.jsonl` (for `--continue`/`--resume`)
- Current project's `projects/<path>/` data (memory + transcripts) — **host project path** (`PROJECT_PATH`) is used for encoding to prevent cross-project data leakage (container's `/workspace` encoding is shared across all projects without this)
- `statsig/`, `plugins/`, `plans/`, `todos/`, `stats-cache.json`

NOT exposed: `debug/`, `session-env/`, `file-history/`, `paste-cache/`, `cache/`, other projects' data, config backups, `.DS_Store`, session logs. Host-side staging is used because virtiofs on macOS ignores POSIX permission changes — `chmod 700` on the mount point cannot restrict access.

| Attack | Protection |
|--------|-----------|
| **Settings escalation** — write `{"permissions":{"allow":["Bash(*)"]}}` to `settings.json` | Writes go to tmpfs; `settings.json` is never synced back to host |
| **CLAUDE.md poisoning** — inject malicious instructions into user-level `~/.claude/CLAUDE.md` | Writes go to tmpfs; user-level `CLAUDE.md` is never synced back to host |
| **Plugin injection** — modify host plugins for persistent compromise | Writes go to tmpfs; lost on exit (plugins do sync back by default) |
| **`.config.json` poisoning** — inject `allowedTools`, `mcpServers`, trust dialog overrides into config for future sessions | `.config.json` is never synced back to host (same treatment as `settings.json`). Writes go to tmpfs only. |
| **Cross-project data leakage** — read other projects' memories, sessions, history | Host-side staging copies only the current project's data; other projects' directories are never mounted. `PROJECT_PATH` env var carries host-side path for per-project encoding — sync-back writes to project-specific directory, not shared `-workspace` |

**Sync-back (default: on):** On clean container exit, session artifacts are synced back to the host for continuity (transcripts, memory, plans, history, etc.). Sync-back uses `rsync --no-links` to prevent symlink planting attacks (all symlinks are silently skipped — both absolute and relative). **Project data is relocated** from the container's generic `-workspace` encoding to the host's real project path encoding before sync, preventing cross-project leakage. Multiple files are **never** synced back regardless of settings:

- `settings.json` / `settings.local.json` — prevents tool auto-approval escalation
- `statusline-command.sh` — prevents command injection via status line
- `CLAUDE.md` (user-level) — prevents persistent prompt injection
- `.config.json` / `.config.json.backup.*` — prevents poisoning of `allowedTools`, `mcpServers`, trust dialogs, and other security-relevant config fields that would take effect in future sessions
- `history.jsonl` — excluded from rsync; new entries synced separately via append-only mechanism (prevents overwriting concurrent host-native sessions)
- `.credentials.json`, `.gitconfig`, `entrypoint.log`, `.history-baseline-lines` — internal state files

Use `--no-sync-back` to disable all sync-back. Project-level `/workspace/CLAUDE.md` is unaffected by this protection (writable via the workspace mount).

**Note:** See [Resuming sessions](../README.md#resuming-sessions) for details on cross-context resume and caveats.

### `/proc/<pid>/mem` Protection

Two independent mechanisms prevent the AI from reading other processes' memory (e.g., extracting credentials from the credential cache daemon):

| Layer | How it works |
|-------|-------------|
| `nodump.so` via `/etc/ld.so.preload` (primary) | Constructor calls `prctl(PR_SET_DUMPABLE, 0)` **after** exec completes — making `/proc/<pid>/mem` inaccessible to same-UID processes without CAP_SYS_PTRACE |
| `chmod 711` on `wrapped-git` (belt-and-suspenders) | Non-readable binaries cause the kernel's `would_dump()` to set `dumpable=0` on exec, independent of LD_PRELOAD |

Note: The `claude` binary is excluded from `chmod 711` — it's a Bun single-file executable that must read itself to extract embedded JavaScript. Its `/proc/<pid>/mem` protection comes from `nodump.so` only.

### Privilege Drop

The entrypoint starts as root for setup (mount isolation, firewall, credentials, git config), then drops to UID 501 via `setpriv`:

```
setpriv --reuid=501 --regid=20 --init-groups --inh-caps=-all --bounding-set=-all -- claude
```

After this point: no capabilities in the bounding set, no inheritable caps, `no-new-privileges` prevents regaining them. Core dumps disabled via both hard and soft ulimits (prevents re-enabling). No `sudo` exists in the image.

### Post-Exit Audit

After the container exits, `run-claude.sh` performs a workspace audit on the host:

1. **`.git/config` tamper detection** — compares SHA-256 hash against the entrypoint's post-sanitization baseline (immutable root-owned file, prevents tampering). If modified during the session, **atomic restore via mktemp+mv** (replaces any symlink at the target path, preventing arbitrary host file overwrite), then auto-restores from pre-session backup and re-applies sanitization (strips all git-guard blocked keys/sections).
2. **Interactive hook review** — for each new or modified non-`.sample` file in `.git/hooks/`, shows a content preview (first 15 lines, ANSI-sanitized) and prompts the user to keep or remove it (default: remove). Uses SHA-256 baseline comparison to avoid false positives on pre-existing unchanged hooks.
3. **Dangerous config key scan** — checks `.git/config` for **all git-guard blocked keys** (exact keys, prefix-based sections like `url.*`, `http.*`, `remote.*`, `credential.*`, `filter.*`, `alias.*`, `diff.*`, `merge.*`, `includeIf.*`) as a final safety net.
4. **Suspect file warnings** — detects workspace files **created or modified during the session** that can execute code outside the sandbox or inject persistent prompts: `CLAUDE.md` (prompt injection persistence), `Justfile`, `Taskfile.yml`, `.envrc`, `.vscode/settings.json`, `.vscode/tasks.json`, `Makefile`, `.gitattributes`, `.gitmodules`, `.github/workflows`, `package.json`, `.npmrc`, `.eslintrc.js`, `jest.config.js`, `tsconfig.json`, `setup.py`, `pyproject.toml`, `.pre-commit-config.yaml`, `docker-compose.yml`, and others (50+ patterns). Uses pre/post session SHA-256 comparison — pre-existing unchanged files produce no warning. Output is **sanitized for ANSI escape sequences**.

## Known Limitations

| Severity | Issue | Mitigation |
|----------|-------|-----------|
| **HIGH** | **GitHub token extractable** — AI runs as same UID as git; can `net.connect` to credential cache socket | Use [fine-grained PATs](https://github.com/settings/personal-access-tokens/new) scoped to workspace repo. `--disallow-broad-gh-token` rejects classic/OAuth tokens. |
| **HIGH** | **API endpoint exfiltration** (accepted risk) — `api.anthropic.com` accepts 200K tokens/request (~800KB), `api.github.com` accepts gists/issues/repos, `registry.npmjs.org` accepts `npm publish`, `api.todoist.com` accepts task creation/updates | Inherent to Claude Code operation — cannot function without API access. Mitigations: fine-grained GitHub PATs, session transcript review, `git diff` after sessions. |
| **MEDIUM** | **Workspace write-back** — `/workspace` is writable; session could plant `.envrc`, hooks, CI configs that execute on host | Post-exit audit warns about dangerous files; new/modified git hooks require interactive user approval (default: deny/delete). Review `git diff` after sessions. |
| **LOW** | **History readable** — container receives host `history.jsonl` for `--continue` (current session only; other projects' data not exposed via host-side staging) | HTTPS exfiltration to allowed domains remains possible (accepted risk above). |
| **LOW** | **`.config.json` PII exposure** (accepted risk) — `.config.json` is copied unfiltered into the container, exposing email, account UUIDs, project paths, and usage metrics to the AI agent | Incremental risk — the AI already has access to workspace code. Firewall limits exfiltration targets. `.config.json` is excluded from sync-back to prevent poisoning. |
| **LOW** | **Credential file persists on tmpfs** — `.credentials.json` scrub is best-effort; Claude Code may re-create it after the 1s scrub | Already excluded from sync-back. Firewall limits exfiltration. Tmpfs is ephemeral (gone on exit). |
| **LOW** | **npm/npx execution** — MCP servers rely on npx, which downloads and runs packages from the npm registry | Firewall allowlist limits what can be downloaded. `~/.npm` is mounted with `noexec`. |
| **INFO** | **noexec bypass via interpreter** — `python3 script.py` works on noexec mounts | Fundamental to how interpreters work; the interpreter binary (not the script) is what the kernel executes. |
| **INFO** | **NETLINK sockets allowed** — seccomp allows socket creation (AF_NETLINK) | No capabilities to use them meaningfully (NET_ADMIN/NET_RAW cleared after init). |

## What We Tried and Removed

Honest disclosure of defenses that were found ineffective and replaced or removed:

| What | Why it failed | Replaced with |
|------|--------------|---------------|
| `drop-dumpable.c` (wrapper: set `PR_SET_DUMPABLE=0` then exec git) | Kernel's `would_dump()` in `fs/exec.c` unconditionally resets `dumpable=1` on exec of readable binaries — the flag was overwritten before git even started | `nodump.so` via `/etc/ld.so.preload` — runs **after** exec, inside the new process |
| Shell-level git credential `fill`/`get` blocking | Same-UID bypass: AI can `net.connect` directly to the credential cache socket, making git-level blocks cosmetic | `git credential fill` still blocked by `git-guard.so` (defense-in-depth); acknowledge socket-level limitation openly; recommend fine-grained PATs; add `--disallow-broad-gh-token` |
| 157-line `git-wrapper.sh` with 4-phase validation | Redundant with `git-guard.so` (binary-level enforcement); shell wrapper bypassable via direct `/usr/libexec/wrapped-git` call | 16-line wrapper that only forces `GIT_CONFIG_COUNT` env vars |
| urandom overwrite of credential env vars | Bash doesn't guarantee in-place memory overwrite; process is about to `exec()` anyway | Simple `unset` before exec |
| `sentry.io` in firewall allowlist | Accepts arbitrary POST data — usable as an exfiltration channel | Removed from allowlist + `DISABLE_ERROR_REPORTING=1` |
| `statsig.com`, `statsig.anthropic.com` in allowlist | Accept arbitrary POST data — usable as exfiltration channels | Removed from allowlist |
| VS Code marketplace/blob/update domains in allowlist | Azure CDN shared IPs — domain fronting risk (traffic to allowed IPs could be routed to attacker-controlled origins) | Removed from allowlist |
| `/proc/kallsyms`, `/sys/kernel` bind-mount masking | OrbStack/runc rejects bind-mounts inside `/proc` and `/sys` | Removed; kernel info leaks are low-risk inside a container |
| DNS rate-limiting (1 query/sec) for anti-tunneling | Allowed ~25 B/s exfiltration via subdomain encoding; sufficient for small secrets | Pre-resolve domains on host, inject via `--add-host`, block ALL DNS for claude user |
| `chmod 700` on `/mnt/.claude-host` to restrict access after privilege drop | virtiofs on macOS ignores POSIX permission changes — mount remained readable | Host-side staging: only copy needed files into temp dir, mount that instead |

## OrbStack Kernel Hardening

OrbStack uses a single Linux VM with a shared kernel for all containers and machines. The custom seccomp profile blocks dangerous syscalls at container level; these kernel settings provide a fallback if seccomp is bypassed.

```bash
# Create a lightweight Linux machine (if you don't have one)
orb create ubuntu hardening

# Set kernel hardening parameters (as root)
orb -m hardening -u root sh -c '
  # Restrict ptrace to admin only (defense-in-depth; seccomp already blocks ptrace)
  sysctl -w kernel.yama.ptrace_scope=2

  # Disable unprivileged userfaultfd (defense-in-depth; seccomp already blocks it)
  sysctl -w vm.unprivileged_userfaultfd=0

  # Make persistent across VM restarts
  cat > /etc/sysctl.d/99-claude-sandbox.conf << EOF
kernel.yama.ptrace_scope = 2
vm.unprivileged_userfaultfd = 0
EOF
'
```

**Note:** These are defense-in-depth measures. The custom seccomp profile already blocks `ptrace`, `userfaultfd`, `process_vm_readv/writev`, `perf_event_open`, `memfd_create`, and `memfd_secret` syscalls at the container level. The kernel-level settings provide a fallback if the seccomp profile is ever bypassed. OrbStack may reset kernel parameters on updates — re-run the commands above after OrbStack updates if needed.

These steps are part of the standard [Setup](../README.md#setup).

## Running a Security Audit

How we audit this project:

1. **Launch Claude Code inside the container** with a security audit / red-team prompt
2. **Attempt container escape**, credential extraction, data exfiltration, persistence planting
3. **Review each hardening layer independently** (firewall, git-guard, mount isolation, etc.)
4. **Check for bypasses in git-guard.so** (flag parsing, env var leaks, config key gaps)
5. **Test firewall rules** (IPv6 bypass, DNS tunneling, port scanning, domain fronting)
6. **Test post-exit audit detection** (plant `.envrc`, modify `.git/config`, add hooks)
7. **Document findings** with severity, proof-of-concept, and remediation

Reference: [docs/audit/](audit/) for methodology and findings from 16+ rounds. Reference: [SECURITY-AUDIT-REPORT.md](audit/SECURITY-AUDIT-REPORT.md) for the initial comprehensive audit.
