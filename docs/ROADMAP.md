# Roadmap

## Copy-Based Workspace Isolation (`--copy-workspace`)

**Status:** Planned
**Priority:** High — closes the last filesystem bridge between container and host

### Problem

On macOS, Docker containers already run inside a Linux VM (OrbStack uses
Virtualization.framework, Docker Desktop uses HyperKit/QEMU). The current
attack path is:

```
AI agent → container escape → OrbStack Linux VM → VM escape → macOS host
```

That's two boundaries — more than Docker Sandboxes (which use one VM, no
container hardening inside). However, the workspace bind mount
(`-v "$PROJECT_DIR":/workspace`) is a virtiofs passthrough from macOS through
the VM into the container. If the agent escapes the container, it lands in
the OrbStack VM with **direct filesystem access** to the host workspace via
virtiofs. This is the bridge that Docker Sandboxes eliminate by using
file-copy sync instead of mounts.

We already use copy-based isolation for `~/.claude` (host-side staging,
read-only mount, tmpfs overlay, sync-back on exit). The workspace is the
remaining virtiofs bridge.

### Comparison: Docker Sandboxes vs. claude-docker

As of February 2026, Docker AI Sandboxes
(https://docs.docker.com/ai/sandboxes/) use microVMs with:

- **Hypervisor isolation**: One VM per sandbox (Virtualization.framework on
  macOS, Hyper-V on Windows). Separate kernel per sandbox.
- **File sync, not mounts**: Workspace is copied between host and VM via
  bidirectional sync. No virtiofs bridge.
- **HTTP/HTTPS proxy filtering**: Traffic routes through
  `host.docker.internal:3128` with hostname-based allow/deny rules. MITM TLS
  termination. Raw TCP/UDP blocked.
- **Private Docker daemon**: Full Docker-in-Docker inside the VM, isolated
  from host.
- **Default network blocks**: RFC 1918 ranges, localhost, link-local, cloud
  metadata.

What Docker Sandboxes **don't** have (and we do):

| Layer | Docker Sandboxes | claude-docker |
|-------|-----------------|---------------|
| Capability dropping | Not documented (VM makes it less critical) | ALL dropped, bounding set cleared after init |
| Seccomp | Not documented | Custom allowlist, ptrace blocked |
| Git hardening | None | git-guard.so, .git/config immutable, hooks neutralized, credential.helper forced |
| Post-exit audit | None | .git/config tamper detection + auto-restore, hook review, 40+ suspect file checks |
| Credential handling | Not documented | Keychain extraction, env scrub, file scrub, sync-back exclusion, auto-refresh |
| Process hardening | VM boundary only | no-new-privileges, nodump.so, core dumps disabled, setuid stripped |
| Config poisoning prevention | Bidirectional sync (no exclusions documented) | settings.json, .config.json, CLAUDE.md never synced back |
| Resource limits | Not documented | 8GB memory, 4096 pids, 512MB tmpfs |
| Filesystem | Bidirectional sync (no audit) | Read-only rootfs, read-only host mount, tmpfs, host-side staging |

**Bottom line**: Docker Sandboxes rely on the VM boundary as the primary (and
mostly only) defense. We have 15+ independent layers but the virtiofs
workspace mount weakens the VM boundary we already get from OrbStack.
Closing the workspace bridge would make our solution strictly stronger.

### Proposed Solution

Add a `--copy-workspace` flag that replaces the bind mount with copy-in at
start and copy-out on exit, using the same pattern as `~/.claude` isolation.

#### Startup (copy-in)

1. Create a temp directory or tmpfs for the workspace copy
2. `rsync -a` (or `cp -a`) the project directory into it
3. Mount the **copy** into the container instead of the original:
   ```
   -v "$WORKSPACE_COPY":/workspace
   ```
   Or even: copy into the container's filesystem (no mount at all)
4. The original project directory is never exposed to the container/VM

#### Shutdown (copy-out)

1. On container exit, diff the workspace copy against the original
2. Present a summary of changes (files created/modified/deleted)
3. Apply changes back to the original workspace (rsync, with exclusions)
4. The post-exit audit (hooks, suspect files, .git/config) runs **before**
   applying changes, so the user can reject the whole batch

#### What this changes

- **No virtiofs bridge**: Even if the agent escapes the container into the
  OrbStack VM, the host workspace isn't mounted. The VM has no filesystem
  path to the host project.
- **Atomic workspace changes**: Changes aren't visible on the host until the
  session ends and the user approves. Good for unsupervised runs.
- **Post-exit audit becomes a gate**: Currently the audit warns but changes
  are already on disk. With copy-workspace, the audit runs on the copy before
  anything touches the host.

#### Trade-offs

- **No real-time visibility**: Host-side editors/IDEs won't see changes until
  sync-back. Unusable for interactive pair-programming where you watch the
  agent edit files.
- **Startup cost**: Copying large repositories takes time. Mitigations:
  rsync with `--exclude=node_modules --exclude=.git/objects` (or let the user
  configure exclusions), or use `--copy-workspace=shallow` to skip large
  directories.
- **Disk usage**: Temporary copy doubles disk usage for the project duration.
- **Git state**: `.git` directory needs special handling. Options:
  - Copy `.git` too (full clone, large for big repos)
  - Share `.git` read-only and use a worktree (complex)
  - Copy workspace files only, init a fresh git repo in the container (loses
    history, breaks `git diff`, `git log`)

#### Recommended approach for `.git`

Copy the full `.git` directory. Yes it's large for big repos, but:
- The agent needs `git diff`, `git log`, `git blame` to work
- Our `.git/config` sanitization already handles the security concerns
- The copy-out step can skip `.git` entirely (only sync workspace files back)
- `.git/hooks` in the copy are neutralized by the entrypoint (core.hooksPath=/dev/null)

#### UX design

```
# Interactive (current default) — bind mount, real-time visibility
./run-claude.sh ~/Projects/my-project

# Unsupervised — copy-based, changes applied on exit after review
./run-claude.sh --copy-workspace ~/Projects/my-project

# Unsupervised with auto-apply (skip review, trust the audit warnings)
./run-claude.sh --copy-workspace --auto-apply ~/Projects/my-project
```

On exit with `--copy-workspace`:
```
[sandbox] Session ended. Reviewing workspace changes...
[sandbox] 12 files modified, 3 files created, 1 file deleted
[sandbox] WARNING: New git hook detected: .git/hooks/pre-commit (BLOCKED — not synced)
[sandbox] WARNING: Suspect file modified: Makefile
[sandbox] Apply changes to ~/Projects/my-project? [y/N]:
```

### Implementation Sketch

#### run-claude.sh changes

1. Add `--copy-workspace` and `--auto-apply` flag parsing
2. When `--copy-workspace`:
   - Create `WORKSPACE_COPY=$(mktemp -d)`
   - `rsync -a "$PROJECT_DIR/" "$WORKSPACE_COPY/"` (with configurable exclusions)
   - Replace `-v "$PROJECT_DIR":/workspace` with `-v "$WORKSPACE_COPY":/workspace`
   - On exit: run post-exit audit on `$WORKSPACE_COPY`, prompt user, then
     `rsync -a` approved changes back to `$PROJECT_DIR`
   - Clean up `$WORKSPACE_COPY`

3. The `.git/config` snapshot/restore and suspect file audit already work on
   `$PROJECT_DIR` — these need to be adapted to compare `$WORKSPACE_COPY`
   against `$PROJECT_DIR` instead.

4. Sync-back of `~/.claude` data works unchanged (separate mechanism).

#### entrypoint.sh changes

None expected. The entrypoint doesn't know or care whether `/workspace` is a
bind mount or a copy — it's just a directory.

#### Post-exit audit changes

The audit currently operates on `$PROJECT_DIR` (the live workspace). With
`--copy-workspace`, it should:
1. Run on `$WORKSPACE_COPY` (detect what the agent did)
2. Block sync-back of `.git/hooks` (new or modified hooks never reach host)
3. Present suspect file changes as a diff, not just a warning
4. Only apply clean changes after user approval

### Open Questions

1. **Large repo performance**: Should we support `--copy-workspace=shallow`
   that skips `.git/objects` and large vendored directories? What's the
   startup cost for a 1GB+ repo?

2. **Incremental sync**: For repeated sessions on the same project, could we
   keep the workspace copy around (named temp dir or volume) and rsync
   incrementally? This would speed up startup but introduces state.

3. **Interaction with `--isolate-claude-data`**: The `--isolate-claude-data`
   flag already uses a named volume for `~/.claude`. Should `--copy-workspace`
   imply `--isolate-claude-data`? Or are they orthogonal?

4. **File watching**: Could we run a background fswatch/inotify to provide
   near-real-time visibility of changes (read-only stream to the host) without
   the virtiofs bridge? This would recover some of the interactive UX.

5. **Default for unsupervised**: Should `-p` (prompt mode) imply
   `--copy-workspace` since it's inherently non-interactive?

---

## Short-Lived GitHub Tokens via GitHub App

**Status:** Planned
**Priority:** Medium — reduces blast radius of GitHub token exposure

### Problem

The AI agent runs as the same UID that holds the GitHub token. Any process
running as `claude` can extract the token via `git credential fill`. Today we
mitigate this with:

- Fine-grained PAT scoped to the workspace repo (`useHttpPath=true`)
- Firewall limiting where the token can be sent
- `--disallow-broad-gh-token` rejecting `ghp_*`/`gho_*` tokens

But a fine-grained PAT is still long-lived (days to months). If exfiltrated
via an accepted channel (GitHub Markdown API at ~600KB/hour, commit message,
branch name), the token remains valid long after the session ends.

### Why Not a Proxy-Based Credential Helper?

An earlier idea was to build a root-owned daemon that injects the token into
git operations without the agent ever seeing it. This was rejected because:

1. **The firewall already covers in-session risk.** During the session, the
   agent can read the token but can only send it to allowlisted endpoints.
   The proxy prevents reading — but what would the agent do with the token
   that the firewall doesn't already block?
2. **The real risk is post-session.** If the token is exfiltrated via an
   accepted channel, a long-lived PAT remains valid. A proxy doesn't help
   after the session ends.
3. **Custom daemon = custom bugs.** A root-owned daemon with a Unix socket
   is new attack surface. GitHub App installation tokens are a standard
   GitHub feature, battle-tested.

### Proposed Solution: GitHub App Installation Tokens

Replace long-lived PATs with short-lived GitHub App installation tokens
(≤1 hour TTL). Even if exfiltrated, the token is dead before anyone can
use it.

#### How GitHub App tokens work

1. Create a GitHub App with minimal permissions (e.g., `contents: write`
   for the target repo only)
2. Install it on the target repository/organization
3. At runtime, use the App's private key to generate a short-lived
   installation token via GitHub's API
4. The token expires in ≤1 hour and is scoped to the repos the App is
   installed on

#### Integration with run-claude.sh

```bash
# Instead of:
GH_TOKEN=$(gh auth token 2>/dev/null || true)

# With GitHub App:
if [ -n "$GITHUB_APP_ID" ] && [ -f "$GITHUB_APP_PRIVATE_KEY" ]; then
    GH_TOKEN=$(generate-installation-token \
        "$GITHUB_APP_ID" \
        "$GITHUB_APP_PRIVATE_KEY" \
        "$GITHUB_APP_INSTALLATION_ID")
    log "[sandbox] GitHub token: short-lived installation token (≤1h TTL)"
else
    GH_TOKEN=$(gh auth token 2>/dev/null || true)
    # ... existing PAT validation ...
fi
```

The `generate-installation-token` helper would:
1. Create a JWT signed with the App's private key
2. Call `POST /app/installations/{id}/access_tokens` to get an installation token
3. Output the token (short-lived, scoped)

This can be done with `openssl` + `curl` (no external dependencies) or via
the `gh` CLI if it supports GitHub App auth.

#### Configuration

New flags or environment variables:

```bash
./run-claude.sh \
    --github-app-id 12345 \
    --github-app-key ~/.config/github-app/private-key.pem \
    --github-app-installation-id 67890 \
    ~/Projects/my-project
```

Or via environment:
```bash
export GITHUB_APP_ID=12345
export GITHUB_APP_PRIVATE_KEY_PATH=~/.config/github-app/private-key.pem
export GITHUB_APP_INSTALLATION_ID=67890
./run-claude.sh ~/Projects/my-project
```

#### What this achieves

| | Long-lived PAT (today) | GitHub App token |
|---|---|---|
| TTL | Days to months | ≤1 hour |
| Scope | User-configured | App installation (repos) |
| Post-exfiltration risk | High — valid until rotated | None — expired |
| Revocation | Manual | Automatic (expiry) |
| Audit | GitHub token log | GitHub App audit log |
| Setup complexity | Low (create PAT) | Medium (create App, install, configure) |

#### Fallback

The existing PAT flow remains the default. GitHub App tokens are opt-in for
users who want stronger guarantees. The `--disallow-broad-gh-token` flag
continues to work for PAT-only setups.

### Credential Landscape Summary

| Credential | Can agent read it? | Current mitigation | Can we vault/short-live it? |
|---|---|---|---|
| Claude Code OAuth access token | Yes (`.credentials.json`) | ~1h TTL already, firewall, tmpfs | No — Anthropic controls auth flow |
| Claude Code OAuth refresh token | Yes (`.credentials.json`) | Firewall, tmpfs, sync-back exclusion | **Yes — stripped at injection, sidecar refreshes access token** |
| GitHub token | Yes (`git credential fill`) | Repo-scoped, firewall | **Yes — GitHub App tokens (this item)** |
| MCP OAuth tokens (Todoist, etc.) | Yes (`.credentials.json`) | Firewall, tmpfs | No — managed by Claude Code |
| Workspace secrets (`.env`, etc.) | Yes (workspace mount) | Firewall; `--copy-workspace` would help | Yes — use vault references on host, resolve before mount |

The irreducible problem: the Claude Code OAuth tokens (access + refresh) and
MCP tokens live in `.credentials.json` which Claude Code itself re-creates
after any scrub attempt (R13-02). The agent will always be able to read its
own operational credentials. The firewall is the primary defense against
exfiltration of these tokens.

### Open Questions

1. **Token generation without Vault**: A simple shell script using `openssl`
   and `curl` can generate GitHub App installation tokens. Is that sufficient,
   or should we support Vault's GitHub secrets engine as well for teams that
   already use Vault?

2. **Private key storage**: The GitHub App private key is a high-value secret
   on the host. It should be in the macOS keychain or a file with 600
   permissions, never in the project directory. Should `run-claude.sh`
   support reading it from the keychain?

3. **Installation ID discovery**: Can we auto-detect the installation ID
   from the repo's remote URL + the App ID, or must the user provide it?
   The GitHub API supports listing installations, which could automate this.

4. **Multiple repos**: If the user works across multiple repos, do they need
   one App installation per repo, or can a single installation cover an
   organization?

---

## Anthropic Token Refresh: Strip + Host-Side Sidecar

**Status:** Implemented
**Priority:** High — removes long-lived refresh token from container,
enables sessions >1 hour

### Problem

The Anthropic OAuth refresh token (`sk-ant-ort01-...`) is injected into
the container but is completely useless there — the refresh endpoint
(`console.anthropic.com`) is not in the firewall allowlist (and shouldn't
be — it would be an exfiltration channel). The refresh token is long-lived
and single-use, making it both high-value and dangerous if consumed
accidentally.

Sessions are limited to the access token TTL (~1 hour). When the token
expires mid-session, Claude Code tries to refresh using the refresh token,
fails (endpoint unreachable), and the user must restart.

### Solution

Two parts:

**Part 1: Strip the Anthropic refresh token before injection.**
On the host, before writing credentials to the env file, set
`claudeAiOauth.refreshToken` to `""`. Only the Anthropic refresh token
is stripped — MCP refresh tokens are kept (see below).

**Part 2: Host-side sidecar for proactive refresh.**
A background process on the host that:
1. Sleeps ~50 minutes (access token TTL minus buffer)
2. Uses the keychain's refresh token to call
   `POST https://console.anthropic.com/v1/oauth/token` with
   `client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e`
3. Updates the keychain with the new access + refresh tokens
   (refresh tokens are single-use — the old one is invalidated)
4. Uses `docker exec` to update `accessToken` and `expiresAt` in
   the container's `.credentials.json`

### Risk: Claude Code in-memory caching

Claude Code may cache the access token in memory and not re-read
`.credentials.json` after the docker exec update. If testing confirms
this, the sidecar still keeps the keychain fresh (faster restarts)
but can't extend sessions beyond ~1 hour without a Claude Code
code change or signal-based refresh trigger.

---

## MCP OAuth Token Refresh Strategy

**Status:** Analysis complete, no action needed now
**Priority:** Low — current behavior is acceptable

### Analysis

MCP OAuth tokens (Todoist, Granola, etc.) are stored alongside the
Anthropic OAuth token in the same keychain blob (`Claude Code-credentials`).
They are injected into the container as part of `.credentials.json`.

Unlike the Anthropic refresh token, MCP refresh tokens have a fundamentally
different situation:

| Aspect | Anthropic OAuth | MCP OAuth (Todoist, etc.) |
|--------|----------------|--------------------------|
| Refresh endpoint in allowlist? | No (`console.anthropic.com`) | Some yes (`api.todoist.com`), some no |
| Can host sidecar refresh? | Yes — known endpoint + client_id | No — each provider has unknown OAuth params |
| Claude Code self-refresh? | No (endpoint blocked) | Yes (for allowlisted providers) |
| What if we strip refresh token? | No impact (can't refresh anyway) | Breaks MCP for services with reachable endpoints |

### Decision: Keep MCP refresh tokens

MCP refresh tokens are NOT stripped because:

1. **Some MCP OAuth endpoints are reachable** — `api.todoist.com` is in the
   firewall allowlist, so Claude Code can self-refresh Todoist tokens inside
   the container. Stripping would break this.
2. **We can't refresh them from the host** — each MCP provider has different
   OAuth endpoints, client_ids, and scopes. The host sidecar doesn't know
   these parameters.
3. **The firewall already limits exposure** — MCP refresh tokens can only be
   sent to allowlisted endpoints (their legitimate providers).
4. **MCP tokens are ephemeral** — they live on tmpfs, excluded from sync-back,
   lost on container exit.

### Future consideration

If we want to strip MCP refresh tokens in the future (to reduce exposure),
we would need:
- A registry of MCP OAuth endpoints and client_ids per provider
- The host sidecar to refresh each MCP token alongside the Anthropic token
- This is complex and provider-specific — not worth pursuing unless a
  specific MCP provider becomes a security concern

Alternatively, the `--copy-workspace` feature (if implemented) combined
with the firewall makes MCP token exposure a minimal risk — the tokens
can only reach their intended providers and are lost on exit.

---

## Landlock Kernel Enforcement + Workspace Snapshots

**Status:** Planned
**Priority:** Medium — adds kernel-enforced filesystem boundaries inside the
container, orthogonal to all existing layers

### Problem

Our current filesystem restrictions are user-space conventions: the container
runs with a read-only rootfs, `/workspace` is a bind mount, and `~/.claude`
is a tmpfs. But the `claude` process (UID 1000) has no **kernel-enforced**
restriction on which paths it can access. If the agent finds a writable path
we didn't anticipate (a new tmpdir, a proc/sys leak, a mount escape), nothing
at the kernel level says "you can only touch `/workspace`, `~/.claude`, and
`/tmp`."

Similarly, the agent can `rm -rf /workspace/*` — there is no distinction
between "write a file" and "delete everything." The damage is instant and
irreversible within the session.

Finally, we audit the workspace **after** the session ends, but we don't
capture a pre-session baseline. If the agent modifies a file and then reverts
it, the post-exit audit sees no diff — but the agent may have exfiltrated
the original content.

### Inspiration: nono.sh

[nono.sh](https://nono.sh/) is a kernel-enforced capability sandbox for AI
agents that uses Landlock (Linux) and Seatbelt (macOS) to restrict filesystem
access at the syscall level. Key ideas from nono.sh that are relevant:

- **Landlock LSM for path restrictions**: Processes self-sandbox by declaring
  which paths they can access and what operations are permitted (read, write,
  execute, delete). The kernel enforces this — no user-space bypass possible.
- **Write-without-delete**: Landlock v2+ can grant `LANDLOCK_ACCESS_FS_WRITE_FILE`
  without `LANDLOCK_ACCESS_FS_REMOVE_FILE` / `LANDLOCK_ACCESS_FS_REMOVE_DIR`.
  The agent can create and modify files but cannot delete them.
- **Pre-execution snapshots**: Capture workspace state before the agent runs,
  enabling clean rollback.

nono.sh applies these at the **host level** (sandboxing the AI process
directly on macOS/Linux). We apply them **inside a container** — different
context, but the same Landlock syscalls are available in our container's
Linux kernel.

### Key Finding: Landlock Syscalls Already Allowed

Our custom seccomp profile already permits the three Landlock syscalls:

| Syscall | Number | Purpose |
|---------|--------|---------|
| `landlock_create_ruleset` | 444 | Create a new Landlock ruleset |
| `landlock_add_rule` | 445 | Add a path rule to the ruleset |
| `landlock_restrict_self` | 446 | Apply the ruleset to the calling process |

These are in the default Docker seccomp allowlist and pass through our custom
profile. No seccomp changes are needed.

### Proposed Solution: Three Layers

#### Layer 1: Landlock Filesystem Enforcement

A new shared library (`landlock-enforce.so`) loaded via `/etc/ld.so.preload`,
following the same pattern as `nodump.so` (disables core dumps) and
`git-guard.so` (blocks git config writes). The library's `__attribute__((constructor))`
function runs before `main()` and applies a Landlock ruleset.

**Allowed paths and access rights:**

| Path | Read | Write | Execute | Delete |
|------|------|-------|---------|--------|
| `/workspace` | Yes | Yes | No | Configurable (see Layer 2) |
| `~/.claude` (tmpfs) | Yes | Yes | No | Yes |
| `/tmp` | Yes | Yes | No | Yes |
| `/` (everything else) | Yes | No | No | No |

After `landlock_restrict_self()`, the kernel enforces these rules for the
process and all children. Even if the agent spawns a shell or binary, the
restrictions are inherited and cannot be lifted.

**Implementation sketch:**

```c
// landlock-enforce.c — loaded via /etc/ld.so.preload
#include <linux/landlock.h>
#include <sys/syscall.h>

__attribute__((constructor))
static void enforce_landlock(void) {
    // Skip if not the claude process (check /proc/self/exe or UID)
    if (getuid() != 1000) return;

    struct landlock_ruleset_attr attr = {
        .handled_access_fs =
            LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_REMOVE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_REG |
            LANDLOCK_ACCESS_FS_MAKE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_SYM,
    };

    int ruleset_fd = syscall(SYS_landlock_create_ruleset,
                             &attr, sizeof(attr), 0);
    if (ruleset_fd < 0) return;  // Kernel doesn't support Landlock — degrade gracefully

    // Add rules for /workspace (write + create, no delete)
    add_path_rule(ruleset_fd, "/workspace",
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_MAKE_SYM);

    // Add rules for ~/.claude, /tmp (full write + delete)
    add_path_rule(ruleset_fd, "/home/claude/.claude",
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_DIR);

    // Apply — irreversible for this process and all children
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    syscall(SYS_landlock_restrict_self, ruleset_fd, 0);
    close(ruleset_fd);
}
```

**Graceful degradation**: If the kernel doesn't support Landlock (pre-5.13,
or the LSM isn't enabled), the constructor returns silently. All other
layers remain active. This makes it safe to add without breaking older
Docker hosts.

#### Layer 2: Filesystem Delete Prevention

Landlock v2+ (kernel 5.19+) supports fine-grained file operations. By
granting `WRITE_FILE` without `REMOVE_FILE`/`REMOVE_DIR` on `/workspace`,
the agent can:

- Create new files (`touch`, `>`, `tee`)
- Modify existing files (write, append, truncate)
- Create directories (`mkdir`)

But **cannot**:

- Delete files (`rm`, `unlink`)
- Delete directories (`rmdir`, `rm -rf`)
- Rename across directories (which implies delete at source)

This turns destructive operations into kernel `EACCES` errors. The agent
sees "Permission denied" and must work non-destructively.

**Trade-off**: Some legitimate workflows need delete — `git checkout` deletes
files when switching branches, `npm install` removes old packages, build
tools clean output directories. Options:

1. **Default: delete enabled** — opt-in via `--no-workspace-delete` flag
2. **Default: delete disabled** — opt-out via `--allow-workspace-delete` flag
3. **Soft delete** — rename to `.trash/` instead of unlinking (requires a
   FUSE layer or LD_PRELOAD shim for `unlink()`, more complex)

Recommendation: start with option 1 (delete enabled by default, opt-in
restriction) since many tools assume delete works. The Landlock ruleset
makes it a one-line change to toggle.

#### Layer 3: Pre-Session Workspace Snapshot

Before the agent starts, capture a content-addressable snapshot of the
workspace. This enables:

- **Rollback**: Restore the workspace to its pre-session state if the agent
  makes unacceptable changes
- **Tamper detection**: Detect files the agent modified and then reverted
  (invisible to post-exit diff)
- **Audit trail**: Know exactly what changed, even if the agent tried to
  cover its tracks

**Implementation sketch:**

```bash
# In run-claude.sh, before starting the container:
snapshot_workspace() {
    local workspace="$1"
    local snapshot_dir="$2"

    # Content-addressable manifest: path → SHA-256
    find "$workspace" -type f \
        -not -path '*/.git/objects/*' \
        -not -path '*/node_modules/*' \
        -exec sha256sum {} + \
        | sort > "$snapshot_dir/manifest.txt"

    # Also capture metadata (permissions, symlinks)
    find "$workspace" -not -path '*/.git/objects/*' \
        -not -path '*/node_modules/*' \
        -printf '%M %u %g %s %p\n' \
        | sort > "$snapshot_dir/metadata.txt"
}

SNAPSHOT_DIR=$(mktemp -d)
snapshot_workspace "$PROJECT_DIR" "$SNAPSHOT_DIR"

# After session ends, before post-exit audit:
diff_workspace() {
    local workspace="$1"
    local snapshot_dir="$2"

    # Generate current manifest
    find "$workspace" -type f \
        -not -path '*/.git/objects/*' \
        -not -path '*/node_modules/*' \
        -exec sha256sum {} + \
        | sort > "$snapshot_dir/current.txt"

    # Compare
    diff "$snapshot_dir/manifest.txt" "$snapshot_dir/current.txt"
}
```

The snapshot pairs with the existing post-exit audit:
1. Snapshot captures pre-session state
2. Agent runs
3. Post-exit audit detects suspect files, hook tampering, git config changes
4. Snapshot diff shows **all** changes, including reverted ones
5. With `--copy-workspace`, user can reject changes and roll back completely

### Integration Pattern

All three layers follow established patterns in the project:

| Layer | Pattern | Precedent |
|-------|---------|-----------|
| Landlock enforcement | `/etc/ld.so.preload` constructor | `nodump.so`, `git-guard.so` |
| Delete prevention | Landlock ruleset flag | Same library, different access bits |
| Workspace snapshot | Pre/post comparison in `run-claude.sh` | `.git/config` snapshot/restore |

The Landlock library is compiled alongside the existing `.so` files in the
Dockerfile and added to `/etc/ld.so.preload` in the same line:

```dockerfile
RUN echo "/usr/lib/nodump.so" >> /etc/ld.so.preload && \
    echo "/usr/lib/git-guard.so" >> /etc/ld.so.preload && \
    echo "/usr/lib/landlock-enforce.so" >> /etc/ld.so.preload
```

### Trade-Offs

- **Kernel version dependency**: Landlock requires kernel 5.13+ (basic) or
  5.19+ (fine-grained delete control). OrbStack and Docker Desktop both run
  recent kernels (typically 6.x), so this is fine for our macOS target. Linux
  hosts with older kernels degrade gracefully (constructor no-ops).
- **No protection for root**: Landlock applies to unprivileged processes. The
  entrypoint runs as root during init and drops to UID 1000 before starting
  Claude Code — Landlock is applied at that point. Any root-level escape
  bypasses Landlock (but root escape also bypasses everything else).
- **Debug complexity**: Kernel EACCES from Landlock looks identical to regular
  permission errors. Debugging requires `dmesg` or `audit.log` with Landlock
  audit support (kernel 6.4+). May need to add logging in the constructor.
- **Snapshot cost**: `sha256sum` over the entire workspace adds startup time.
  For large repos, this could be multiple seconds. Mitigations: skip
  `.git/objects`, `node_modules`, and other large vendored directories;
  parallelize with `xargs -P`; or use `git hash-object` for tracked files.

### Open Questions

1. **Landlock ABI version detection**: Should the library check the kernel's
   Landlock ABI version at runtime and adapt the ruleset? v1 (5.13) doesn't
   support file removal distinctions; v2 (5.19) adds `REFER`; v3 (6.2) adds
   truncate. The constructor should detect and use the best available version.

2. **Process filtering**: The `/etc/ld.so.preload` library loads into every
   process. The constructor should check whether it's running as the `claude`
   user (UID 1000) and skip for root processes (entrypoint init). Should it
   also skip for specific binaries (git, node) that might need broader access?

3. **Interaction with `--copy-workspace`**: If copy-workspace is active, the
   agent operates on a disposable copy. Is Landlock still valuable? Yes —
   it prevents the agent from accessing paths outside the expected set, even
   within the container. But delete prevention is less critical since the
   copy is disposable.

4. **Snapshot storage**: For `--copy-workspace`, the snapshot is trivially
   the original workspace (already preserved). For bind-mount mode, the
   snapshot manifest lives in a temp directory on the host. Should it be
   kept for forensic analysis after the session?

5. **FUSE alternative for soft-delete**: Instead of kernel EACCES on delete,
   a FUSE overlay could intercept `unlink()` and move files to `.trash/`.
   This preserves tool compatibility but adds complexity. Worth exploring
   if hard-deny delete proves too disruptive?
