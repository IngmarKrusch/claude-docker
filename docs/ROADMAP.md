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
