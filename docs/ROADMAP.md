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
