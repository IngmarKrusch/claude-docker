# Audit Round 17 — Git Config Bypass, Firewall Rule Ordering & Post-Exit Hardening

**Date:** 2026-02-15
**Auditor:** Claude (Opus 4.6, running inside the sandbox)
**Scope:** Git environment variable bypass, firewall rule ordering, container escape validation, network probing, suspect file coverage, post-exit hook review, entrypoint log lockdown
**Method:** Live red-team from inside the running container (7 parallel test groups). Two additional findings (C5, M4) identified and implemented by a parallel audit session.

---

## Executive Summary

Two exploitable vulnerabilities confirmed, one hypothesized issue disproven, one coverage gap identified, and two improvements implemented by a parallel session. The critical finding (R17-01) allows **arbitrary command execution via git filter drivers** by redirecting git to an unsanitized config file through the `GIT_CONFIG_GLOBAL` environment variable — bypassing all existing git-guard protections. Container escape, network firewall, and seccomp protections all hold (10/10 pass).

| ID | Severity | Confidence | Status | Finding |
|----|----------|------------|--------|---------|
| R17-01 | **HIGH** | High | **Implemented** | `GIT_CONFIG_GLOBAL` env var not cleared — arbitrary command execution via filter drivers |
| R17-02 | **MEDIUM** | High | **Implemented** | Firewall rule ordering allows SSH/Docker API to host subnet (dead code for SSH DROP) |
| R17-03 | — | High | Disproven | `/dev/shm` noexec — already hardened |
| R17-04 | **LOW** | High | **Implemented** | 17 auto-executing files missing from post-exit `SUSPECT_FILES` audit |
| R17-C5 | **MEDIUM** | High | **Implemented** | Post-exit hook review upgraded from passive warning to interactive review |
| R17-M4 | **LOW** | High | **Implemented** | Entrypoint log lockdown (chmod 444 after init) |

---

## Detailed Findings

### R17-01: `GIT_CONFIG_GLOBAL` Not Cleared — Arbitrary Code Execution (HIGH)

**File:** `container/git-guard.c:118-147`
**Confidence:** High — proven with live exploit

#### Description

`git-guard.c` clears 13 dangerous git environment variables (lines 121-133) but misses several critical ones, most notably `GIT_CONFIG_GLOBAL` and `GIT_CONFIG`. These variables redirect git to read configuration from an arbitrary file, bypassing the entrypoint's startup sanitization of `.git/config` and global gitconfig.

The code comment on line 136-137 is **misleading**:
```c
/* GIT_CONFIG_COUNT overrides local/global gitconfig, preventing
 * bypass via .git/config or GIT_CONFIG_GLOBAL. */
```

`GIT_CONFIG_COUNT=4` only forces 4 specific keys (`core.hooksPath`, `credential.helper`, `core.fsmonitor`, `core.sshCommand`). All other blocked keys — `filter.*`, `alias.*`, `core.pager`, `diff.*.textconv`, etc. — are **freely read** from the file pointed to by `GIT_CONFIG_GLOBAL`.

**Currently cleared (lines 121-133):**
```
GIT_EXTERNAL_DIFF, GIT_SSH, GIT_SSH_COMMAND, GIT_ASKPASS, GIT_EDITOR,
GIT_EXEC_PATH, GIT_TEMPLATE_DIR, GIT_CONFIG_SYSTEM, GIT_PROXY_COMMAND,
GIT_PAGER, GIT_SEQUENCE_EDITOR, VISUAL, EDITOR
```

**Missing (exploitable):**
```
GIT_CONFIG_GLOBAL, GIT_CONFIG, GIT_DIR, PAGER, LESSOPEN, LESSCLOSE
```

**Missing (defense-in-depth, lower priority):**
```
GIT_WORK_TREE, GIT_INDEX_FILE, GIT_ALTERNATE_OBJECT_DIRECTORIES, GIT_COMMON_DIR
```

#### Attack Chain (Proven)

```bash
# 1. Write a malicious gitconfig with a filter driver
cat > /tmp/evil-gitconfig <<'EOF'
[filter "x"]
    clean = echo FILTER_BYPASS_WORKS >&2
    smudge = cat
    required = true
EOF

# 2. Create .gitattributes referencing the filter
echo '*.txt filter=x' > /workspace/.gitattributes

# 3. Redirect git to the malicious config
export GIT_CONFIG_GLOBAL=/tmp/evil-gitconfig

# 4. Trigger the filter via git add
echo test > /workspace/test.txt
git add test.txt
# Output: FILTER_BYPASS_WORKS — arbitrary command executed
```

The filter's `clean` command can be any shell command. This bypasses `git-guard.so` entirely because git-guard only blocks `git config` writes and `-c` flag overrides — it does not intercept config file reads.

**Additional confirmed vectors:**
- `GIT_DIR` redirect to an unsanitized `.git` directory in `/tmp` — bypasses entrypoint sanitization
- `PAGER` fallback — when `GIT_PAGER` is cleared (line 130), git falls through to `PAGER` env var, which can execute arbitrary commands via git output paging

#### Why This Is Not an Accepted Risk

SECURITY.md line 75 explicitly lists env vars that are "cleared on every invocation." `GIT_CONFIG_GLOBAL` is simply absent — it was never listed as an accepted risk or deliberate omission.

#### Fix

Add `unsetenv()` calls in `git-guard.c` before the existing block (before line 121):

```c
/* R17-01 fix: Clear config-redirect and pager env vars that bypass
 * GIT_CONFIG_COUNT (which only forces 4 specific keys, not all config). */
unsetenv("GIT_CONFIG_GLOBAL");
unsetenv("GIT_CONFIG");
unsetenv("GIT_DIR");
unsetenv("GIT_WORK_TREE");
unsetenv("GIT_INDEX_FILE");
unsetenv("GIT_ALTERNATE_OBJECT_DIRECTORIES");
unsetenv("GIT_COMMON_DIR");
unsetenv("PAGER");
unsetenv("LESSOPEN");
unsetenv("LESSCLOSE");
```

Also fix the misleading comment on lines 135-137:

```c
/* Force security-critical git config via environment.
 * GIT_CONFIG_COUNT forces these 4 specific keys with highest precedence,
 * but does NOT suppress config file loading — other keys are still read
 * from gitconfig files. The unsetenv() calls above prevent redirection
 * to unsanitized config files via GIT_CONFIG_GLOBAL/GIT_CONFIG. */
```

**Regression risk:** Very low. None of these env vars are set by the entrypoint or needed for normal Claude Code git operations.

---

### R17-02: Firewall Rule Ordering — Host Subnet SSH/Docker API Bypass (MEDIUM)

**File:** `container/init-firewall.sh:103,121`
**Confidence:** High — proven with live test

#### Description

The iptables OUTPUT chain processes rules in first-match-wins order. The host network ACCEPT rule (line 103) fires before the SSH DROP rule (line 121) for any destination within the host subnet:

```
Rule  3: -A OUTPUT -d 192.168.215.0/24 -j ACCEPT    ← matches first
...
Rule  7: -A OUTPUT -p tcp --dport 22 -j DROP          ← never reached for host subnet
```

This makes the SSH DROP dead code for host-subnet destinations, and also leaves Docker API ports (2375/2376) open to the host subnet.

#### Proof of Concept

```bash
# SSH to host IP — packet reaches host (connection refused = host received it)
curl --connect-timeout 3 telnet://192.168.215.1:22
# curl: (28) Connection refused

# SSH to external IP — firewall blocks it (timeout = packet dropped)
curl --connect-timeout 3 telnet://1.1.1.1:22
# curl: (28) Connection timed out
```

The different error responses confirm: SSH to host subnet bypasses the firewall, SSH to external IPs is correctly blocked.

#### Relationship to Accepted Risks

SECURITY.md line 51 documents host subnet access as accepted:
> **Host subnet allowed** — Docker gateway subnet (e.g. `192.168.1.0/24`) is reachable — needed for Docker gateway and local MCP services

However, SSH is separately documented as universally blocked (line 45):
> SSH (port 22) blocked — Prevents raw TCP exfiltration via `github.com:22`

The intent was clearly to block SSH to ALL destinations. The rule ordering makes the implementation inconsistent with the documented security model.

#### Practical Impact

- **SSH to host (macOS):** Low direct risk — macOS doesn't run sshd by default. On Linux hosts or cloud VMs, this could enable host access.
- **Docker API (2375/2376):** Higher risk — if the Docker daemon listens on TCP (common in Docker Desktop or remote Docker setups), access to the API would enable full container escape via `docker exec`.
- **Other LAN services:** Already accepted — host subnet access is needed for Docker gateway and MCP services.

#### Fix

In `init-firewall.sh`, insert SSH and Docker API DROP rules before the host network ACCEPT (before line 102):

```bash
# R17-02 fix: Block dangerous ports to host subnet BEFORE general host network ACCEPT.
# SSH (port 22) is an exfiltration channel; Docker API (2375/2376) enables container escape.
iptables -A OUTPUT -d "$HOST_NETWORK" -p tcp --dport 22 -j DROP
iptables -A OUTPUT -d "$HOST_NETWORK" -p tcp --dport 2375 -j DROP
iptables -A OUTPUT -d "$HOST_NETWORK" -p tcp --dport 2376 -j DROP

# Set up remaining iptables rules
iptables -A INPUT -s "$HOST_NETWORK" -j ACCEPT
iptables -A OUTPUT -d "$HOST_NETWORK" -j ACCEPT
```

The general SSH DROP on line 121 should remain for defense-in-depth (covers non-host-subnet destinations).

**Regression risk:** None. MCP services use custom high ports, not 22/2375/2376. The Docker gateway doesn't use SSH.

---

### R17-C5: Interactive Hook Review (MEDIUM) — IMPLEMENTED

**Files:** `run-claude.sh:374-383,623-661`, `docs/SECURITY.md`, `docs/ARCHITECTURE.md`
**Confidence:** High
**Status:** Implemented in parallel session (commit 1f713b3)

#### Description

The post-exit hook detection was a passive warning that listed new hooks but took no action. An AI agent could plant a malicious git hook (e.g., `pre-commit` that exfiltrates code on every commit) and the user would only see a warning message that could be overlooked.

#### Fix (Implemented)

Upgraded from passive warning to **interactive per-hook review**:

1. **Pre-session SHA-256 baseline** (`run-claude.sh:374-383`): Each non-`.sample` hook is hashed before the session. Hooks that existed unchanged are silently skipped at post-exit — no false positives.
2. **Interactive review** (`run-claude.sh:623-661`): For each NEW or MODIFIED hook:
   - Content preview (first 15 lines, ANSI-sanitized)
   - Prompt: `Keep this hook? [y/N]` — default is **remove**
   - Hook is deleted unless the user explicitly approves
3. **Documentation updated**: SECURITY.md and ARCHITECTURE.md reflect the new interactive behavior.

**Regression risk:** Low. Interactive prompt requires `/dev/tty` — will fail silently if not attached to a terminal (e.g., CI/CD piped usage). The `read -r _answer < /dev/tty || _answer=""` fallback defaults to remove, which is the safe choice.

---

### R17-M4: Entrypoint Log Lockdown (LOW) — IMPLEMENTED

**File:** `container/entrypoint.sh:428-431`
**Confidence:** High
**Status:** Implemented in parallel session (commit 1f713b3)

#### Description

The entrypoint log file (`/run/entrypoint.log`) is a virtiofs-mounted host tempfile that was writable by the claude user after init. A malicious session could inject content into the log, potentially including ANSI escape sequences for terminal injection (mitigated by existing sanitization in `run-claude.sh`, but defense-in-depth is warranted). Originally identified as R13-07 (LOW, deferred).

#### Fix (Implemented)

```bash
# R17-M4: Lock down host entrypoint log after init (best-effort on virtiofs)
if [ -n "$HOST_LOG" ]; then
    chmod 444 "$HOST_LOG" 2>/dev/null || true
fi
```

**Limitation:** virtiofs on macOS may ignore `chmod` (documented behavior). The existing ANSI sanitization in `run-claude.sh` remains the primary protection. This is defense-in-depth.

---

### R17-03: `/dev/shm` Noexec — DISPROVEN

**File:** `run-claude.sh:476`
**Confidence:** High — tested live

#### Hypothesis

`--shm-size=64m` was hypothesized to lack `noexec`, creating an executable tmpfs gap (unlike `/tmp` and `/run` which have `noexec`; note: `~/.npm` does NOT have `noexec` — see `run-claude.sh`).

#### Test Results

```bash
$ mount | grep shm
shm /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=65536k

$ cp /usr/bin/id /dev/shm/test && /dev/shm/test
bash: /dev/shm/test: Permission denied  (exit 126)

$ LD_PRELOAD=/dev/shm/test.so git status
ERROR: ld.so: ... failed to map segment from shared object '/dev/shm/test.so': Operation not permitted
```

**Result:** `/dev/shm` already has `noexec`. Docker applies `noexec` by default to `--shm-size` mounts. No fix needed.

---

### R17-04: Missing SUSPECT_FILES Entries (LOW)

**File:** `run-claude.sh:404`
**Confidence:** High

#### Description

The `SUSPECT_FILES` array (line 404) contains 34 entries for the post-exit workspace audit. Several auto-executing build/config files are missing. These files can execute arbitrary code when opened by IDEs, invoked by build tools, or triggered on directory entry.

#### Recommended Additions (17 files)

**HIGH priority — auto-execute on IDE open or directory entry:**

| File | Risk | Justification |
|------|------|---------------|
| `build.gradle` | HIGH | Groovy script executed on JetBrains IDE auto-sync |
| `build.gradle.kts` | HIGH | Kotlin DSL executed on JetBrains IDE auto-sync |
| `pom.xml` | HIGH | Maven plugins executed on IDE auto-import |
| `Vagrantfile` | HIGH | Arbitrary Ruby executes on HOST on any `vagrant` command |
| `WORKSPACE` | HIGH | Bazel Starlark with host `execute()` capability |
| `.mise.toml` | HIGH | Shell hooks auto-execute on `cd` into directory |
| `.devcontainer/devcontainer.json` | HIGH | VS Code auto-prompts to reopen; `postCreateCommand` runs arbitrary shell |
| `justfile` | HIGH | Lowercase variant evades existing `Justfile` check (case-insensitive tool) |
| `.justfile` | HIGH | Hidden variant, same risk as `justfile` |
| `Rakefile` | HIGH | Arbitrary Ruby executes at parse time on any `rake` invocation |
| `Gemfile` | HIGH | Ruby code executed by `bundle install` (common onboarding step) |

**MEDIUM priority — common developer commands:**

| File | Risk | Justification |
|------|------|---------------|
| `babel.config.js` | HIGH | JavaScript `require()`d by Babel/webpack/Jest — same risk as `jest.config.js` (already listed) |
| `Tiltfile` | MEDIUM | `local()` built-in runs arbitrary shell commands |
| `Brewfile` | MEDIUM | Evaluated as Ruby code by `brew bundle` |
| `deno.json` | MEDIUM | Task definitions; consistency with `package.json` (already listed) |
| `deno.jsonc` | MEDIUM | Same as `deno.json` |
| `.ruby-version` | MEDIUM | Consistency with `.node-version`/`.python-version` (already listed) |

**Excluded (too low risk):**

| File | Why excluded |
|------|-------------|
| `.bazelrc` | Configuration-only, no code execution capability |
| `Earthfile` | Requires explicit invocation, runs in containers |
| `Procfile` | Requires explicit `foreman start` |
| `Cakefile` | Legacy CoffeeScript, effectively dormant ecosystem |
| `.java-version` | Just a version string; jenv less common than rbenv/nvm |

**Note on `WORKSPACE`:** This is a generic filename. Bazel's `WORKSPACE` files contain Starlark with host `execute()` capability, but non-Bazel projects might have a file with this name. False positive risk is higher than other entries but the warning is advisory-only, so the cost is low.

#### Fix

Append to the `SUSPECT_FILES` array on line 404 of `run-claude.sh`:

```bash
SUSPECT_FILES=(CLAUDE.md Justfile Taskfile.yml .envrc ... .cargo/config.toml
    build.gradle build.gradle.kts pom.xml Vagrantfile WORKSPACE .mise.toml
    .devcontainer/devcontainer.json justfile .justfile Rakefile Gemfile
    babel.config.js Tiltfile Brewfile deno.json deno.jsonc .ruby-version)
```

**Regression risk:** None. Advisory-only warnings; no behavior change.

---

## Vectors Tested and Found Effective (Defense Holds)

### Container Escape (10/10 PASS)

| Vector | Result |
|--------|--------|
| `/proc/1/root`, `/proc/1/environ`, `/proc/1/mem` | Permission denied |
| Capabilities (all 5 sets) | All zero |
| Seccomp (filter mode) | Active (mode 2, 1 filter) |
| ptrace, memfd_create, AF_VSOCK | Operation not permitted |
| `unshare`, `nsenter` | Removed from image |
| `/dev/mem`, `/dev/kmem` | Not present |
| Cgroup escape (`release_agent`) | Cgroup v2, no release_agent |
| Signal PID 1 | Operation not permitted |
| Core dump limits | Hard limit 0 |
| IPv6 connectivity | Disabled at kernel level |

### Network Firewall (All PASS)

| Test | Result |
|------|--------|
| Blocked sites (example.com, google.com, ifconfig.me, httpbin.org) | All blocked |
| Allowed sites (api.github.com, api.anthropic.com, registry.npmjs.org) | All reachable |
| DNS resolution as claude user | Fully blocked (UID-based iptables) |
| Non-standard ports on allowed IPs (8080, 8443, 9090) | All blocked |
| Port 80 on allowed IPs | Reachable (expected — HTTP allowed by design) |

### Socket/FD Scanning (Clean)

| Test | Result |
|------|--------|
| Docker socket | Not mounted |
| Unix sockets | Only credential cache socket (accepted same-UID limitation) |
| `/proc/<pid>/environ` for credentials | No credential leaks found |
| Open FD enumeration | Clean — no host file leaks |

---

## Documentation Updates Required

### `docs/SECURITY.md`

1. **Line 75:** Add `GIT_CONFIG_GLOBAL`, `GIT_CONFIG`, `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_COMMON_DIR`, `PAGER`, `LESSOPEN`, `LESSCLOSE` to the env var clearing list
2. **Line 45:** Clarify SSH blocking scope now includes host subnet (after R17-02 fix)
3. **Line 51:** Update host subnet entry to note SSH/Docker API exclusion
4. **Line 165:** Update suspect file pattern count

### `docs/ARCHITECTURE.md`

1. **Line 64:** Update git-guard env var description to include new vars
2. **Line 75:** Update suspect file count

### `container/git-guard.c`

1. **Lines 135-137:** Fix misleading comment about `GIT_CONFIG_COUNT` preventing `GIT_CONFIG_GLOBAL` bypass

---

## Remediation Plan

### Already Implemented (commit 1f713b3)

**R17-C5:** Interactive hook review — post-exit hooks now require explicit user approval (default: deny/delete).
**R17-M4:** Entrypoint log lockdown — `chmod 444` after init (best-effort on virtiofs).

### Priority 1 — Fix Immediately

**R17-01:** Add 10 `unsetenv()` calls to `git-guard.c` + fix misleading comment. This is the only finding with proven arbitrary code execution.

### Priority 2 — Fix Soon

**R17-02:** Reorder firewall rules in `init-firewall.sh`. Insert SSH/Docker API DROP before host network ACCEPT.

### Priority 3 — Fix When Convenient

**R17-04:** Add 17 entries to `SUSPECT_FILES` array in `run-claude.sh`. Advisory-only; no behavior change.

### Documentation

Update `SECURITY.md`, `ARCHITECTURE.md` to reflect all changes (R17-01, R17-02, R17-04). C5 and M4 documentation was updated in commit 1f713b3.

---

## Cross-Reference with Previous Rounds

| Round | Related Finding | Relationship |
|-------|----------------|-------------|
| R10 (H4) | Added initial env var clearing | R17-01 extends the list with 10 missing vars |
| R10 (H2) | Restricted ipset to TCP 443/80 | R17-02 is a separate ordering issue within the same rule set |
| R10 (M9) | ANSI-sanitized hook filenames in post-exit audit | R17-C5 replaces passive warning with interactive review |
| R12 (C03) | Cloud metadata DROP before host network | R17-02 follows the same pattern — dangerous DROPs before general ACCEPT |
| R13 (R13-05) | Added CLAUDE.md, Justfile, Taskfile.yml to SUSPECT_FILES | R17-04 continues expanding the same array |
| R13 (R13-07) | Entrypoint log writable (deferred) | R17-M4 implements the fix (chmod 444) |
| R16 (L1) | Added GIT_PAGER, GIT_SEQUENCE_EDITOR, VISUAL, EDITOR | R17-01 extends further with GIT_CONFIG_GLOBAL, GIT_CONFIG, PAGER, etc. |
| R16 (L7) | Documented host subnet access | R17-02 narrows it by excluding dangerous ports |

---

## Verification Checklist

- [x] All file:line references cross-checked against current codebase (post-1f713b3)
- [x] No accepted risks (documented in SECURITY.md) presented as bugs
- [x] Host subnet access remains accepted; only SSH/Docker API ports narrowed
- [x] R17-03 tested and disproven before proposing fix — correctly dropped
- [x] Findings deduplicated against previous audit rounds (R10, R12, R13, R16)
- [x] Confidence ratings provided for all findings
- [x] Regression risk assessed for each proposed fix
- [x] Misleading code comment identified for correction (git-guard.c:135-137)
- [x] Parallel session fixes (R17-C5, R17-M4) from commit 1f713b3 incorporated into report
- [x] Line numbers updated to reflect run-claude.sh changes in 1f713b3 (SUSPECT_FILES: 395→404)

---

## Remediation Status

All findings from this round have been addressed.

| ID | Severity | Status | Implementation |
|----|----------|--------|---------------|
| R17-01 | HIGH | **Implemented** | Added 10 `unsetenv()` calls to `git-guard.c` (`GIT_CONFIG_GLOBAL`, `GIT_CONFIG`, `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_COMMON_DIR`, `PAGER`, `LESSOPEN`, `LESSCLOSE`). Fixed misleading comment about `GIT_CONFIG_COUNT` scope. |
| R17-02 | MEDIUM | **Implemented** | Inserted 3 `iptables -A OUTPUT -d $HOST_NETWORK -p tcp --dport {22,2375,2376} -j DROP` rules before the host network ACCEPT in `init-firewall.sh`. General SSH DROP on line 121 retained for defense-in-depth. |
| R17-03 | — | **Disproven** | `/dev/shm` already has `noexec` (Docker default). No fix needed. |
| R17-04 | LOW | **Implemented** | Added 17 entries to `SUSPECT_FILES` array in `run-claude.sh` (52 total): `build.gradle`, `build.gradle.kts`, `pom.xml`, `Vagrantfile`, `WORKSPACE`, `.mise.toml`, `.devcontainer/devcontainer.json`, `justfile`, `.justfile`, `Rakefile`, `Gemfile`, `babel.config.js`, `Tiltfile`, `Brewfile`, `deno.json`, `deno.jsonc`, `.ruby-version`. |
| R17-C5 | MEDIUM | **Implemented** | Interactive hook review (commit 1f713b3). |
| R17-M4 | LOW | **Implemented** | Entrypoint log lockdown (commit 1f713b3). |

Documentation updated: `SECURITY.md` (env var list, SSH scope, host subnet, file count), `ARCHITECTURE.md` (firewall desc, file count).
