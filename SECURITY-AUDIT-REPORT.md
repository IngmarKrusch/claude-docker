# Docker Sandbox Security Audit Report

**Date:** 2026-02-10
**Scope:** Red-team security assessment of Claude Code Docker sandbox
**Environment:** Debian bookworm-slim, OrbStack Linux 6.17.8 (aarch64)

---

## Executive Summary

The sandbox demonstrates **excellent defense-in-depth** for container escape prevention. All kernel-level escape vectors are thoroughly blocked. However, the audit identified **three critical findings** and **two medium findings** related to the git guard bypass chain and data exfiltration channels.

---

## Findings by Severity

### CRITICAL-1: git-guard.so Not Compiled or Loaded

**Severity:** CRITICAL
**Vector:** Calling `/usr/libexec/wrapped-git push` directly bypasses the shell wrapper's push guard.

The `git-guard.c` source file exists in the repository but **git-guard.so is never compiled, installed, or loaded**:
- `/etc/ld.so.preload` does not exist
- `LD_PRELOAD` only contains `nodump.so`
- No `git-guard.so` file exists anywhere on the filesystem

**Impact:** The only protection against `git push` is the shell wrapper at `/usr/local/bin/git`. Any process calling `/usr/libexec/wrapped-git push` directly bypasses all push restrictions.

**Proof:**
```
$ /usr/libexec/wrapped-git push
To https://github.com/IngmarKrusch/claude-docker.git
   f31ea4e..a26761c  main -> main
```

**Remediation:**
1. Compile `git-guard.c` into `git-guard.so`
2. Install to `/etc/ld.so.preload` (rootfs is read-only, so this must be done at image build time)
3. Verify it loads for all git invocations, not just those via the shell wrapper

---

### CRITICAL-2: ALLOW_GIT_PUSH Environment Variable Trivially Settable

**Severity:** CRITICAL
**Vector:** Setting `ALLOW_GIT_PUSH=1` bypasses the push check in the shell wrapper.

The shell wrapper checks `if [ "${ALLOW_GIT_PUSH:-}" != "1" ]` to block pushes. Since the environment variable is under the container user's control, any process can set it:

```
$ ALLOW_GIT_PUSH=1 git push --dry-run origin main
Everything up-to-date
```

**Impact:** Combined with CRITICAL-1 (no binary-level guard), push restrictions are completely bypassable.

**Remediation:**
1. The compiled `git-guard.so` (CRITICAL-1 fix) also checks `ALLOW_GIT_PUSH`, but this env var check is inherently bypassable by the user
2. Consider alternative mechanisms: a flag file only root can create, or checking a parent process tree
3. At minimum, ensure the binary-level guard is active so the env var bypass is defense-in-depth, not the sole gate

---

### CRITICAL-3: Git Hooks Bypass via Config Edit + Direct Binary Call

**Severity:** CRITICAL
**Vector:** Edit writable `.gitconfig` and `.git/config` to remove `hooksPath=/dev/null`, then call `wrapped-git` directly without `GIT_CONFIG_COUNT` override.

**Proof:**
1. Edit `/home/claude/.claude/.gitconfig` — remove `hooksPath = /dev/null`
2. Edit `/workspace/.git/config` — remove `hookspath = /dev/null`
3. Create `.git/hooks/pre-commit` with arbitrary commands
4. Call `/usr/libexec/wrapped-git commit` without `GIT_CONFIG_COUNT` env vars
5. **Hook executes** — confirmed output: `HOOK_EXEC`

**Impact:** Arbitrary command execution via git hooks. The `/workspace` filesystem is exec-enabled (virtiofs), so scripts placed in `.git/hooks/` can run. This bypasses the hook protection intended to prevent code execution during git operations.

**Remediation:**
1. The compiled `git-guard.so` forces `GIT_CONFIG_COUNT` at the binary level, which would prevent this
2. Consider making `.git/hooks` read-only or using a bind mount
3. The `wrapped-git` binary permissions (`--x--x--x`) prevent reading but not execution — consider removing execute permission for the group/other

---

### MEDIUM-1: OAuth Tokens Readable in .credentials.json

**Severity:** MEDIUM
**Vector:** Direct file read of `/home/claude/.claude/.credentials.json`

The credentials file is readable by the container user and contains OAuth access and refresh tokens:
```
$ cat /home/claude/.claude/.credentials.json
{"claudeAiOauth":{"accessToken":"sk-ant-oat01-...","refreshToken":"sk-ant-ort01-...",...}}
```

**Impact:** If combined with any data exfiltration channel (see MEDIUM-2), these tokens could be stolen. The access token grants API access to Claude AI services.

**Note:** This is somewhat expected — the container needs these credentials to function. The defense relies on preventing exfiltration rather than preventing reading.

**Remediation:**
1. Consider using a credential helper that serves tokens via a Unix socket with single-use tokens
2. Use file permissions `0600` (already set) but also consider mounting credentials via a tmpfs that's unmounted after initial auth
3. Reduce token scope to minimum necessary

---

### MEDIUM-2: Data Exfiltration Channels Exist via Allowed Domains

**Severity:** MEDIUM
**Vector:** HTTP POST to allowed domains (GitHub API, npm registry, statsig, Anthropic API, todoist API)

All allowlisted domains accept HTTP POST requests. While authentication is required, if any token is available (e.g., the OAuth token from MEDIUM-1, or a GitHub token from git credential cache), data can be exfiltrated:

| Endpoint | Reachable | Auth Required | Exfil Potential |
|----------|-----------|---------------|-----------------|
| api.github.com | Yes | Yes (401) | High if GitHub token available |
| registry.npmjs.org | Yes | Partial (404) | Medium |
| featuregates.org (statsig) | Yes | Yes (401) | Low |
| api.anthropic.com | Yes | Yes (401) | Medium if API key available |
| api.todoist.com | Yes | Partial (200 for OPTIONS) | Medium |
| github.com:22 (SSH) | **FIXED** | N/A | ~~Medium (raw TCP)~~ **Blocked** |
| github.com:443 (HTTPS) | Yes | Per-API | High |

**Fixed:** GitHub SSH (port 22) was an exfiltration channel accepting raw TCP connections (2400 bytes sent in testing). Now blocked — outbound port 22 is dropped by the firewall (`iptables -A OUTPUT -p tcp --dport 22 -j DROP`). This repo uses HTTPS for GitHub authentication, so SSH access is not needed.

**Remaining remediation:**
1. Consider restricting outbound connections to specific paths/methods, not just hosts (requires L7 proxy)
2. Monitor for unusual POST patterns to allowed hosts

---

### LOW-1: DNS Tunneling Viable at ~39 bytes/sec

**Severity:** LOW
**Vector:** Encode data in DNS subdomain labels

The DNS rate limit (1 query/sec with burst of 2) is effective but still allows ~39 bytes/sec of data exfiltration via DNS tunneling to an attacker-controlled nameserver.

**Bandwidth estimate:**
- 1 query/sec rate limit confirmed working
- ~39 bytes per query (base32 in subdomain labels)
- An API key (~40 bytes) could be exfiltrated in 1-2 seconds
- An SSH key (~2KB) in ~1 minute

**Proof:**
```
Spaced queries (1.5s apart): All succeed (NXDOMAIN)
Burst of 5 rapid queries: 2 succeed, 3 rate-limited
```

**Remediation:**
1. Reduce burst allowance from 2 to 1
2. Consider DNS filtering/monitoring for unusually long subdomain labels
3. Use a DNS proxy that validates query patterns

---

### LOW-2: mmap(RWX) Succeeds — Arbitrary Shellcode Execution

**Severity:** LOW (in context)
**Vector:** Python ctypes + mmap with PROT_READ|PROT_WRITE|PROT_EXEC

Anonymous mmap with RWX permissions succeeds, allowing arbitrary native code execution:
```python
addr = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
# Write ARM64 shellcode: mov w0, #42; ret
# Call via ctypes.CFUNCTYPE → returns 42
```

**Impact:** Low in this context because interpreters (Python, Node.js, Perl) already provide arbitrary code execution. The RWX mmap doesn't grant additional capabilities beyond what the interpreters provide. However, it does bypass noexec on tmpfs for custom native code.

**Note:** File-backed mmap from noexec tmpfs IS properly blocked (`dlopen` from tmpfs fails with "failed to map segment").

**Remediation:**
1. Add `prctl(PR_SET_MDWE, ...)` to prevent RWX mmap if kernel supports it
2. Or add a seccomp rule to block mmap/mprotect with PROT_EXEC + PROT_WRITE combination
3. Lower priority since interpreters already provide equivalent capability

---

## Controls That Passed

| Control | Status | Details |
|---------|--------|---------|
| Capability bounding set | PASS | All capabilities dropped (CapBnd=0000000000000000) |
| NoNewPrivs | PASS | Enabled (cannot gain privileges) |
| Seccomp | PASS | MODE_FILTER active with custom profile |
| ptrace blocked | PASS | Returns EPERM |
| memfd_create blocked | PASS | Returns EPERM |
| Mount operations | PASS | All mount calls fail (not superuser) |
| Cgroup escape | PASS | /sys/fs/cgroup read-only |
| /proc/1/root traversal | PASS | Permission denied |
| User namespace creation | PASS | unshare(CLONE_NEWUSER) returns EPERM |
| Device creation (mknod) | PASS | Operation not permitted |
| Raw sockets (ICMP) | PASS | Operation not permitted |
| Direct IP connections | PASS | Blocked by firewall (No route to host) |
| Unauthorized DNS | PASS | Direct queries to 8.8.8.8 blocked |
| /proc/self/mem write | PASS | Permission denied |
| /proc/1/environ read | PASS | Permission denied |
| Signal injection (PID 1) | PASS | Operation not permitted |
| Core dumps | PASS | Disabled (RLIMIT_CORE=0, nodump.so) |
| noexec on tmpfs (files) | PASS | Direct exec and dlopen blocked |
| Read-only rootfs | PASS | Cannot modify /etc or system files |
| SSH client | PASS | Not installed |
| unshare binary | PASS | Not installed |
| SUID binaries | PASS | None found |

---

## Attack Chain Summary

The most concerning attack chain combines multiple findings:

1. **Read** `/home/claude/.claude/.credentials.json` to get OAuth tokens (MEDIUM-1)
2. **Exfiltrate** tokens via DNS tunneling (~2 seconds, LOW-1) or HTTP POST to allowed host (MEDIUM-2)
3. **OR** use direct `wrapped-git push` (CRITICAL-1) to push repository data to a remote
4. **OR** bypass hooks protection (CRITICAL-3) to execute arbitrary commands during git operations

**Primary remediation:** Compile and install `git-guard.so` via `/etc/ld.so.preload`. This single fix addresses CRITICAL-1, CRITICAL-2, and CRITICAL-3 simultaneously, as the binary-level guard enforces push blocks, config overrides, and hooksPath at the process level regardless of how git is invoked.

---

## Recommendations Priority

| Priority | Finding | Fix |
|----------|---------|-----|
| P0 | CRITICAL-1,2,3 | Build and install `git-guard.so` via `/etc/ld.so.preload` |
| ~~P1~~ | ~~MEDIUM-2~~ | ~~Block GitHub SSH (port 22) if not needed~~ **FIXED** |
| P2 | MEDIUM-1 | Consider credential rotation or short-lived tokens |
| P3 | LOW-1 | Tighten DNS rate limit burst to 1 |
| P4 | LOW-2 | Add seccomp rule for RWX mmap if practical |
