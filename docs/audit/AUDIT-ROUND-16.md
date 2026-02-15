# Audit Round 16 — Comprehensive Codebase Audit

**Date:** 2026-02-15
**Scope:** Full codebase audit covering security, code quality, documentation accuracy, and simplification opportunities.
**Files examined:** All shell scripts, C sources, config files, Dockerfile, README.md, docs/SECURITY.md, docs/ARCHITECTURE.md.

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 2 |
| LOW | 7 |
| INFO / DOC-ONLY | 8 |
| **Total** | **17** |

No critical or high-severity issues found. Two medium findings affect documentation accuracy (one gives users incorrect kernel hardening instructions, one overstates git-guard scope). Low findings are defense-in-depth consistency gaps and reliability improvements. Info findings are documentation drift.

### Resolution

All 17 findings + 1 excluded-but-actionable item resolved:

- **M1** (`vm.unprivileged_userfaultfd`): Changed `=1` to `=0` in README.md and SECURITY.md (4 occurrences)
- **M2** (`diff.*`/`merge.*` scope): SECURITY.md updated to document specific subkeys instead of prefix-based blocking
- **L1** (`GIT_PAGER` et al.): Added `unsetenv()` calls for `GIT_PAGER`, `GIT_SEQUENCE_EDITOR`, `VISUAL`, `EDITOR` in git-guard.c; updated SECURITY.md env var list
- **L2** (`include` section): Added `include` to post-exit audit section scan in run-claude.sh (both pre-snapshot and post-exit)
- **L3** (shellcheck): Rewrote lint.sh to run shellcheck on all shell scripts after hadolint
- **L4** (WARNING→FATAL): Changed claude-user GitHub API check from WARNING to FATAL with `exit 1` in init-firewall.sh
- **L5** (CIDR minimum): Added `/8` minimum prefix check in reload-firewall.sh
- **L6** (envfile timer): Moved `(sleep 2 && rm)` from before DNS pre-resolution to just before `docker run`
- **L7** (host subnet): Documented host subnet access and cloud metadata blocking in SECURITY.md firewall table
- **I1** (`--with-gvisor`): Removed dead code from run-claude.sh (flag, variable, runtime detection, docker run arg) and all gVisor references from README.md
- **I2** (`cp -P`→`cp -L`): Fixed ARCHITECTURE.md to match actual code
- **I3** (suspect file count): Updated ARCHITECTURE.md to say "35 patterns total"
- **I4** (audit file paths): Fixed paths in ARCHITECTURE.md to include `audit/` prefix
- **I5** (broken link): Fixed SECURITY.md relative link to audit report
- **I6** (cloud metadata docs): Added cloud metadata endpoint blocking row to SECURITY.md firewall table
- **I7** (round count): Updated "11+" to "16+" in README.md and SECURITY.md
- **I8** (`/run` tmpfs): Added `/run` tmpfs to ARCHITECTURE.md mount diagram
- **Excluded action** (`api.todoist.com`): Added to SECURITY.md API exfiltration accepted risk entry

---

## MEDIUM

### M1. `vm.unprivileged_userfaultfd=1` enables rather than disables

**Files:** `README.md:30,35`, `docs/SECURITY.md:206,211`
**Confidence:** 99%

The comment says "Disable unprivileged userfaultfd" but `vm.unprivileged_userfaultfd=1` **enables** it (kernel docs: 0=disabled, 1=enabled). The instruction does the opposite of its stated purpose.

Impact is theoretical — the seccomp profile already blocks the `userfaultfd` syscall — but users following the setup guide get a weaker kernel config than intended.

**Fix:** Change `1` to `0` in all four occurrences (two in README.md, two in SECURITY.md).

**Regression risk:** None. The seccomp profile already blocks userfaultfd; this just makes the defense-in-depth layer actually work.

---

### M2. SECURITY.md overstates `diff.*` / `merge.*` git-guard blocking scope

**Files:** `docs/SECURITY.md:67`, `container/git-guard.c:77-89`
**Confidence:** 90%

Documentation lists `diff.*`, `merge.*` under "Prefix-based blocking" alongside `url.*`, `http.*`, etc., implying the entire prefix family is blocked. The code only blocks specific dangerous subkeys:

- `diff.<driver>.textconv` (git-guard.c:80)
- `diff.<driver>.command` (git-guard.c:81)
- `merge.<driver>.driver` (git-guard.c:87)

Other subkeys (e.g. `diff.tool`) pass through git-guard unblocked.

**Mitigated by:** Entrypoint strips entire `diff`/`merge` sections from `.git/config` at startup, and post-exit audit scans for additions. But `git -c diff.tool=<cmd>` would pass git-guard unblocked.

**Fix:** Move `diff.*`, `merge.*` out of the "Prefix-based blocking" list in SECURITY.md. Instead document the specific subkeys: `diff.<driver>.textconv`, `diff.<driver>.command`, `merge.<driver>.driver`.

**Regression risk:** None (documentation-only change).

---

## LOW

### L1. Missing `GIT_PAGER` env var clearance in git-guard.c

**File:** `container/git-guard.c:118-129`
**Confidence:** 85%

`GIT_PAGER` can execute arbitrary commands when git pages output. `core.pager` is blocked as a config key but the `GIT_PAGER` environment variable is not cleared. Also missing: `GIT_SEQUENCE_EDITOR`, `VISUAL`, `EDITOR`.

Currently cleared env vars (lines 121-129): `GIT_EXTERNAL_DIFF`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_ASKPASS`, `GIT_EDITOR`, `GIT_EXEC_PATH`, `GIT_TEMPLATE_DIR`, `GIT_CONFIG_SYSTEM`, `GIT_PROXY_COMMAND`.

**Impact is limited:** the AI can already execute arbitrary commands directly (python3, etc.), so this is a defense-in-depth *consistency* gap, not a primary security boundary.

**Fix:** Add `unsetenv("GIT_PAGER"); unsetenv("GIT_SEQUENCE_EDITOR"); unsetenv("VISUAL"); unsetenv("EDITOR");`

**Regression risk:** Low. These vars are never set by the entrypoint; only matters if the AI sets them.

---

### L2. `include` section missing from post-exit audit scan

**File:** `run-claude.sh:668`
**Confidence:** 95%

The section scan iterates: `alias includeIf filter url http remote credential diff merge`. The `include` section (without `If`) is missing. A newly-added `[include]` section in `.git/config` would evade the post-exit scan.

**Mitigated by:** Entrypoint removes the `include` section at startup, and the `.git/config` tamper detection (SHA-256 hash comparison) would flag any modification.

**Fix:** Add `include` to the section list on line 668.

**Regression risk:** None.

---

### L3. `lint.sh` only runs hadolint — no shellcheck

**File:** `lint.sh:1-4`
**Confidence:** 95%

The lint script only runs `hadolint` on the Dockerfile. Shell scripts are the most security-critical components but are never statically analyzed.

**Fix:** Add `shellcheck -x` for `.sh` files.

**Regression risk:** Shellcheck may flag existing issues that need `# shellcheck disable=` directives.

---

### L4. Claude-user firewall verification is WARNING, not FATAL

**File:** `container/init-firewall.sh:148-150`
**Confidence:** 70%

If the claude user can't reach GitHub (missing `--add-host` entries), the session proceeds with a non-functional network — leading to confusing failures later. The check logs a `WARNING` but does not exit.

**Fix:** Consider making it FATAL (exit 1).

**Regression risk:** Could cause startup failures on networks where DNS is slow or GitHub is temporarily unreachable. The 10-second `--connect-timeout` mitigates this. Strictness vs. resilience tradeoff.

---

### L5. GitHub meta API response: no minimum CIDR prefix validation

**File:** `container/reload-firewall.sh:56-61`
**Confidence:** 80%

CIDR format validation exists (line 56) and rejects prefixes >32 (line 58-60), but accepts any prefix length including very broad CIDRs like `0.0.0.0/1`. A poisoned GitHub meta response could effectively open the firewall.

**Impact:** Requires compromising GitHub's API (HTTPS protected). Same trust boundary as using GitHub for code hosting.

**Fix:** Reject entries with prefix shorter than `/8`.

**Regression risk:** None; GitHub IPs are /16 at broadest.

---

### L6. ENVFILE deletion timer starts before DNS pre-resolution

**File:** `run-claude.sh:440`
**Confidence:** 85%

The `(sleep 2 && rm -f "$ENVFILE") &` background job starts at line 440. DNS pre-resolution for `--add-host` entries runs at lines 456-471 (which can involve multiple `dig` calls). `docker run` — which reads `--env-file` — starts at line 475.

If DNS resolution takes >2 seconds (unusual but possible on slow networks), the envfile is deleted before Docker reads it. The EXIT trap `_cleanup_temps` (line 436) also removes it, making the timed deletion redundant.

**Fix:** Move the `(sleep 2 && rm)` to just before `docker run`, or increase the timeout to 5 seconds.

**Regression risk:** None; this is a reliability improvement.

---

### L7. Host network firewall rule allows entire subnet

**File:** `container/init-firewall.sh:101-102`
**Confidence:** 95%

`$HOST_NETWORK` is the full subnet CIDR (e.g. `192.168.1.0/24`), enabling access to any device on the LAN (NAS, printers, other containers on other hosts). This is required for Docker networking and MCP servers that connect to local services.

**Fix:** Document the security implication in SECURITY.md's network firewall table (e.g. "Host subnet allowed — needed for Docker gateway and local MCP services; on shared networks this permits LAN-wide access").

**Regression risk:** None (documentation-only).

---

## INFO / DOC-ONLY

### I1. `--with-gvisor` is effectively dead code

gVisor's virtualized network stack breaks iptables, and firewall init failure is FATAL (`entrypoint.sh:225-229`). So `--with-gvisor` always exits at firewall init. Already documented in README lines 86, 211, 228-234: "firewall doesn't work with gVisor... use default runc runtime instead." Not a security risk (fails safe), but dead code that could be removed for clarity.

### I2. ARCHITECTURE.md says `cp -P` but code uses `cp -L`

**File:** `docs/ARCHITECTURE.md:55`

Says `cp -P` (no symlink dereferencing) but code uses `cp -L` (dereference symlinks) — changed in R12-H04. The actual behavior is *more secure* than documented (dereferencing prevents symlink-following attacks).

### I3. ARCHITECTURE.md understates suspect file pattern count

**File:** `docs/ARCHITECTURE.md:70`

Lists only 10 suspect file patterns; the actual `SUSPECT_FILES` array in `run-claude.sh:418` has 35 entries. `docs/SECURITY.md` correctly says "30+ patterns."

### I4. ARCHITECTURE.md lists audit files at wrong paths

**File:** `docs/ARCHITECTURE.md:103-104`

Lists:
- `docs/SECURITY-AUDIT-REPORT.md` — actual path: `docs/audit/SECURITY-AUDIT-REPORT.md`
- `docs/ROUND-10-IMPLEMENTATION.md` — actual path: `docs/audit/ROUND-10-IMPLEMENTATION.md`

### I5. SECURITY.md has broken relative link

**File:** `docs/SECURITY.md:232`

Link `[SECURITY-AUDIT-REPORT.md](SECURITY-AUDIT-REPORT.md)` should be `[SECURITY-AUDIT-REPORT.md](audit/SECURITY-AUDIT-REPORT.md)`.

### I6. Cloud metadata endpoint blocking not documented

**File:** `container/init-firewall.sh:97-98`

`169.254.169.254/32` and `169.254.0.0/16` are blocked (AWS/GCP/Azure metadata endpoints), but this defense-in-depth layer is not mentioned in README.md, SECURITY.md, or ARCHITECTURE.md.

### I7. Audit round count is stale

**Files:** `README.md:278`, `docs/SECURITY.md:232`

Both say "11+" audit rounds, but the codebase includes rounds through 15 (with this report being round 16).

### I8. Architecture diagram missing `/run` tmpfs mount

**File:** `docs/ARCHITECTURE.md:34-41`

The mount diagram lists `/workspace`, `/mnt/.claude-host`, `~/.claude`, `/tmp`, `~/.npm`, `~/.config`, `/dev/shm` — but omits the `/run` tmpfs (1m, rw, nosuid, noexec) mounted at `run-claude.sh:497`. This mount is used for sandbox flags (`/run/sandbox-flags/allow-git-push`).

---

## Findings Reviewed and Excluded

These were flagged by the raw audit but are already documented as accepted limitations in SECURITY.md:

| Finding | Why excluded |
|---------|-------------|
| `api.todoist.com` exfiltration risk | Actively needed for Todoist MCP server. Same accepted risk profile as api.anthropic.com / api.github.com / registry.npmjs.org (SECURITY.md line 166). **Action:** Add `api.todoist.com` to the "API endpoint exfiltration" known limitation entry in SECURITY.md so future audits don't re-flag it. |
| Credential cache socket extractable by same-UID | SECURITY.md line 96: "fundamental same-UID constraint" — accepted HIGH |
| `.git/config` bypass via rename on bind-mount | SECURITY.md lines 156-159: post-exit audit is the real control, not chmod |
| Credential scrub 1-second window (best-effort) | SECURITY.md line 89: explicitly documented as "may persist on tmpfs for the session lifetime" |
| `/workspace` mounted read-write | SECURITY.md line 167: accepted MEDIUM, mitigated by post-exit audit |
| npm/npx execution risk | SECURITY.md line 171: accepted LOW, mitigated by noexec on `/tmp` |
| Firewall rule ordering (DROP set after init rules) | No attack window: no claude-user processes exist during init; only root runs |
| `nodump.c` prctl return check | Seccomp guarantees the call succeeds; theoretical only |
| Signal trap installed after child start | Window is microseconds; `--init` (tini) reaps orphans |
| `gosu` in final image | Read-only rootfs, all caps dropped — cannot be used for escalation |

---

## Verification Checklist

- [x] All file:line references cross-checked against current codebase
- [x] No accepted risks (documented in SECURITY.md) presented as bugs
- [x] Findings deduplicated against previous audit rounds
- [x] Confidence ratings provided for all actionable findings
- [x] Regression risk assessed for each proposed fix
