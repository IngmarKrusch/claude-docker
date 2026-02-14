# Security Audit Round 12

**Date:** 2026-02-14
**Scope:** Full codebase, documentation, Dockerfile, all shell scripts, C sources, seccomp profile, firewall config
**Method:** Automated multi-agent review with cross-referencing against documented claims in README.md, docs/SECURITY.md, docs/ARCHITECTURE.md, and prior audit rounds (10, 11)

---

## Executive Summary

The codebase is a well-engineered defense-in-depth sandbox with 11 prior rounds of hardening. This audit identified **4 critical/high findings**, **9 medium findings**, and **8 low/informational findings**. The most significant gaps are in the network layer (exfiltration via allowlisted APIs, cloud metadata exposure, gVisor bypass) and supply chain (unpinned images, unverified downloads). Several findings from prior rounds remain partially addressed.

---

## Findings

### CRITICAL

#### R12-C01: Curl-Pipe-to-Bash Installation Without Integrity Verification

**File:** `Dockerfile:19, 28`
```dockerfile
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
RUN curl -fsSL https://claude.ai/install.sh | bash
```

**Impact:** A compromised CDN, MITM, or DNS hijack delivers arbitrary code execution as root during image build. No checksum, GPG signature, or pinned hash is verified.

**Fix Options:**
1. Pin Node.js via Debian package with version constraint (`apt-get install nodejs=22.*`)
2. Download scripts to a file, verify checksum, then execute
3. For Claude Code, verify the binary checksum post-download against a published hash

---

#### R12-C02: `api.todoist.com` Is a Direct Data Exfiltration Channel

**File:** `config/firewall-allowlist.conf:17`
```
api.todoist.com
```

**Impact:** The Todoist API accepts arbitrary POST data (task creation, notes). A compromised Claude session can exfiltrate workspace contents, credentials, or any data reachable from the container by creating Todoist tasks. This is the same class of risk that led to removing sentry.io and statsig.com.

**Fix Options:**
1. **Remove entirely** -- cleanest fix
2. **Move behind a flag** -- `--allow-todoist` that appends the line at runtime
3. **Document as accepted risk** -- if MCP integration is critical

---

#### R12-C03: Host Network Fully Allowed -- Cloud Metadata Endpoint Exposure

**File:** `container/init-firewall.sh:90-91`
```bash
iptables -A INPUT -s "$HOST_NETWORK" -j ACCEPT
iptables -A OUTPUT -d "$HOST_NETWORK" -j ACCEPT
```

**Impact:** On cloud VMs (AWS, GCP, Azure), the metadata endpoint at `169.254.169.254` is reachable through the host network allow rule. This exposes instance credentials, cloud API tokens, IAM role tokens, and other sensitive infrastructure data. On any host running services (databases, web servers, Docker socket proxy), those services are also reachable.

**Fix Options:**
1. Add explicit block before the host network allow:
   ```bash
   iptables -A OUTPUT -d 169.254.169.254 -j DROP
   iptables -A OUTPUT -d 169.254.0.0/16 -j DROP  # link-local range
   ```
2. Restrict host network access to only the gateway IP (not entire subnet)
3. Block Docker socket ports (2375/2376) explicitly

---

#### R12-C04: `--with-gvisor` Silently Disables All Firewall Protections

**File:** `run-claude.sh:287-290`

**Impact:** When `--with-gvisor` is used, the iptables firewall cannot initialize (gVisor virtualizes the network stack). The entrypoint logs a warning but the container runs with **unrestricted network access**, defeating the core security model. A user may not notice the warning in the output.

**Fix Options:**
1. **Refuse to start** unless `--allow-no-firewall` is also passed (fail-safe)
2. **Print a prominent banner** requiring user acknowledgment
3. **Use gVisor's network policy** instead of iptables (requires runsc configuration)

---

### HIGH

#### R12-H01: `PROJECT_PATH` Injection in sed Commands

**File:** `container/entrypoint.sh:45-46, 149`
```bash
sed -i "s|\"project\":\"${PROJECT_PATH}\"|\"project\":\"/workspace\"|g" \
    "$CLAUDE_DIR/history.jsonl" 2>/dev/null || true
```

**Impact:** `PROJECT_PATH` is an environment variable passed into the container. If it contains `|` (the sed delimiter), regex metacharacters, or sed command separators, the expression breaks or injects sed commands. While the value originates from `pwd` on the host, it flows through Docker's environment mechanism which could be manipulated.

**Fix Options:**
1. Validate `PROJECT_PATH` against `^/[a-zA-Z0-9._/ -]+$` before use
2. Use `jq` for JSON rewriting (correct tool for JSON manipulation)
3. Escape sed metacharacters in the variable before substitution

---

#### R12-H02: TOCTOU Race in `.git/config` Symlink Check

**File:** `run-claude.sh:556-560`
```bash
if [ -L "$PROJECT_DIR/.git/config" ]; then
    echo "[sandbox] DANGER: .git/config is a symlink -- removing it"
    rm -f "$PROJECT_DIR/.git/config"
fi
cp "$GIT_CONFIG_BACKUP" "$PROJECT_DIR/.git/config"
```

**Impact:** Between `rm -f` and `cp`, an attacker process could create a new symlink at `.git/config`, causing the backup to be written to an arbitrary file on the host filesystem.

**Fix Options:**
1. Write to a temp file and atomically rename:
   ```bash
   cp "$GIT_CONFIG_BACKUP" "$PROJECT_DIR/.git/.config.restored.tmp"
   mv -f "$PROJECT_DIR/.git/.config.restored.tmp" "$PROJECT_DIR/.git/config"
   ```
2. Use `install -m 644` which doesn't follow symlinks

---

#### R12-H03: Predictable Temp File Paths in `includeIf` Stripping

**File:** `run-claude.sh:574-577`, `container/entrypoint.sh:284-289`
```bash
_tmp="/workspace/.git/.includeif-strip.tmp"
awk '...' /workspace/.git/config > "$_tmp" && mv "$_tmp" /workspace/.git/config
```

**Impact:** The temp file path is deterministic. On the host side (post-exit audit), a pre-placed symlink at `.includeif-strip.tmp` causes the awk output to be written to an arbitrary file.

**Fix Options:**
1. Use `mktemp` with random suffix:
   ```bash
   _tmp=$(mktemp "$PROJECT_DIR/.git/.includeif-strip.XXXXXX")
   ```

---

#### R12-H04: `cp -P` Preserves Symlinks During Host-Side Staging

**File:** `run-claude.sh:335-357`
```bash
cp -P "$HOME/.claude/$f" "$CLAUDE_STAGING/" 2>/dev/null || true
cp -rP "$HOME/.claude/projects/$_HOST_ENCODED/." "$CLAUDE_STAGING/projects/$_HOST_ENCODED/" 2>/dev/null || true
```

**Impact:** `-P` preserves symbolic links. If any file in `~/.claude/` is a malicious symlink (e.g., placed by a previous compromised session), it gets mounted into the container. The entrypoint's `cp -P` at lines 24-91 also preserves these. Sync-back uses `rsync --no-links` (good), but the staging path does not have equivalent protection.

**Fix Options:**
1. Use `cp -L` (dereference symlinks) for staging
2. Add a pre-staging symlink scan: `find "$HOME/.claude" -type l -delete`
3. Use `rsync --no-links` for staging as well

---

### MEDIUM

#### R12-M01: Unquoted Variable Expansions in Docker Run Command

**File:** `run-claude.sh:461-497`
```bash
$RUNTIME_FLAG \
$GITCONFIG_MOUNT \
$CLAUDE_MOUNT_FLAGS \
$SYNC_BACK_FLAGS \
$ADD_HOST_FLAGS \
```

**Impact:** Word splitting occurs on these variables. While they're constructed internally, `$ADD_HOST_FLAGS` is built from DNS resolution output (`dig +short`). A malicious DNS response with crafted content could inject Docker flags. Paths containing spaces would also break.

**Fix Option:** Convert to bash arrays:
```bash
ADD_HOST_FLAGS=()
ADD_HOST_FLAGS+=("--add-host=${domain}:${ip}")
# Then: "${ADD_HOST_FLAGS[@]}"
```

---

#### R12-M02: Unpinned Base Image Tag

**File:** `Dockerfile:1`
```dockerfile
FROM debian:bookworm-slim
```

**Impact:** A supply-chain compromise of the `bookworm-slim` tag silently propagates. Rebuilds may produce different images.

**Fix Option:** Pin to digest: `FROM debian:bookworm-slim@sha256:<digest>`

---

#### R12-M03: `registry.npmjs.org` Exfiltration Potential

**File:** `config/firewall-allowlist.conf:8`

**Impact:** If npm credentials exist in the workspace (`.npmrc`), `npm publish` can exfiltrate data as package contents. Even without credentials, npm package metadata requests leak information about project dependencies.

**Fix Options:**
1. Block npm publish by adding `--ignore-scripts` enforcement
2. Make npm access a runtime flag (`--allow-npm`)
3. Accept as documented risk (required for MCP server installation)

---

#### R12-M04: `git clone --config` Bypasses git-guard

**File:** `container/git-guard.c` (missing handling)

**Impact:** `git clone --config core.fsmonitor=...` passes config via a subcommand-specific flag, not the global `-c` flag. The git-guard's `-c` parsing (lines 179-199) only catches `git -c key=value`, not `git clone --config key=value`.

**Fix Option:** Add `clone` subcommand handling to inspect `--config` arguments:
```c
if (strcmp(subcmd, "clone") == 0) {
    for (int j = sub_idx + 1; j < argc; j++) {
        if (strcmp(argv[j], "--config") == 0 && j + 1 < argc) {
            if (check_config_arg(argv[j + 1])) block("...");
        }
    }
}
```

---

#### R12-M05: No `ip6tables` Rules as Defense-in-Depth

**File:** `container/init-firewall.sh`

**Impact:** IPv6 is disabled via sysctl (`net.ipv6.conf.all.disable_ipv6=1`), but no `ip6tables` rules exist. If the sysctl is bypassed or reset, IPv6 traffic is unfiltered.

**Fix Option:** Add `ip6tables -P INPUT DROP && ip6tables -P OUTPUT DROP && ip6tables -P FORWARD DROP`

---

#### R12-M06: `SUSPECT_FILES` Is a String, Not an Array

**File:** `run-claude.sh:403, 647`
```bash
SUSPECT_FILES=".envrc .vscode/settings.json .vscode/tasks.json Makefile ..."
for _sf in $SUSPECT_FILES; do
```

**Impact:** Word splitting iteration is fragile. If any filename ever contains glob characters (`*`, `?`), they'd be expanded against the current directory.

**Fix Option:** Convert to bash array:
```bash
SUSPECT_FILES=(.envrc .vscode/settings.json .vscode/tasks.json Makefile ...)
for _sf in "${SUSPECT_FILES[@]}"; do
```

---

#### R12-M07: Docker DNS Rule Re-Injection via `xargs`

**File:** `container/init-firewall.sh:28-29`
```bash
DOCKER_DNS_RULES=$(iptables-save -t nat | grep "127\.0\.0\.11" || true)
echo "$DOCKER_DNS_RULES" | xargs -L 1 iptables -t nat
```

**Impact:** `xargs` without `-0` is fragile with special characters in iptables-save output (rule comments, etc.). While the source is trusted, a `while read` loop is more robust.

**Fix Option:**
```bash
while IFS= read -r rule; do
    iptables -t nat $rule
done <<< "$DOCKER_DNS_RULES"
```

---

#### R12-M08: Loose IP Address Validation

**File:** `run-claude.sh:447-453`
```bash
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
```

**Impact:** Accepts invalid IPs like `999.999.999.999`. Docker rejects truly invalid entries, but tighter validation prevents unexpected behavior.

**Fix Option:** Validate octets are 0-255:
```bash
grep -E '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
```

---

#### R12-M09: Credential Tempfile Race Window

**File:** `run-claude.sh:296-298, 425`

**Impact:** Between `mktemp` creation and the deferred `rm -f` (~2 seconds), the credential file is readable by any process running as the same host user. `mktemp` defaults to mode 0600, but this is umask-dependent.

**Fix Option:** Use `install -m 600 /dev/null "$ENVFILE"` for creation, or use Docker secrets/stdin-based credential passing.

---

### LOW

#### R12-L01: `sanitize_ansi` Regex Incomplete

**File:** `run-claude.sh:10-12`

**Impact:** Does not handle DCS (Device Control String: `ESC P...ST`), SOS/PM/APC sequences, or 8-bit C1 control codes (0x80-0x9F). Could allow terminal injection via crafted filenames.

---

#### R12-L02: Host Project Path Exposed via Environment Variable

**File:** `run-claude.sh:494`

**Impact:** `PROJECT_PATH` reveals host filesystem structure (username, directory layout) to the container. Informational exposure only.

---

#### R12-L03: `lint.sh` Pulls Unpinned Docker Image

**File:** `lint.sh:4`
```bash
docker run --rm -i hadolint/hadolint < "$SCRIPT_DIR/Dockerfile"
```

**Impact:** Supply-chain risk. The hadolint image is not pinned to a digest.

---

#### R12-L04: Symlink Syscalls Allowed in Seccomp Profile

**File:** `config/seccomp-profile.json:77`

**Impact:** Claude can create symlinks in `/workspace`. Sync-back uses `rsync --no-links` (mitigated), but symlinks within the workspace could point to `/proc` or `/etc` during the session.

---

#### R12-L05: `git-guard.c` key_buf Limited to 256 Bytes

**File:** `container/git-guard.c:97`

**Impact:** A config key longer than 256 bytes would bypass the `check_config_arg` function (returns 0). Git config keys are never this long in practice.

---

#### R12-L06: `git remote remove` Not Blocked

**File:** `container/git-guard.c:221-227`

**Impact:** `git remote remove` is allowed while `add`/`set-url`/`rename` are blocked. However, `.git/config` is root:root 444, so the command would fail to write the config change. Mitigated by filesystem immutability.

---

#### R12-L07: GIT_CONFIG_GLOBAL Not Cleared by git-guard

**File:** `container/git-guard.c:121-129`

**Impact:** A child process could set `GIT_CONFIG_GLOBAL` to a controlled file. Mitigated by `GIT_CONFIG_COUNT` override precedence and root-owned gitconfig.

---

#### R12-L08: Compiler Toolchain in Docker Layer Cache

**File:** `Dockerfile:8-88`

**Impact:** gcc is installed for compilation then purged, but remains in earlier Docker layers. An attacker with access to layer cache could recover it.

**Fix Option:** Use multi-stage build: compile in builder stage, `COPY --from=builder` the `.so` files.

---

## Redundant / Overlapping Controls

| Control A | Control B | Assessment |
|-----------|-----------|------------|
| `git-wrapper.sh` (GIT_CONFIG_COUNT) | `git-guard.so` (GIT_CONFIG_COUNT) | **Intentional.** Wrapper covers statically-linked edge case. Keep both. |
| `setuid bit stripping` (Dockerfile) | `--security-opt=no-new-privileges` (run-claude.sh) | **Intentional.** Independent enforcement. Keep both. |
| `nodump.so` (PR_SET_DUMPABLE=0) | `chmod 711 wrapped-git` | **Intentional.** Different mechanisms, same goal. Keep both. |
| `.git/config` sanitization (entrypoint) | `.git/config` immutability (root:root 444) | **Intentional.** Sanitization cleans; immutability prevents re-contamination. Keep both. |
| Git env var clearing (git-guard.c) | GIT_CONFIG_COUNT forcing (git-guard.c) | **Complementary.** Different attack surfaces. Keep both. |
| DNS blocking (iptables UID match) | Pre-resolved /etc/hosts (--add-host) | **Intentional.** Blocking prevents dynamic resolution; /etc/hosts provides static resolution. Keep both. |

**Verdict:** No redundancies should be removed. All overlapping controls serve distinct purposes or cover each other's failure modes.

---

## Simplification Opportunities

### S1: Multi-Stage Docker Build
Consolidate the gcc install/compile/purge sequence into a builder stage. Eliminates 3 Dockerfile sections and removes the compiler from all layers.

### S2: Bash Arrays for Docker Flags
Converting `$ADD_HOST_FLAGS`, `$CLAUDE_MOUNT_FLAGS`, `$SYNC_BACK_FLAGS` etc. from strings to arrays eliminates the SC2086 shellcheck disables and makes the code more robust and readable.

### S3: `jq` for JSON Rewriting
Replace the `sed` history.jsonl rewriting with `jq`, eliminating the regex injection risk and handling edge cases correctly.

### S4: Consolidate Temp File Handling
Create a single `safe_tempfile()` function that uses `mktemp` with proper mode, adds the path to a cleanup list, and handles SIGKILL-orphan cleanup via the deferred-delete pattern already used for `ENVFILE`.

---

## Prior Audit Findings Status

| Finding | Round | Status in R12 |
|---------|-------|---------------|
| F-01: Domain fronting | R10 | **Fixed** -- VS Code domains removed |
| F-02: Credential cache socket | R10 | **Accepted risk** -- documented, fine-grained PATs recommended |
| F-03: MAX_CMDLINE truncation | R10 | **Fixed** -- blocks on truncation |
| F-05: Diverging blocked-key lists | R10 | **Partially fixed** -- git-guard.so is primary, wrapper is belt-and-suspenders |
| F-07: Sync-back before audit | R10 | **Fixed** -- audit runs, sync-back locked by root |
| F-08: Host network /24 hardcoded | R10 | **Improved** -- uses `ip route` CIDR, but see R12-C03 (metadata endpoint) |
| F-09: drop-dumpable.c no value | R10 | **Fixed** -- replaced by nodump.so (LD_PRELOAD constructor) |
| R11-01: Git filter TOCTOU | R11 | **Fixed** -- .git/config now root:root 444 |
| R11-02: git credential fill | R11 | **Fixed** -- blocked in git-guard.c |
| R11-04: Sync-back staging writable | R11 | **Fixed** -- root:root 700 after init |
| R11-05: PR_SET_DUMPABLE bypass | R11 | **Fixed** -- seccomp blocks PR_SET_DUMPABLE non-zero |
| R11-06: Incomplete suspect files | R11 | **Fixed** -- expanded list includes package.json, .npmrc, etc. |

---

## Recommendations Summary (Priority Order)

| # | Severity | Finding | Effort |
|---|----------|---------|--------|
| 1 | **Critical** | R12-C02: Remove `api.todoist.com` from allowlist | Trivial |
| 2 | **Critical** | R12-C03: Block cloud metadata endpoint (169.254.0.0/16) | Small |
| 3 | **Critical** | R12-C04: Make `--with-gvisor` fail without explicit acknowledgment | Small |
| 4 | **Critical** | R12-C01: Verify checksums for curl-pipe-to-bash installs | Medium |
| 5 | **High** | R12-H01: Validate/escape PROJECT_PATH in sed or use jq | Small |
| 6 | **High** | R12-H02: Atomic .git/config restore (mv instead of cp) | Trivial |
| 7 | **High** | R12-H03: Use mktemp for includeIf stripping | Trivial |
| 8 | **High** | R12-H04: Use `cp -L` or `rsync --no-links` for staging | Trivial |
| 9 | **Medium** | R12-M01: Convert docker flags to bash arrays | Medium |
| 10 | **Medium** | R12-M02: Pin base image to digest | Trivial |
| 11 | **Medium** | R12-M04: Block `git clone --config` in git-guard | Small |
| 12 | **Medium** | R12-M05: Add ip6tables DROP policy | Trivial |
| 13 | **Medium** | R12-M06: Convert SUSPECT_FILES to array | Trivial |
| 14 | **Medium** | R12-M08: Tighten IP validation regex | Trivial |

---

## Overall Assessment

The sandbox demonstrates mature, iterative security engineering with 11 prior audit rounds producing measurable hardening. The defense-in-depth architecture (seccomp + capabilities + iptables + LD_PRELOAD + read-only rootfs + post-exit audit) is well-designed, with each layer independently mitigating distinct attack classes.

**Strongest aspects:**
- Git operation enforcement (three independent layers)
- Credential lifecycle management (scrub + scope + cache)
- Firewall fail-closed design
- Post-exit tamper detection
- Seccomp prctl filtering for nodump protection

**Weakest aspects:**
- Network allowlist includes exfiltration-capable endpoints (todoist, npm, GitHub API)
- Supply chain integrity (curl-pipe-to-bash, unpinned images)
- Host network over-permissiveness (metadata endpoints, full subnet access)
- Shell quoting fragility in the launch script

The residual attack surface is primarily in the **allowed network endpoints** -- any API that accepts POST data is an exfiltration channel. This is a fundamental tension between functionality (MCP servers, git push, npm install) and isolation, and should be managed through token scoping and runtime flags rather than trying to eliminate it entirely.
