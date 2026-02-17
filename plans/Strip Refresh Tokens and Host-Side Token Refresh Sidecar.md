# Strip Refresh Tokens + Host-Side Token Refresh Sidecar

## Context

The credentials JSON (extracted from the macOS keychain as a single blob)
contains both Anthropic OAuth tokens and MCP server OAuth tokens (Todoist,
Granola, etc.). The Anthropic refresh token is useless inside the container
(OAuth endpoint `console.anthropic.com` not in firewall allowlist) and
should be stripped. MCP refresh tokens have a different story.

### Key research findings

1. **Anthropic refresh tokens are single-use** — consuming one invalidates
   it server-side and returns a NEW refresh token. The sidecar must persist
   the new refresh token to the keychain atomically.
2. **Claude Code caches access tokens in memory** — updating
   `.credentials.json` via docker exec may not be picked up until Claude
   Code re-reads the file. Needs testing.
3. **Anthropic OAuth refresh**: `POST https://console.anthropic.com/v1/oauth/token`
   with `Content-Type: application/x-www-form-urlencoded`, params:
   `grant_type=refresh_token`, `refresh_token=<token>`,
   `client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e`.
   Response: `{ access_token, refresh_token, expires_in }`.
4. **MCP tokens are different**: each MCP server has its own OAuth flow,
   endpoints, and client_id. We don't know these parameters and can't
   refresh MCP tokens from the host. But some MCP refresh endpoints ARE
   reachable from inside the container (e.g., `api.todoist.com` is in the
   firewall allowlist), so Claude Code can self-refresh those.
5. **`apiKeyHelper`** is for API key auth only, not OAuth.

### Why strip Anthropic refresh token but keep MCP refresh tokens

| | Anthropic OAuth | MCP OAuth (Todoist, Granola, etc.) |
|---|---|---|
| Refresh endpoint reachable? | No (`console.anthropic.com` not allowlisted) | Some yes (`api.todoist.com`), some no |
| Can host sidecar refresh? | Yes — we know the endpoint + client_id | No — provider-specific, unknown params |
| What happens if stripped? | No impact (already can't refresh) | MCP services die after access token TTL |
| Recommendation | **Strip** | **Keep** |

---

## Part 1: Strip Anthropic Refresh Token

### File: `run-claude.sh`

After the auto-refresh logic, strip ONLY the Anthropic refresh token:

```bash
CREDS=$(python3 -c "
import json, sys
creds = json.loads(sys.stdin.read())
if 'claudeAiOauth' in creds and isinstance(creds['claudeAiOauth'], dict):
    creds['claudeAiOauth']['refreshToken'] = ''
json.dump(creds, sys.stdout, separators=(',', ':'))
" <<< "$CREDS")
```

- Targets only `claudeAiOauth.refreshToken` (not MCP entries)
- Sets to `""` (not deleted — avoids KeyError in Claude Code)
- Preserves all MCP OAuth entries intact (access + refresh tokens)

---

## Part 2: Host-Side Token Refresh Sidecar

A background process on the host that refreshes the Anthropic access token
before it expires and injects it into the running container via `docker exec`.

### Design

```
HOST (sidecar)                         CONTAINER
───────────────────                    ──────────────────
keychain refresh token                 .credentials.json:
        │                                claudeAiOauth.accessToken (fresh)
        ▼  every ~50 min                 claudeAiOauth.refreshToken = ""
POST console.anthropic.com                MCP tokens intact (self-refresh)
        │                                       ▲
        ├─► update keychain                     │
        │   (new refresh + access)              │
        └─► docker exec: update ────────────────┘
            accessToken + expiresAt
```

### Implementation

1. **Container naming**: `CONTAINER_NAME="claude-sandbox-$$"` with
   `--name "$CONTAINER_NAME"` on docker run
2. **Sidecar function** (`_token_refresh_sidecar`): loops every 50 min,
   reads keychain, calls OAuth endpoint, updates keychain FIRST, then
   docker exec to inject new access token
3. **Lifecycle**: launched as background process before docker run,
   killed after docker exits, also cleaned up via EXIT trap

### Critical ordering

The keychain update happens BEFORE the docker exec injection because:
- The old refresh token is already consumed (invalidated server-side)
- If docker exec fails, we at least have the new tokens in the keychain
- If the keychain update fails after consuming the token, the refresh
  token is lost (user must `claude login`) — but this window is minimal

---

## Risks

### Claude Code may not re-read `.credentials.json`

If it caches the access token in memory and never re-reads, the docker exec
injection has no effect. Needs testing — start a container, wait for near-
expiry, docker exec to update the token, see if Claude Code picks it up.

**If it doesn't work**: document the ~1h session limit and investigate
sending a signal to Claude Code to trigger re-read.

### Keychain update failure

If the sidecar consumes the refresh token (server-side invalidation) but
crashes before writing the new one to the keychain, the refresh token is
lost. User must run `claude login`.

**Mitigation**: keychain update is the first action after receiving the
response. Failure window is minimal.

---

## Verification

1. **Refresh token stripped**: Start container, check
   `jq '.claudeAiOauth.refreshToken' ~/.claude/.credentials.json` → `""`
2. **MCP tokens intact**: Check that MCP OAuth entries still have their
   refresh tokens
3. **Claude Code starts normally**: No auth errors on startup
4. **Sidecar refresh**: Wait ~55 min (or reduce sleep for testing), verify
   new access token appears in container's `.credentials.json`
5. **Keychain updated**: After sidecar refresh, verify keychain has new
   refresh token (not the consumed one)
6. **Container exit**: Sidecar dies cleanly

---

## Files modified

- `run-claude.sh` — refresh token stripping, container naming, sidecar
  function, sidecar lifecycle
- `docs/ROADMAP.md` — updated credential landscape table, added Anthropic
  Token Refresh Sidecar and MCP OAuth Token Analysis roadmap items
- `docs/SECURITY.md` — documented refresh token stripping and sidecar in
  credential protection section
- `plans/Strip Refresh Tokens and Host-Side Token Refresh Sidecar.md` —
  this file
