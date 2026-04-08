# Auth0 Integration Setup Guide
## NAC Demo — RFC 8693 Sidecar Pattern

This guide walks you through connecting the NAC demo to a **real Auth0 tenant**
so that the root token T₀ is issued by Auth0 (not the internal mock OAuth server).

Total time: **~15 minutes**. Auth0 free tier is sufficient.

---

## What You Are Building

```
Auth0 (real IdP)
   │  client_credentials grant
   │  issues T₀ (Auth0 RS256 JWT)
   ▼
auth0_exchange_server.py  (RFC 8693 sidecar, port 9400)
   │  validates T₀ against Auth0's live JWKS endpoint
   │  issues child token T₁ (our RS256 JWT, scope-attenuated)
   ▼
Worker services
   │  validate T₁ against sidecar /jwks
   │  enforce aud, scope, act chain, JTI one-time-use
   ▼
All four NAC security properties confirmed with a real IdP root token
```

---

## Step 1 — Create a Free Auth0 Account

1. Go to <https://auth0.com> → **Sign Up** (free tier is enough)
2. Choose a tenant name (e.g. `nac-demo`). Your domain will be:
   `nac-demo.us.auth0.com`  ← note this down, it is `AUTH0_DOMAIN`

---

## Step 2 — Create the Hub API (resource server)

This defines what the root token T₀ is **for** (its `aud` claim).

> **⚠️ IMPORTANT: You do NOT need a custom domain for this!**
> 
> The **Identifier** (`https://mcp-hub.example.com`) is just a logical string used inside JWT tokens. It does NOT need to be a real, resolvable domain. Auth0 never tries to reach this URL. You can use:
> - The example value as-is: `https://mcp-hub.example.com`
> - Or any unique string like: `https://YOUR_TENANT.us.auth0.com/hub-api`
> 
> Just make sure whatever you choose, you use the **exact same string** for `AUTH0_HUB_AUDIENCE` in your environment variables.

1. Dashboard → **Applications** → **APIs** → **+ Create API**
2. Fill in:
   - **Name**: `MCP Hub`
   - **Identifier**: `https://mcp-hub.example.com`  ← this is `AUTH0_HUB_AUDIENCE`
   - **Signing Algorithm**: RS256
3. Click **Create**
4. Open the new API → **Permissions** tab → **+ Add a Permission** for each scope:

   | Permission       | Description                     |
   |------------------|---------------------------------|
   | `calendar:read`  | Read calendar events            |
   | `docs:read`      | Read documents                  |
   | `comms:send`     | Send communications             |
   | `external:fetch` | Fetch from external APIs        |

5. Click **Save Changes**

> **⚠️ MOST COMMON FAILURE: empty `scope` in Auth0 token**
> If you get `scope : ` (empty) in the demo output, the permissions above were
> not added OR the M2M app was not authorized for them (Step 3 below is the fix).

---

## Step 3 — Create a Machine-to-Machine Application

This is the "MCP Hub" client that requests T₀.

1. Dashboard → **Applications** → **Applications** → **+ Create Application**
2. Fill in:
   - **Name**: `MCP Hub M2M`
   - **Application Type**: Machine to Machine Applications
3. Click **Create**
4. On the next screen, select the **MCP Hub** API you just created
5. **Expand the scopes list** → check all four scopes:
   - `calendar:read`, `docs:read`, `comms:send`, `external:fetch`
6. Click **Authorize**

7. Open the application → **Settings** tab → copy:
   - **Domain**        → `AUTH0_DOMAIN`
   - **Client ID**     → `AUTH0_CLIENT_ID`
   - **Client Secret** → `AUTH0_CLIENT_SECRET`

---

## Step 4 — (Optional) Enable JTI in Auth0 Tokens

By default, Auth0 M2M tokens do not include a `jti` claim.
The sidecar handles this gracefully (it generates a synthetic session ID),
but if you want end-to-end JTI tracking, enable it with an Auth0 Action:

1. Dashboard → **Actions** → **Library** → **Build Custom**
2. Name: `Add JTI to M2M Tokens` | Trigger: **Machine to Machine**
3. Paste this code:

```javascript
exports.onExecuteCredentialsExchange = async (event, api) => {
  api.accessToken.setCustomClaim("jti", require("crypto").randomUUID());
};
```

4. Deploy → attach to the **Machine to Machine** flow

---

## Step 5 — Configure Environment Variables

```bash
# Copy the example file
cp .env.example .env.auth0   # or just create .env manually

# Edit .env with your values:
AUTH0_DOMAIN=YOUR_TENANT.us.auth0.com
AUTH0_CLIENT_ID=YOUR_CLIENT_ID
AUTH0_CLIENT_SECRET=YOUR_CLIENT_SECRET
AUTH0_HUB_AUDIENCE=https://mcp-hub.example.com
AUTH0_ROOT_SCOPES=calendar:read docs:read comms:send external:fetch

# Install dependencies (includes python-dotenv for auto-loading)
pip install -r requirements.txt
```

> **Note:** The script automatically loads `.env` on Windows, Linux, and Mac — no manual env var setup needed!

---

## Step 6 — Start Redis

```bash
docker run -d -p 6379:6379 --name nac-redis redis:7-alpine
```

---

## Step 7 — Run the Demo

```bash
# Just run it! The script auto-loads .env.auth0 on all platforms
python run_auth0_demo.py
```

### Validate config without running
```bash
python run_auth0_demo.py --check-only
```

---

## Expected Output

```
======================================================================
  Phase 1 — Auth0 Configuration Check
======================================================================
  AUTH0_DOMAIN    : nac-demo.us.auth0.com
  AUTH0_CLIENT_ID : abcd1234********************
  HUB_AUDIENCE    : https://mcp-hub.example.com
  ROOT_SCOPES     : calendar:read docs:read comms:send external:fetch
  [✓] Auth0 config loaded from environment              PASS

======================================================================
  Phase 3 — Auth0 Root Token (T₀)
======================================================================
  sub   : abcd1234XXXX@clients
  aud   : https://mcp-hub.example.com
  scope : calendar:read docs:read comms:send external:fetch
  iss   : https://nac-demo.us.auth0.com/
  [✓] T₀ issued by Auth0                               PASS
  [✓] T₀ audience = hub API                            PASS
  [✓] T₀ scope includes calendar:read                  PASS

======================================================================
  Phase 4 — Normal Token Exchange (T₀ → T₁ for calendar-service)
======================================================================
  T₁ iss   : https://agentic-nac-demo.local (our sidecar)
  T₁ sub   : abcd1234XXXX@clients (Auth0 identity preserved)
  T₁ aud   : calendar-service (scoped to calendar only)
  T₁ scope : calendar:read (attenuated from root)
  T₁ act   : {
        "sub": "assistant-hub",
        "act": null,
        "auth0_client": "abcd1234XXXX"
      }
  [✓] T₁ issued by our sidecar (not Auth0)             PASS
  [✓] T₁ audience = calendar-service                   PASS
  [✓] T₁ scope = calendar:read (attenuated)            PASS
  [✓] T₁ act.sub = assistant-hub                       PASS
  [✓] T₁ act.auth0_client = Auth0 app ID               PASS

======================================================================
  Phase 5 — Attack A1: Scope Escalation (should be BLOCKED)
======================================================================
  [✓] A1 scope escalation BLOCKED by sidecar           PASS

======================================================================
  Phase 6 — Attack A2: Audience Mismatch (should be BLOCKED)
======================================================================
  [✓] A2 audience mismatch BLOCKED by worker           PASS

======================================================================
  Phase 7 — Attack A3: Token Replay (should be BLOCKED)
======================================================================
  [✓] A3 token replay BLOCKED by Redis JTI check       PASS

======================================================================
  Phase 8 — Attack A4: Identity Attribution
======================================================================
  [✓] Auth0 sub preserved in T₁.sub                   PASS
  [✓] Hub identity in T₁.act.sub                       PASS
  [✓] Auth0 app ID visible in act chain                PASS
  [✓] A4 attribution: 100% chain visible               PASS

======================================================================
  Summary
======================================================================
  Checks passed : 17/17
  IdP           : Auth0 (nac-demo.us.auth0.com)
  Root token    : Auth0 M2M client_credentials grant
  Exchange      : RFC 8693 sidecar (http://127.0.0.1:9400/token/exchange)
  JWKS source   : https://nac-demo.us.auth0.com/.well-known/jwks.json (live)

  Security properties confirmed with real Auth0 root token:
    P1 Audience binding   — child token aud ≠ root aud
    P2 Scope attenuation  — A1 escalation blocked at sidecar
    P3 Delegation chain   — act chain preserved with Auth0 client ID
    JTI one-time-use      — A3 replay blocked by Redis
```

---

## How This Relates to the Paper

This demo exercises the **"deploy a lightweight exchange sidecar"** path from
the Practical Adoption Checklist (§ V.D, Step 1):

> If your IdP does not natively support RFC 8693 (Auth0 Token Vault is
> Enterprise-only), deploy a lightweight exchange sidecar that validates
> the IdP token via its published JWKS endpoint and issues NAC child tokens.

The key integration point is `auth0_exchange_server.py` line ~85:
```python
jwks_client = _get_auth0_jwks_client()          # fetches Auth0's public key
signing_key = jwks_client.get_signing_key_from_jwt(token)
claims = jwt.decode(token, signing_key.key, algorithms=["RS256"], audience=...)
```

This is the only code change needed to support a real IdP — all downstream
NAC machinery (scope enforcement, JTI revocation, act chain) is unchanged.

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `401 Unauthorized` from Auth0 | Wrong client_id or client_secret | Re-copy from Auth0 dashboard |
| `"Unknown API"` from Auth0 | Audience not registered | Check AUTH0_HUB_AUDIENCE matches API Identifier exactly |
| `"Client has not been granted scopes"` (403) | M2M app not authorized for API scopes | **Auth0 Dashboard → Applications → MCP Hub M2M → APIs tab → Authorize → check all scopes** |
| `scope not in token` | Scopes not authorized for M2M app | Applications → APIs → Authorize → check all scopes |
| `Redis connection refused` | Redis not running | `docker run -d -p 6379:6379 redis:7-alpine` |
| `AUTH0_DOMAIN is not configured` | Env var missing | Run `python run_auth0_demo.py --check-only` to diagnose |
| `InvalidIssuerError` | DOMAIN mismatch | Verify token `iss` == `https://<AUTH0_DOMAIN>/` exactly |
| "Do I need a custom domain?" | No! | The Identifier is just a logical string, not a real URL. Use `https://mcp-hub.example.com` as-is or any unique string. |
