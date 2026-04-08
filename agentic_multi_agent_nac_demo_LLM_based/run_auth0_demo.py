"""
Auth0 Real-IdP Integration Demo — RFC 8693 NAC Sidecar Pattern.

What this script proves
-----------------------
The NAC pattern (RFC 8693 token exchange with Nested Actor Claims) integrates
with Auth0 as a real identity provider using the "lightweight exchange sidecar"
path described in the paper's Practical Adoption Checklist (§ V.D).

Specifically:
  • Auth0 issues the root token T₀ via M2M client_credentials grant.
  • Our sidecar (auth0_exchange_server.py) validates T₀ against Auth0's live
    JWKS endpoint, then issues NAC child tokens T₁ signed by our RSA key.
  • All four security properties are verified against real signed JWTs:
      A1 Scope escalation  — BLOCKED at sidecar (scope ⊄ parent)
      A2 Audience mismatch — BLOCKED by worker (aud claim rejected)
      A3 Token replay      — BLOCKED by Redis JTI revocation
      A4 Identity chain    — VISIBLE in act claim (Auth0 client preserved)

Prerequisites
-------------
  1. docker run -d -p 6379:6379 redis:7-alpine
  2. Create a .env file with your Auth0 credentials:
     - AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET
     - AUTH0_HUB_AUDIENCE, AUTH0_ROOT_SCOPES
  3. pip install -r requirements.txt  (includes python-dotenv for auto-loading)
  4. python run_auth0_demo.py   (auto-loads .env on all platforms)

Usage
-----
  python run_auth0_demo.py                # full demo
  python run_auth0_demo.py --check-only   # validate config without running
"""

from __future__ import annotations

import argparse
import asyncio
import json
import multiprocessing as mp
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import uvicorn

# Auto-load .env if it exists (works on Windows, Linux, Mac)
_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    from dotenv import load_dotenv
    load_dotenv(_env_file)

from auth0_config import (
    AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET,
    AUTH0_HUB_AUDIENCE, AUTH0_ROOT_SCOPES,
    AUTH0_EXCHANGE_PORT,
    validate_config,
)
from auth0_exchange_server import make_auth0_exchange_app
from nac_common import (
    validate_token, is_jti_revoked, revoke_jti, clear_jti_store,
    AUDIENCES, TRUSTED_ACTORS,
)
import jwt as pyjwt


# ── helpers ───────────────────────────────────────────────────────────────────

EXCHANGE_URL = f"http://127.0.0.1:{AUTH0_EXCHANGE_PORT}/token/exchange"
RFC8693_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
RFC8693_AT    = "urn:ietf:params:oauth:token-type:access_token"
RFC8693_JWT   = "urn:ietf:params:oauth:token-type:jwt"

PASS = "PASS"
FAIL = "FAIL"

results: list[dict[str, Any]] = []


def sep(title: str) -> None:
    print(f"\n{'='*70}\n  {title}\n{'='*70}")


def check(label: str, passed: bool, detail: str = "") -> None:
    status = PASS if passed else FAIL
    mark   = "✓" if passed else "✗"
    print(f"  [{mark}] {label:<45} {status}")
    if detail:
        print(f"       {detail}")
    results.append({"label": label, "passed": passed, "detail": detail})


# ── server startup ────────────────────────────────────────────────────────────

def _serve_exchange(port: int) -> None:
    app = make_auth0_exchange_app()
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


def start_exchange_server() -> mp.Process:
    ctx = mp.get_context("spawn")
    p   = ctx.Process(target=_serve_exchange, args=(AUTH0_EXCHANGE_PORT,))
    p.daemon = True
    p.start()
    return p


async def wait_ready(url: str, timeout: int = 15) -> None:
    deadline = time.time() + timeout
    async with httpx.AsyncClient() as c:
        while time.time() < deadline:
            try:
                r = await c.get(url.replace("/token/exchange", "/health"))
                if r.status_code == 200:
                    return
            except Exception:
                pass
            await asyncio.sleep(0.3)
    raise TimeoutError(f"Exchange server did not start within {timeout}s")


# ── Auth0 token acquisition ───────────────────────────────────────────────────

async def get_auth0_root_token(client: httpx.AsyncClient) -> str:
    """
    Obtain a root token T₀ from Auth0 using the M2M client_credentials grant.

    The M2M flow requires no browser interaction — ideal for automated demos
    and CI pipelines.  Scopes must be pre-configured in Auth0 (see AUTH0_SETUP.md).
    """
    response = await client.post(
        f"https://{AUTH0_DOMAIN}/oauth/token",
        json={
            "client_id":     AUTH0_CLIENT_ID,
            "client_secret": AUTH0_CLIENT_SECRET,
            "audience":      AUTH0_HUB_AUDIENCE,
            "grant_type":    "client_credentials",
            "scope":         AUTH0_ROOT_SCOPES,   # request all hub scopes explicitly
        },
        timeout=15.0,
    )
    if response.status_code != 200:
        print(f"\n[ERROR] Auth0 token request failed ({response.status_code}):")
        print(f"  {response.text}")
        raise SystemExit(1)
    return response.json()["access_token"]


async def exchange_for_child(
    client:    httpx.AsyncClient,
    parent:    str,
    audience:  str,
    scope:     str,
    actor:     str = "assistant-hub",
) -> dict[str, Any]:
    """Call the sidecar /token/exchange endpoint and return the full response JSON."""
    response = await client.post(
        EXCHANGE_URL,
        data={
            "grant_type":         RFC8693_GRANT,
            "subject_token":      parent,
            "subject_token_type": RFC8693_AT,
            "audience":           audience,
            "scope":              scope,
            "actor_token":        actor,
            "actor_token_type":   RFC8693_JWT,
        },
        timeout=10.0,
    )
    return {"status_code": response.status_code, "body": response.json()}


# ── demo phases ───────────────────────────────────────────────────────────────

def check_config() -> bool:
    sep("Phase 1 — Auth0 Configuration Check")
    missing = validate_config()
    if missing:
        print(f"\n  [✗] Missing required environment variables:")
        for m in missing:
            print(f"      {m}")
        print("\n  See AUTH0_SETUP.md for step-by-step setup instructions.")
        return False

    print(f"  AUTH0_DOMAIN    : {AUTH0_DOMAIN}")
    print(f"  AUTH0_CLIENT_ID : {AUTH0_CLIENT_ID[:8]}{'*' * (len(AUTH0_CLIENT_ID) - 8)}")
    print(f"  HUB_AUDIENCE    : {AUTH0_HUB_AUDIENCE}")
    print(f"  ROOT_SCOPES     : {AUTH0_ROOT_SCOPES}")
    check("Auth0 config loaded from environment", True)
    return True


def check_redis() -> None:
    sep("Phase 2 — Redis JTI Store")
    import redis
    url = os.getenv("NAC_REDIS_URL", "redis://127.0.0.1:6379/0")
    try:
        r = redis.from_url(url, socket_connect_timeout=2)
        r.ping()
        clear_jti_store()
        check("Redis connected and JTI store cleared", True, f"url={url}")
    except Exception as exc:
        check("Redis connection", False, str(exc))
        print("\n  Start Redis:  docker run -d -p 6379:6379 redis:7-alpine")
        raise SystemExit(1)


async def phase_root_token(client: httpx.AsyncClient) -> str:
    sep("Phase 3 — Auth0 Root Token (T₀)")
    print("  Calling Auth0 /oauth/token with client_credentials grant ...")
    t0 = await get_auth0_root_token(client)

    # Inspect the token (no signature verification needed here — sidecar handles that)
    claims = pyjwt.decode(t0, options={"verify_signature": False})
    sub    = claims.get("sub", "")
    aud    = claims.get("aud", "")
    scope  = claims.get("scope", "")
    jti    = claims.get("jti", "(none — enable in Auth0 Actions if needed)")
    exp    = claims.get("exp", 0)

    print(f"\n  sub   : {sub}")
    print(f"  aud   : {aud}")
    print(f"  scope : {scope}")
    print(f"  jti   : {jti}")
    print(f"  exp   : {exp} (TTL {max(0, exp - int(time.time()))}s)")
    print(f"  iss   : {claims.get('iss')}")

    check("T₀ issued by Auth0",    claims.get("iss", "").startswith(f"https://{AUTH0_DOMAIN}"))
    check("T₀ audience = hub API", AUTH0_HUB_AUDIENCE in (aud if isinstance(aud, list) else [aud]))

    if not scope:
        print("\n  [!] Auth0 returned an EMPTY scope. Fix required in Auth0 Dashboard:")
        print("      1. Applications → APIs → MCP Hub → Permissions tab")
        print("         → Add: calendar:read  docs:read  comms:send  external:fetch")
        print("      2. Applications → MCP Hub M2M → APIs tab → MCP Hub")
        print("         → click Authorize → check ALL four scopes → Update")
        print("      Then re-run this script.\n")

    check("T₀ scope includes calendar:read", "calendar:read" in scope)
    if "calendar:read" not in scope:
        raise SystemExit(1)
    return t0


async def phase_normal_exchange(client: httpx.AsyncClient, t0: str) -> str:
    sep("Phase 4 — Normal Token Exchange (T₀ → T₁ for calendar-service)")
    resp = await exchange_for_child(
        client,
        parent   = t0,
        audience = AUDIENCES["calendar"],
        scope    = "calendar:read",
        actor    = "assistant-hub",
    )
    check("Sidecar returns HTTP 200", resp["status_code"] == 200,
          f"got {resp['status_code']}: {resp['body'].get('error', '')}")

    if resp["status_code"] != 200:
        raise SystemExit(1)

    t1 = resp["body"]["access_token"]
    c1 = pyjwt.decode(t1, options={"verify_signature": False})

    print(f"\n  T₁ iss   : {c1.get('iss')} (our sidecar)")
    print(f"  T₁ sub   : {c1.get('sub')} (Auth0 client identity preserved)")
    print(f"  T₁ aud   : {c1.get('aud')} (scoped to calendar-service only)")
    print(f"  T₁ scope : {c1.get('scope')} (attenuated from root)")
    print(f"  T₁ act   : {json.dumps(c1.get('act'), indent=6)}")

    check("T₁ issued by our sidecar (not Auth0)",      c1.get("iss") == "https://agentic-nac-demo.local")
    check("T₁ audience = calendar-service",            c1.get("aud") == AUDIENCES["calendar"])
    check("T₁ scope = calendar:read (attenuated)",     c1.get("scope") == "calendar:read")
    check("T₁ act.sub = assistant-hub",                c1.get("act", {}).get("sub") == "assistant-hub")
    check("T₁ act.auth0_client = Auth0 app ID",        bool(c1.get("act", {}).get("auth0_client")))
    return t1


async def phase_a1_scope_escalation(client: httpx.AsyncClient, t0: str) -> None:
    sep("Phase 5 — Attack A1: Scope Escalation (should be BLOCKED)")
    print("  Attempting to exchange T₀ for a token with hr:read (not in root scopes) ...")
    resp = await exchange_for_child(
        client,
        parent   = t0,
        audience = AUDIENCES["calendar"],
        scope    = "calendar:read hr:read",   # hr:read not in Auth0 root token
        actor    = "malicious-actor",
    )
    blocked = resp["status_code"] == 400
    check(
        "A1 scope escalation BLOCKED by sidecar",
        blocked,
        f"HTTP {resp['status_code']} — {resp['body'].get('detail', {}).get('detail', '')}",
    )


async def phase_a2_audience_mismatch(t1_calendar: str) -> None:
    sep("Phase 6 — Attack A2: Audience Mismatch (should be BLOCKED)")
    print("  Presenting calendar token (aud=calendar-service) to docs-service validator ...")
    try:
        validate_token(
            token             = t1_calendar,
            expected_audience = AUDIENCES["docs"],   # wrong audience
            required_scopes   = ["docs:read"],
            enforce_audience  = True,
        )
        check("A2 audience mismatch BLOCKED by worker", False, "token was wrongly accepted")
    except Exception as exc:
        check("A2 audience mismatch BLOCKED by worker", True, f"rejected: {exc}")


async def phase_a3_token_replay(t1: str) -> None:
    sep("Phase 7 — Attack A3: Token Replay (should be BLOCKED)")
    t1_claims = pyjwt.decode(t1, options={"verify_signature": False})
    t1_jti    = t1_claims.get("jti", "")

    print(f"  T₁ JTI: {t1_jti}")
    print("  Simulating first use: worker revokes T₁ JTI in Redis ...")
    if t1_jti:
        revoke_jti(t1_jti)

    print("  Simulating replay: second use of same T₁ ...")
    try:
        validate_token(
            token             = t1,
            expected_audience = AUDIENCES["calendar"],
            required_scopes   = ["calendar:read"],
            enforce_audience  = True,
            enforce_jti       = True,
        )
        check("A3 token replay BLOCKED by Redis JTI check", False, "token was wrongly accepted")
    except Exception as exc:
        check("A3 token replay BLOCKED by Redis JTI check", True, f"rejected: {exc}")


async def phase_a4_identity_chain(t0: str, t1: str) -> None:
    sep("Phase 8 — Attack A4: Identity Attribution (chain must be visible)")
    t0_claims = pyjwt.decode(t0, options={"verify_signature": False})
    t1_claims = pyjwt.decode(t1, options={"verify_signature": False})

    auth0_sub       = t0_claims.get("sub", "")
    t1_sub          = t1_claims.get("sub", "")
    t1_act          = t1_claims.get("act", {})
    acting_hub      = t1_act.get("sub", "")
    auth0_client_id = t1_act.get("auth0_client", "")

    print(f"\n  Delegation chain in T₁:")
    print(f"    end user / Auth0 client : {auth0_sub}")
    print(f"    acting hub              : {acting_hub}")
    print(f"    Auth0 app ID in act     : {auth0_client_id}")
    print(f"    T₁ sub (identity)       : {t1_sub}")

    check("Auth0 sub preserved in T₁.sub",      t1_sub == auth0_sub)
    check("Hub identity in T₁.act.sub",         acting_hub == "assistant-hub")
    check("Auth0 app ID visible in act chain",   bool(auth0_client_id))
    check("A4 attribution: 100% chain visible",  bool(auth0_sub and acting_hub))


async def main(check_only: bool = False) -> None:
    if not check_config():
        raise SystemExit(1)

    if check_only:
        print("\n  --check-only flag set; exiting after config validation.")
        return

    check_redis()

    sep("Starting Auth0 Exchange Sidecar")
    proc = start_exchange_server()
    print(f"  Exchange server PID: {proc.pid}  port: {AUTH0_EXCHANGE_PORT}")

    async with httpx.AsyncClient() as client:
        print("  Waiting for sidecar to become ready ...")
        await wait_ready(EXCHANGE_URL)
        print(f"  Sidecar ready at http://127.0.0.1:{AUTH0_EXCHANGE_PORT}")

        t0 = await phase_root_token(client)
        t1 = await phase_normal_exchange(client, t0)
        await phase_a1_scope_escalation(client, t0)

    await phase_a2_audience_mismatch(t1)
    await phase_a3_token_replay(t1)
    await phase_a4_identity_chain(t0, t1)

    # ── Summary ───────────────────────────────────────────────────────────────
    sep("Summary")
    passed = sum(1 for r in results if r["passed"])
    total  = len(results)
    print(f"\n  Checks passed : {passed}/{total}")
    print(f"  IdP           : Auth0 ({AUTH0_DOMAIN})")
    print(f"  Root token    : Auth0 M2M client_credentials grant")
    print(f"  Exchange      : RFC 8693 sidecar ({EXCHANGE_URL})")
    print(f"  JWKS source   : https://{AUTH0_DOMAIN}/.well-known/jwks.json (live)")
    print(f"\n  Security properties confirmed with real Auth0 root token:")
    print(f"    P1 Audience binding   — child token aud ≠ root aud")
    print(f"    P2 Scope attenuation  — A1 escalation blocked at sidecar")
    print(f"    P3 Delegation chain   — act chain preserved with Auth0 client ID")
    print(f"    JTI one-time-use      — A3 replay blocked by Redis")

    if passed < total:
        print(f"\n  {total - passed} check(s) failed — review output above.")
        raise SystemExit(1)

    print(f"\n  All {total} checks passed.")
    proc.terminate()


if __name__ == "__main__":
    mp.freeze_support()
    parser = argparse.ArgumentParser(description="Auth0 NAC integration demo")
    parser.add_argument(
        "--check-only", action="store_true",
        help="Validate Auth0 config and exit without starting servers",
    )
    args = parser.parse_args()
    asyncio.run(main(check_only=args.check_only))
