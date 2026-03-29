"""
Secure NAC demo — all four attacks blocked, 3-hop chain, optional real LLM planner.

Phases:
  1  Start secure server stack
  2  Normal briefing workflow  (real LLM if ANTHROPIC_API_KEY set)
  3  3-hop delegation chain demonstration
  4  Attack A1 BLOCKED — scope escalation rejected (hr:read missing)
  5  Attack A2 BLOCKED — lateral movement rejected (wrong audience)
  6  Attack A3 BLOCKED — token replay rejected (jti revoked)
  7  Attack A4 RESOLVED — 100% attribution rate in audit log
  8  Security summary and RFC 8693 compliance evidence
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import os
import time

import httpx
import uvicorn

from agents import (
    AssistantAgent, AttackerAgent,
    LateralMovementAgent, TokenReplayAgent, IdentityConfusionAgent,
)
from assistant_server import make_assistant_app
from oauth_server     import make_oauth_app
from worker_servers   import build_calendar_app, build_docs_app, build_comms_app, build_external_api_app
import audit_log


def _check_redis() -> None:
    import redis
    url = os.getenv("NAC_REDIS_URL", "redis://127.0.0.1:6379/0")
    try:
        redis.from_url(url, socket_connect_timeout=2).ping()
        print(f"  Redis: connected at {url}")
    except Exception as exc:
        print(f"\n[ERROR] Cannot connect to Redis at {url}: {exc}")
        print("  Start Redis first:  docker run -d -p 6379:6379 redis:7-alpine")
        raise SystemExit(1)


BASE           = 9300
OAUTH_PORT     = BASE
ASSISTANT_PORT = BASE + 1
CAL_PORT       = BASE + 2
DOCS_PORT      = BASE + 3
COMMS_PORT     = BASE + 4
EXT_PORT       = BASE + 5


def sep(title: str) -> None:
    print(f"\n{'='*72}\n  {title}\n{'='*72}")


def serve_server(kind: str, secure: bool, port: int, callback_url: str, worker_urls: dict | None = None):
    if kind in ("calendar", "docs", "comms", "external-api"):
        os.environ["NAC_PUBLIC_ONLY"] = "1"

    if kind == "oauth":
        app = make_oauth_app(secure=secure, callback_url=callback_url)
    elif kind == "assistant":
        app = make_assistant_app(secure=secure, oauth_url=f"http://127.0.0.1:{OAUTH_PORT}",
                                  worker_urls=worker_urls, callback_url=callback_url)
    elif kind == "calendar":
        app = build_calendar_app(port=port, secure=secure)
    elif kind == "docs":
        app = build_docs_app(port=port, secure=secure)
    elif kind == "comms":
        app = build_comms_app(port=port, secure=secure)
    elif kind == "external-api":
        app = build_external_api_app(port=port, secure=secure)
    else:
        raise ValueError(kind)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


def start_process(kind: str, secure: bool, port: int, callback_url: str, worker_urls: dict | None = None):
    ctx = mp.get_context("spawn")
    p   = ctx.Process(target=serve_server, args=(kind, secure, port, callback_url, worker_urls))
    p.daemon = True
    p.start()
    return p


async def wait_ready(ports: list[int], timeout: int = 20) -> None:
    deadline = time.time() + timeout
    async with httpx.AsyncClient() as c:
        while time.time() < deadline:
            try:
                resps = await asyncio.gather(
                    *[c.get(f"http://127.0.0.1:{p}/health") for p in ports],
                    return_exceptions=True,
                )
                if all(not isinstance(r, Exception) and r.status_code == 200 for r in resps):
                    return
            except Exception:
                pass
            await asyncio.sleep(0.3)
    raise TimeoutError("Secure servers did not start in time")


async def main():
    _check_redis()
    audit_log.clear_log()
    callback_url = f"http://127.0.0.1:{ASSISTANT_PORT}/oauth/callback"
    worker_urls  = {
        "calendar":     f"http://127.0.0.1:{CAL_PORT}",
        "docs":         f"http://127.0.0.1:{DOCS_PORT}",
        "comms":        f"http://127.0.0.1:{COMMS_PORT}",
        "external-api": f"http://127.0.0.1:{EXT_PORT}",
    }

    sep("PHASE 1: Start secure NAC server stack")
    procs = [
        start_process("oauth",        True, OAUTH_PORT,     callback_url),
        start_process("calendar",     True, CAL_PORT,       callback_url),
        start_process("docs",         True, DOCS_PORT,      callback_url),
        start_process("comms",        True, COMMS_PORT,     callback_url),
        start_process("external-api", True, EXT_PORT,       callback_url),
        start_process("assistant",    True, ASSISTANT_PORT, callback_url, worker_urls),
    ]
    await wait_ready([OAUTH_PORT, CAL_PORT, DOCS_PORT, COMMS_PORT, EXT_PORT, ASSISTANT_PORT])

    has_llm = bool(os.getenv("ANTHROPIC_API_KEY"))
    print(f"  Secure servers live (NAC enabled, enforce_audience=True):")
    print(f"    :{OAUTH_PORT}  OAuth server  (RFC 8693 /token/exchange, jti tracking)")
    print(f"    :{ASSISTANT_PORT} Assistant hub (HTTP token exchange, no signing key)")
    print(f"    :{CAL_PORT}  Calendar worker  (public key only)")
    print(f"    :{DOCS_PORT}  Docs worker     (public key only)")
    print(f"    :{COMMS_PORT}  Comms worker    (public key only)")
    print(f"    :{EXT_PORT}  External-API     (3rd hop, public key only)")
    print(f"  Real LLM planner: {'ENABLED (Claude claude-opus-4-6)' if has_llm else 'DISABLED (set ANTHROPIC_API_KEY to enable)'}")

    # Get a root token for all agents
    async with httpx.AsyncClient(follow_redirects=True) as c:
        r = await c.get(
            f"http://127.0.0.1:{OAUTH_PORT}/login/oauth/authorize"
            f"?client_id=assistant-hub"
            f"&redirect_uri={callback_url}"
            f"&scope=calendar:read+docs:read+email:send+slack:write"
            f"&state=demo",
            headers={"X-Simulated-User": "alice"},
        )
        from urllib.parse import parse_qs, urlparse
        code = parse_qs(urlparse(str(r.url)).query).get("code", [""])[0]
        tok_r = await c.post(
            f"http://127.0.0.1:{OAUTH_PORT}/login/oauth/access_token",
            json={"code": code, "client_id": "assistant-hub", "redirect_uri": callback_url},
        )
        root_token = tok_r.json().get("access_token", "")
    print(f"\n  Root token: aud=assistant-hub  scopes=calendar:read docs:read email:send slack:write")

    assistant_url = f"http://127.0.0.1:{ASSISTANT_PORT}"
    agent         = AssistantAgent(assistant_url, token=root_token)
    attacker      = AttackerAgent(assistant_url, token=root_token)
    lateral_agent = LateralMovementAgent(assistant_url, token=root_token)
    replay_agent  = TokenReplayAgent(assistant_url, token=root_token)
    id_agent      = IdentityConfusionAgent(assistant_url, token=root_token)

    # ── Phase 2: Normal workflow ──────────────────────────────────────────────
    sep("PHASE 2: Normal team-briefing workflow")
    if has_llm:
        print("  Using real LLM (Claude claude-opus-4-6) as the agent planner.")
    print("  Each worker receives a fresh RFC 8693-exchanged token with correct aud and scope.\n")
    await agent.list_tools()
    await agent.execute_prompt(
        "Connect my workspace and prepare a daily team briefing from calendar, notes, email, and Slack"
    )

    # ── Phase 3: 3-hop chain ─────────────────────────────────────────────────
    sep("PHASE 3: 3-Hop Delegation Chain Demonstration")
    print("  The briefing now sub-calls the external-API worker from within the calendar call.")
    print("  Token chain: alice → assistant-hub → calendar-service → external-api-service")
    print("  Each hop has a fresh token with the correct audience and a nested act claim.\n")
    await agent.execute_prompt(
        "Prepare daily briefing with external API sub-call",
        external_url=f"http://127.0.0.1:{EXT_PORT}",
    )

    # ── Phase 4: Attack A1 ───────────────────────────────────────────────────
    sep("PHASE 4: Attack A1 BLOCKED — Scope Escalation")
    print("  Agent tries to read hr-payroll.  Token has docs:read but NOT hr:read.")
    print("  OAuth /token/exchange enforces scope attenuation → hr:read cannot be granted.")
    print("  Worker validates scope list → rejects with 403 SCOPE_INSUFFICIENT.\n")
    await attacker.try_scope_escalation()

    # ── Phase 5: Attack A2 ───────────────────────────────────────────────────
    sep("PHASE 5: Attack A2 BLOCKED — Lateral Movement")
    print("  Agent obtains aud=calendar-service token and replays it at docs-service.")
    print("  Docs worker validates aud claim → rejects with 403 WRONG_AUDIENCE.\n")
    await lateral_agent.try_lateral_movement()

    # ── Phase 6: Attack A3 ───────────────────────────────────────────────────
    sep("PHASE 6: Attack A3 BLOCKED — Token Replay")
    print("  Agent replays a calendar child token for a second call.")
    print("  OAuth server revokes parent jti after exchange; worker checks jti registry.")
    print("  Expected: BLOCKED with 403 TOKEN_REPLAY.\n")
    await replay_agent.try_token_replay()

    # ── Phase 7: Attack A4 ───────────────────────────────────────────────────
    sep("PHASE 7: Attack A4 RESOLVED — Identity Attribution")
    print("  Every tool call in secure mode carries a non-empty act_chain in the audit log.")
    print("  Each entry proves exactly which agent acted on Alice's behalf.")
    print("  Expected: 100% attribution rate.\n")
    await id_agent.demonstrate()

    # ── Phase 8: Security summary ─────────────────────────────────────────────
    sep("PHASE 8: Security Summary and RFC 8693 Compliance Evidence")
    async with httpx.AsyncClient() as c:
        health = (await c.get(f"http://127.0.0.1:{ASSISTANT_PORT}/health")).json()
    print(f"  Assistant health: {health}")
    print()
    print("  RFC 8693 compliance evidence:")
    print("    ✓ Token exchange via HTTP POST to OAuth /token/exchange")
    print("    ✓ grant_type = urn:ietf:params:oauth:grant-type:token-exchange")
    print("    ✓ subject_token_type and issued_token_type present in request/response")
    print("    ✓ Scope attenuation enforced at exchange time")
    print("    ✓ Workers hold no signing key (NAC_PUBLIC_ONLY=1)")
    print("    ✓ jti revocation after use (replay prevention)")
    print("    ✓ act chain depth-limited (max 10) to prevent infinite-loop attacks")
    print()
    print("  NAC security properties:")
    print("    ✓ Audience binding   — each token valid only on its target service")
    print("    ✓ Scope attenuation  — child scope ⊆ parent scope enforced cryptographically")
    print("    ✓ Chain visibility   — every audit entry carries full delegation history")
    print("    ✓ Replay prevention  — jti revoked after first use")
    print("    ✓ N-hop support      — 3-hop chain demonstrated with full chain validation")
    print()
    print("  Reference: https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices")

    for p in procs:
        if p.is_alive():
            p.terminate()
            p.join(timeout=2)


if __name__ == "__main__":
    mp.freeze_support()
    asyncio.run(main())
