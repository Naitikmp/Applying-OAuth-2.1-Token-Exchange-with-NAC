"""
Baseline (problem) demo — token passthrough, all four attack vectors demonstrated.

This script starts the insecure server stack and exercises:
  Phase 1  Start servers
  Phase 2  Normal team-briefing workflow
  Phase 3  Attack A1 — scope escalation (HR payroll)
  Phase 4  Attack A2 — lateral movement (calendar token → docs)
  Phase 5  Attack A3 — token replay (jti not tracked)
  Phase 6  Attack A4 — identity confusion (audit log attribution)
  Phase 7  Summary of vulnerabilities
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

BASE           = 9200
OAUTH_PORT     = BASE
ASSISTANT_PORT = BASE + 1
CAL_PORT       = BASE + 2
DOCS_PORT      = BASE + 3
COMMS_PORT     = BASE + 4
EXT_PORT       = BASE + 5


def sep(title: str) -> None:
    print(f"\n{'='*72}\n  {title}\n{'='*72}")


def serve_server(kind: str, secure: bool, port: int, callback_url: str, worker_urls: dict | None = None):
    # Workers must not hold the signing key
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
    raise TimeoutError("Baseline servers did not start in time")


async def main():
    audit_log.clear_log()
    callback_url = f"http://127.0.0.1:{ASSISTANT_PORT}/oauth/callback"
    worker_urls  = {
        "calendar":     f"http://127.0.0.1:{CAL_PORT}",
        "docs":         f"http://127.0.0.1:{DOCS_PORT}",
        "comms":        f"http://127.0.0.1:{COMMS_PORT}",
        "external-api": f"http://127.0.0.1:{EXT_PORT}",
    }

    sep("PHASE 1: Start baseline (insecure) server stack")
    procs = [
        start_process("oauth",        False, OAUTH_PORT,     callback_url),
        start_process("calendar",     False, CAL_PORT,       callback_url),
        start_process("docs",         False, DOCS_PORT,      callback_url),
        start_process("comms",        False, COMMS_PORT,     callback_url),
        start_process("external-api", False, EXT_PORT,       callback_url),
        start_process("assistant",    False, ASSISTANT_PORT, callback_url, worker_urls),
    ]
    await wait_ready([OAUTH_PORT, CAL_PORT, DOCS_PORT, COMMS_PORT, EXT_PORT, ASSISTANT_PORT])
    print(f"  Servers live (all insecure, enforce_audience=False):")
    print(f"    :{OAUTH_PORT}  OAuth server  (no redirect-URI binding, no jti tracking)")
    print(f"    :{ASSISTANT_PORT} Assistant hub (token passthrough, no RFC 8693 exchange)")
    print(f"    :{CAL_PORT}  Calendar worker")
    print(f"    :{DOCS_PORT}  Docs worker")
    print(f"    :{COMMS_PORT}  Comms worker")
    print(f"    :{EXT_PORT}  External-API worker")

    # Get a root token for all agents to use
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
    print(f"\n  Root token obtained (aud=assistant-hub, all scopes)")

    assistant_url = f"http://127.0.0.1:{ASSISTANT_PORT}"
    agent         = AssistantAgent(assistant_url, token=root_token)
    attacker      = AttackerAgent(assistant_url, token=root_token)
    lateral_agent = LateralMovementAgent(assistant_url, token=root_token)
    replay_agent  = TokenReplayAgent(assistant_url, token=root_token)
    id_agent      = IdentityConfusionAgent(assistant_url, token=root_token)

    # ── Phase 2: Normal workflow ──────────────────────────────────────────────
    sep("PHASE 2: Normal team-briefing workflow")
    await agent.list_tools()

    # Run the briefing directly (bypasses LLM planner) to ensure captured_tokens
    # is populated before the A3 replay test
    async def _run_briefing_direct():
        from mcp.client.session import ClientSession
        from mcp.client.sse import sse_client as _sse
        import json as _json
        headers = {"Authorization": f"Bearer {root_token}"}
        async with _sse(f"{assistant_url}/sse", headers=headers) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                result = await s.call_tool("prepare_daily_briefing", {})
                parsed = _json.loads(result.content[0].text)
                print("\n[Agent] Tool result: prepare_daily_briefing")
                print(_json.dumps(parsed, indent=2)[:600])

    await _run_briefing_direct()

    # ── Phase 3: Attack A1 — Scope Escalation ────────────────────────────────
    sep("PHASE 3: Attack A1 — Scope Escalation (HR payroll read)")
    print("  A mis-scoped agent tries to read confidential HR payroll data.")
    print("  In baseline: the token has docs:read in scope and aud is not checked.")
    print("  Expected: SUCCEEDS — vulnerability demonstrated.\n")
    await attacker.try_scope_escalation()

    # ── Phase 4: Attack A2 — Lateral Movement ────────────────────────────────
    sep("PHASE 4: Attack A2 — Lateral Movement (calendar token → docs worker)")
    print("  A token obtained for calendar is replayed against docs.")
    print("  In baseline: aud is not enforced, so any valid token passes.")
    print("  Expected: SUCCEEDS — token crosses service boundary undetected.\n")
    await lateral_agent.try_lateral_movement()

    # ── Phase 5: Attack A3 — Token Replay ────────────────────────────────────
    sep("PHASE 5: Attack A3 — Token Replay (captured token reused)")
    print("  A child token captured from the briefing call is replayed.")
    print("  In baseline: no jti revocation list, replay accepted within TTL.")
    print("  Expected: SUCCEEDS — jti is cosmetic only.\n")
    await replay_agent.try_token_replay()

    # ── Phase 6: Attack A4 — Identity Confusion ──────────────────────────────
    sep("PHASE 6: Attack A4 — Identity Attribution (audit log)")
    print("  Measure what fraction of calls carry a verifiable act chain.")
    print("  In baseline: act_chain=[] on every log entry — cannot tell who called.")
    print("  Expected: 0% attribution rate.\n")
    await id_agent.demonstrate()

    # ── Phase 7: Summary ──────────────────────────────────────────────────────
    sep("PHASE 7: Vulnerability Summary")
    print("  All four attack vectors succeed in baseline mode:\n")
    print("  A1 Scope escalation   — hr:read scope never issued, yet HR data returned")
    print("  A2 Lateral movement   — aud=calendar-service token accepted by docs-service")
    print("  A3 Token replay       — same jti accepted twice within TTL window")
    print("  A4 Identity confusion — 0% of audit entries carry act chain (zero attributability)")
    print()
    print("  Root cause: single token forwarded unchanged; aud/scope/chain not enforced.")
    print("  This is exactly the token passthrough pattern banned by the MCP spec.")
    print("  See: https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices")

    for p in procs:
        if p.is_alive():
            p.terminate()
            p.join(timeout=2)


if __name__ == "__main__":
    mp.freeze_support()
    asyncio.run(main())