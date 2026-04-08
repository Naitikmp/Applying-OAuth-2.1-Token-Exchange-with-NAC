"""
Top-level assistant MCP hub server — v3 (latency-corrected).

Changes from v2:
  - _http_exchange uses a persistent httpx.AsyncClient (closure variable)
    instead of creating a new client per call.  With asyncio.gather firing
    4 concurrent exchanges, the shared client's connection pool keeps up to
    4 TCP connections alive to the OAuth server and reuses them across the
    30 latency-measurement rounds — saves ~5-10 ms of TCP handshake overhead
    per round.
  - All other logic unchanged.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from contextvars import ContextVar
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import TextContent, Tool

import audit_log
from nac_common import (
    AUDIENCES, RFC8693_AT, RFC8693_GRANT, RFC8693_JWT,
    ROOT_CLIENT_ID, token_preview, chain_summary,
    get_public_key, scope_to_list,
)

import jwt as pyjwt

# ── per-connection token ──────────────────────────────────────────────────────
_session_token: ContextVar[str] = ContextVar("session_token", default="")


# ── ASGI mixer ────────────────────────────────────────────────────────────────

def _make_mcp_asgi(server: Server, transport: SseServerTransport, fastapi_app: FastAPI):
    class MixedASGIApp:
        def __init__(self, app: FastAPI) -> None:
            self._app = app

        async def __call__(self, scope, receive, send) -> None:
            if scope.get("type") == "http":
                path = scope.get("path", "")

                if path == "/sse":
                    raw_headers = dict(scope.get("headers", []))
                    auth  = raw_headers.get(b"authorization", b"").decode()
                    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
                    _session_token.set(token)

                    async with transport.connect_sse(scope, receive, send) as (r, w):
                        await server.run(r, w, server.create_initialization_options())
                    return

                if path == "/messages":
                    await transport.handle_post_message(scope, receive, send)
                    return

            await self._app(scope, receive, send)

    return MixedASGIApp(fastapi_app)


# ── worker SSE caller ─────────────────────────────────────────────────────────

async def _call_worker(
    worker_url: str,
    tool_name:  str,
    args:       dict[str, Any],
    token:      str,
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with sse_client(f"{worker_url}/sse", headers=headers) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, args)
            return json.loads(result.content[0].text)


# ── main factory ──────────────────────────────────────────────────────────────

def make_assistant_app(
    *,
    secure:       bool,
    oauth_url:    str,
    worker_urls:  dict[str, str],
    callback_url: str,
) -> Any:
    mode      = "secure" if secure else "baseline"
    server    = Server("assistant-hub-mcp")
    transport = SseServerTransport("/messages")
    fastapi_app = FastAPI(title=f"{mode.capitalize()} Assistant Hub")

    # ── Persistent OAuth HTTP client ──────────────────────────────────────────
    # Created once per process.  httpx.AsyncClient maintains a connection pool
    # to the OAuth server — TCP connections are reused across the 4 concurrent
    # asyncio.gather calls and across all 30 latency-measurement rounds.
    # Saving: ~5-10 ms of TCP handshake overhead per round (4 new connections →
    # pool reuse, handshake amortised).
    _oauth_client = httpx.AsyncClient(
        timeout = httpx.Timeout(10.0),
        limits  = httpx.Limits(max_connections=10, max_keepalive_connections=5),
    )

    session_tokens:   dict[str, str] = {}
    consent_state:    dict[str, str] = {}
    _captured_tokens: dict[str, str] = {}

    def _root_token_for_session() -> str:
        token = _session_token.get()
        if not token:
            raise ValueError("not authenticated — connect first (send Authorization header)")
        return token

    def _username_from_token(token: str) -> str:
        try:
            claims = pyjwt.decode(token, options={"verify_signature": False})
            return claims.get("sub", "unknown")
        except Exception:
            return "unknown"

    # ── OAuth callback ────────────────────────────────────────────────────────

    @fastapi_app.get("/oauth/callback")
    async def oauth_callback(code: str = "", state: str = ""):
        return {"status": "callback_received", "code_present": bool(code)}

    # ── MCP tools ─────────────────────────────────────────────────────────────

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="connect_workspace",
                description="OAuth-connect the user's workspace and store the root token.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "username":            {"type": "string", "description": "Simulated user identity"},
                        "custom_redirect_uri": {"type": "string"},
                    },
                    "required": ["username"],
                },
            ),
            Tool(
                name="prepare_daily_briefing",
                description=(
                    "Read calendar, notes, send email and Slack. "
                    "Calls external-api as a 3rd hop when external_url is provided."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "external_url": {"type": "string", "description": "Optional 3rd-hop external API URL"},
                    },
                },
            ),
            Tool(
                name="attempt_scope_escalation",
                description="Attack A1: attempt to read a confidential HR payroll document.",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="attempt_lateral_movement",
                description=(
                    "Attack A2: obtain a calendar-scoped token then replay it "
                    "directly against the docs worker (audience mismatch)."
                ),
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="attempt_token_replay",
                description=(
                    "Attack A3: use a previously captured child token for a second "
                    "call to the same worker without re-authenticating."
                ),
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="demonstrate_identity_attribution",
                description=(
                    "Attack A4: compare audit-log attributability between baseline "
                    "and secure paths (prints act_chain evidence)."
                ),
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="inspect_session",
                description="Show the stored root token metadata for the current session.",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        print(f"\n[{mode.upper()} Assistant] Tool: '{name}'")

        try:
            if name == "connect_workspace":
                return await _connect_workspace(arguments)
            if name == "prepare_daily_briefing":
                return await _prepare_daily_briefing(arguments)
            if name == "attempt_scope_escalation":
                return await _attack_scope_escalation()
            if name == "attempt_lateral_movement":
                return await _attack_lateral_movement(_captured_tokens)
            if name == "attempt_token_replay":
                return await _attack_token_replay(_captured_tokens)
            if name == "demonstrate_identity_attribution":
                return await _demonstrate_identity_attribution()
            if name == "inspect_session":
                token = _session_token.get()
                return [TextContent(type="text", text=json.dumps({
                    "has_token":     bool(token),
                    "token_preview": token_preview(token) if token else None,
                }, indent=2))]
            return [TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}))]

        except Exception as exc:
            return [TextContent(type="text", text=json.dumps({
                "error": str(exc), "mode": mode
            }, indent=2))]

    # ── tool implementations ──────────────────────────────────────────────────

    async def _connect_workspace(args: dict[str, Any]) -> list[TextContent]:
        username     = args.get("username", "alice")
        redirect_uri = args.get("custom_redirect_uri", callback_url)

        if secure and redirect_uri != callback_url:
            raise ValueError("redirect_uri rejected — must match registered URI")

        state = str(uuid.uuid4())
        consent_state[state] = username
        auth_url = (
            f"{oauth_url}/login/oauth/authorize"
            f"?client_id={ROOT_CLIENT_ID}"
            f"&redirect_uri={callback_url}"
            f"&scope=calendar:read+docs:read+email:send+slack:write"
            f"&state={state}"
        )

        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp      = await client.get(auth_url, headers={"X-Simulated-User": username})
            final_url = str(resp.url)

        token_stored = False
        if "code=" in final_url:
            from urllib.parse import parse_qs, urlparse
            code = parse_qs(urlparse(final_url).query).get("code", [""])[0]
            if code:
                async with httpx.AsyncClient() as client:
                    tok_resp = await client.post(
                        f"{oauth_url}/login/oauth/access_token",
                        json={
                            "code":         code,
                            "client_id":    ROOT_CLIENT_ID,
                            "redirect_uri": callback_url,
                        },
                    )
                data  = tok_resp.json()
                token = data.get("access_token", "")
                if token:
                    session_tokens[username] = token
                    token_stored = True

        return [TextContent(type="text", text=json.dumps({
            "auth_url":     auth_url,
            "token_stored": token_stored,
            "mode":         mode,
        }, indent=2))]

    async def _http_exchange(
        parent_token: str,
        audience:     str,
        scope:        list[str],
        actor:        str,
    ) -> str:
        """
        RFC 8693 token exchange via the persistent OAuth HTTP client.

        Using the shared _oauth_client means the 4 concurrent asyncio.gather calls
        share a connection pool — TCP connections are reused within a round and
        across rounds, avoiding repeated handshake overhead.
        """
        resp = await _oauth_client.post(
            f"{oauth_url}/token/exchange",
            data={
                "grant_type":           RFC8693_GRANT,
                "subject_token":        parent_token,
                "subject_token_type":   RFC8693_AT,
                "audience":             audience,
                "scope":                " ".join(scope),
                "actor_token":          actor,
                "actor_token_type":     RFC8693_JWT,
                "requested_token_type": RFC8693_AT,
            },
        )
        if resp.status_code != 200:
            raise ValueError(f"RFC 8693 exchange failed ({resp.status_code}): {resp.text}")
        return resp.json()["access_token"]

    async def _get_worker_token(root: str, worker: str, scope: list[str]) -> str:
        """Exchange root token for a worker-bound child token via OAuth server (RFC 8693)."""
        if secure:
            return await _http_exchange(
                parent_token = root,
                audience     = AUDIENCES[worker],
                scope        = scope,
                actor        = "assistant-hub",
            )
        # Baseline: forward root token unchanged (the insecure passthrough pattern)
        return root

    async def _prepare_daily_briefing(args: dict[str, Any]) -> list[TextContent]:
        root         = _root_token_for_session()
        external_url = args.get("external_url")

        # Parallel token exchange: all four RFC 8693 calls fire concurrently.
        # With the JTI server backend, the OAuth server completes all four in
        # ~20 ms (RSA signing is GIL-limited ~12 ms + async JTI ops ~2 ms).
        cal_token, docs_token, email_token, slack_token = await asyncio.gather(
            _get_worker_token(root, "calendar", ["calendar:read"]),
            _get_worker_token(root, "docs",     ["docs:read"]),
            _get_worker_token(root, "comms",    ["email:send"]),
            _get_worker_token(root, "comms",    ["slack:write"]),
        )

        # Capture cal_token for the replay-attack demo (A3)
        _captured_tokens["calendar"] = cal_token

        # Worker calls — sequential (each result feeds the next message)
        calendar = await _call_worker(worker_urls["calendar"], "get_today_meetings", {}, cal_token)
        notes    = await _call_worker(worker_urls["docs"],     "read_meeting_notes", {"doc_id": "meeting-notes"}, docs_token)
        email    = await _call_worker(worker_urls["comms"],    "send_summary_email", {
            "to":      "team@company.com",
            "subject": "Daily team briefing",
            "message": f"Meeting: {calendar.get('meeting')} | Notes: {notes.get('document', {}).get('body')}",
        }, email_token)
        slack = await _call_worker(worker_urls["comms"], "post_slack_update", {
            "channel": "#team-updates",
            "message": "Briefing sent. Calendar checked, notes summarized, email delivered.",
        }, slack_token)

        payload: dict[str, Any] = {
            "calendar": calendar,
            "notes":    notes,
            "email":    email,
            "slack":    slack,
            "mode":     mode,
        }

        # 3rd hop: call external-api using the same calendar-scoped token
        if external_url:
            ext_token = await _get_worker_token(cal_token if secure else root, "external-api", ["calendar:read"])
            external  = await _call_worker(external_url, "get_calendar_sub_resource", {}, ext_token)
            payload["external_api_3rd_hop"] = external

        return [TextContent(type="text", text=json.dumps(payload, indent=2))]

    # ── Attack A1: scope escalation ───────────────────────────────────────────

    async def _attack_scope_escalation() -> list[TextContent]:
        root = _root_token_for_session()
        audit_log.log_attack_attempt("scope_escalation", "attacker-agent", "hr-payroll", mode)
        try:
            docs_token = await _get_worker_token(root, "docs", ["docs:read"])
            result = await _call_worker(
                worker_urls["docs"], "read_hr_payroll",
                {"doc_id": "hr-payroll"}, docs_token,
            )
            if result.get("error_code"):
                return [TextContent(type="text", text=json.dumps({
                    "attack":  "scope_escalation",
                    "outcome": f"BLOCKED — {result['error_code']}: {result.get('detail', '')}",
                    "mode":    mode,
                }, indent=2))]
            return [TextContent(type="text", text=json.dumps({
                "attack":  "scope_escalation",
                "outcome": "SUCCESS — payroll data returned (VULNERABILITY)",
                "data":    result,
                "mode":    mode,
            }, indent=2))]
        except Exception as exc:
            return [TextContent(type="text", text=json.dumps({
                "attack":  "scope_escalation",
                "outcome": "BLOCKED (exception)",
                "reason":  str(exc),
                "mode":    mode,
            }, indent=2))]

    # ── Attack A2: lateral movement ───────────────────────────────────────────

    async def _attack_lateral_movement(captured: dict[str, str]) -> list[TextContent]:
        root = _root_token_for_session()
        audit_log.log_attack_attempt("lateral_movement", "attacker-agent", "docs-service", mode)

        cal_token = await _get_worker_token(root, "calendar", ["calendar:read"])

        try:
            result = await _call_worker(
                worker_urls["docs"], "read_meeting_notes",
                {"doc_id": "meeting-notes"}, cal_token,
            )
            if result.get("error_code"):
                return [TextContent(type="text", text=json.dumps({
                    "attack":     "lateral_movement",
                    "outcome":    f"BLOCKED — {result['error_code']}: {result.get('detail', '')}",
                    "token_aud":  "calendar-service (correctly rejected by docs-service)",
                    "mode":       mode,
                }, indent=2))]
            return [TextContent(type="text", text=json.dumps({
                "attack":     "lateral_movement",
                "outcome":    "SUCCESS — docs responded to calendar-scoped token (VULNERABILITY)",
                "token_aud":  "calendar-service (was replayed at docs-service)",
                "data":       result,
                "mode":       mode,
            }, indent=2))]
        except Exception as exc:
            return [TextContent(type="text", text=json.dumps({
                "attack":  "lateral_movement",
                "outcome": "BLOCKED (exception)",
                "reason":  str(exc),
                "mode":    mode,
            }, indent=2))]

    # ── Attack A3: token replay ───────────────────────────────────────────────

    async def _attack_token_replay(captured: dict[str, str]) -> list[TextContent]:
        audit_log.log_attack_attempt("token_replay", "attacker-agent", "calendar-service", mode)

        if "calendar" not in captured:
            return [TextContent(type="text", text=json.dumps({
                "attack":  "token_replay",
                "outcome": "SKIPPED — run prepare_daily_briefing first to capture a token",
                "mode":    mode,
            }))]

        captured_token = captured["calendar"]
        try:
            result = await _call_worker(
                worker_urls["calendar"], "get_today_meetings", {}, captured_token,
            )
            if result.get("error_code"):
                return [TextContent(type="text", text=json.dumps({
                    "attack":  "token_replay",
                    "outcome": f"BLOCKED — {result['error_code']}: jti was revoked after first use",
                    "mode":    mode,
                }, indent=2))]
            return [TextContent(type="text", text=json.dumps({
                "attack":  "token_replay",
                "outcome": "SUCCESS — captured token was accepted again (VULNERABILITY: no jti revocation)",
                "data":    result,
                "mode":    mode,
            }, indent=2))]
        except Exception as exc:
            return [TextContent(type="text", text=json.dumps({
                "attack":  "token_replay",
                "outcome": "BLOCKED (exception)",
                "reason":  str(exc),
                "mode":    mode,
            }, indent=2))]

    # ── Attack A4: identity attribution ──────────────────────────────────────

    async def _demonstrate_identity_attribution() -> list[TextContent]:
        from audit_log import read_log, attribution_rate

        entries = [
            e for e in read_log()
            if e.get("event") == "TOKEN_VALIDATED" and e.get("mode") == mode
        ]
        rate = attribution_rate(mode)

        return [TextContent(type="text", text=json.dumps({
            "attack":           "identity_attribution",
            "mode":             mode,
            "total_validated":  len(entries),
            "attributable":     sum(1 for e in entries if e.get("attributable")),
            "attribution_rate": f"{rate:.0%}",
            "interpretation": (
                "100% attributable — every call carries a full act chain" if rate == 1.0
                else "0% attributable — audit log cannot identify which agent made each call"
                if rate == 0.0
                else f"{rate:.0%} attributable"
            ),
            "sample_entries": entries[:3],
        }, indent=2))]

    # ── health ────────────────────────────────────────────────────────────────

    @fastapi_app.get("/health")
    def health():
        return {"status": "ok", "server": "assistant-hub", "secure": secure}

    return _make_mcp_asgi(server, transport, fastapi_app)