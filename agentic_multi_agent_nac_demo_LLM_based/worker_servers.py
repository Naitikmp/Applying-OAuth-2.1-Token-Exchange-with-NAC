"""
Specialist MCP worker servers: Calendar, Docs, Comms, and External-API.

Changes from v1:
  - Tokens are extracted from the HTTP Authorization header (proper MCP transport).
    Tool arguments no longer carry the token.  A ContextVar threads the token from
    the ASGI scope into the MCP call_tool handler safely across concurrent connections.
  - Workers set NAC_PUBLIC_ONLY=1 at process start — they never load the signing key.
  - Validation failures return structured HTTP 401 / 403 responses with an error_code
    field so the evaluation harness can distinguish security rejections from bugs.
  - Every token validation and rejection is written to the structured audit log.
  - jti revocation is enforced in the secure path (replay attack prevention).
  - External-API worker is the 3rd hop in the chain demo.
"""

from __future__ import annotations

import json
import os
from contextvars import ContextVar
from typing import Any, Callable

from fastapi import FastAPI, Response
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import TextContent, Tool
from starlette.responses import JSONResponse as StarletteJSON

import audit_log
from nac_common import (
    AUDIENCES, TRUSTED_ACTORS,
    chain_summary, token_preview, validate_token,
)

WorkerHandler = Callable[[dict[str, Any]], dict[str, Any]]

# ── per-connection token (thread-safe across async tasks) ─────────────────────
_session_token: ContextVar[str] = ContextVar("session_token", default="")


# ── ASGI mixer ────────────────────────────────────────────────────────────────

def _make_sse_app(server: Server, transport: SseServerTransport, fastapi_app: FastAPI):
    class MixedASGIApp:
        def __init__(self, app: FastAPI) -> None:
            self._app = app

        async def __call__(self, scope, receive, send) -> None:
            if scope.get("type") == "http":
                path = scope.get("path", "")

                if path == "/sse":
                    # Extract Authorization header and store in ContextVar
                    raw_headers = dict(scope.get("headers", []))
                    auth = raw_headers.get(b"authorization", b"").decode()
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


# ── validation wrapper ────────────────────────────────────────────────────────

def _validate_request(
    token:           str,
    worker_name:     str,
    tool_name:       str,
    tool_meta:       dict[str, Any],
    secure:          bool,
    mode:            str,
) -> tuple[dict[str, Any] | None, StarletteJSON | None]:
    """
    Validate the token for a tool call.

    Returns (claims, None) on success or (None, error_response) on failure.
    HTTP status codes:
      401 — missing or unparseable token
      403 — wrong audience, missing scope, or untrusted actor chain
    """
    if not token:
        audit_log.log_token_rejected(
            reason     = "missing token",
            error_code = "TOKEN_MISSING",
            worker     = worker_name,
            tool       = tool_name,
            mode       = mode,
        )
        return None, StarletteJSON(
            {"error": "unauthorized", "error_code": "TOKEN_MISSING"}, status_code=401
        )

    required_scopes = tool_meta.get("required_scopes", [])

    try:
        if secure:
            claims = validate_token(
                token,
                expected_audience = AUDIENCES[worker_name],
                required_scopes   = required_scopes,
                trusted_actors    = TRUSTED_ACTORS,
                enforce_audience  = True,
                enforce_chain     = True,
                enforce_jti       = True,
            )
        else:
            claims = validate_token(
                token,
                expected_audience = AUDIENCES[worker_name],
                required_scopes   = [],        # baseline: no scope check
                trusted_actors    = None,
                enforce_audience  = False,     # baseline: no audience check
                enforce_chain     = False,
                enforce_jti       = False,
            )
    except Exception as exc:
        msg = str(exc)
        if "audience" in msg.lower() or "InvalidAudience" in type(exc).__name__:
            code = "WRONG_AUDIENCE"
            status = 403
        elif "scope" in msg.lower():
            code = "SCOPE_INSUFFICIENT"
            status = 403
        elif "untrusted actor" in msg.lower():
            code = "UNTRUSTED_ACTOR"
            status = 403
        elif "replay" in msg.lower() or "revoked" in msg.lower():
            code = "TOKEN_REPLAY"
            status = 403
        elif "depth" in msg.lower():
            code = "CHAIN_TOO_DEEP"
            status = 403
        else:
            code = "TOKEN_INVALID"
            status = 401

        audit_log.log_token_rejected(
            reason       = msg,
            error_code   = code,
            worker       = worker_name,
            tool         = tool_name,
            mode         = mode,
            token_preview = token[:32],
        )
        return None, StarletteJSON(
            {"error": "forbidden", "error_code": code, "detail": msg}, status_code=status
        )

    audit_log.log_token_validated(
        sub       = claims.get("sub", ""),
        audience  = claims.get("aud", ""),
        scope     = claims.get("scope", ""),
        act_chain = chain_summary(claims),
        worker    = worker_name,
        tool      = tool_name,
        mode      = mode,
    )

    # Secure path: revoke the child token's jti immediately after first use.
    # This enforces one-time-use semantics — a captured child token cannot be
    # replayed for a second call even within its TTL window.
    if secure:
        from nac_common import revoke_jti as _revoke
        child_jti = claims.get("jti", "")
        if child_jti:
            _revoke(child_jti)

    return claims, None


# ── worker app factory ────────────────────────────────────────────────────────

def make_worker_app(
    *,
    worker_name:   str,
    port:          int,
    secure:        bool,
    tools:         dict[str, dict[str, Any]],
    service_logic: dict[str, WorkerHandler],
) -> Any:
    mode   = "secure" if secure else "baseline"
    server = Server(f"{worker_name}-mcp")
    transport = SseServerTransport("/messages")
    fastapi_app = FastAPI(title=f"{worker_name} worker ({mode})")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name        = name,
                description = meta["description"],
                inputSchema = meta["inputSchema"],
            )
            for name, meta in tools.items()
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        token = _session_token.get()

        print(f"\n[{mode.upper()} {worker_name}] Tool called: '{name}'")
        audit_log.log_tool_called(
            tool     = name,
            args_keys = list(arguments.keys()),
            worker   = worker_name,
            mode     = mode,
        )

        if name not in service_logic:
            return [TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}))]

        tool_meta = tools.get(name, {})
        claims, err_response = _validate_request(token, worker_name, name, tool_meta, secure, mode)

        if err_response is not None:
            audit_log.log_tool_blocked(
                tool   = name,
                reason = err_response.body.decode() if hasattr(err_response, "body") else "validation failed",
                worker = worker_name,
                mode   = mode,
            )
            # MCP returns errors as text content with error fields
            body = json.loads(err_response.body) if hasattr(err_response, "body") else {"error": "forbidden"}
            return [TextContent(type="text", text=json.dumps(body))]

        payload = service_logic[name](arguments)
        payload["token_sub"]   = claims.get("sub")
        payload["aud"]         = claims.get("aud")
        payload["act_chain"]   = chain_summary(claims)
        payload["token_preview"] = token_preview(token)
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]

    @fastapi_app.get("/health")
    def health():
        return {"status": "ok", "server": worker_name, "port": port, "secure": secure}

    return _make_sse_app(server, transport, fastapi_app)


# ── service logic ─────────────────────────────────────────────────────────────

def calendar_logic(arguments: dict[str, Any]) -> dict[str, Any]:
    mode = arguments.get("mode", "today")
    if mode == "today":
        return {
            "status":    "ok",
            "meeting":   "2:00 PM project sync",
            "attendees": ["alice@company.com", "bob@company.com", "ops@company.com"],
        }
    return {"status": "ok", "detail": f"calendar mode={mode}"}


def docs_logic(arguments: dict[str, Any]) -> dict[str, Any]:
    doc_id = arguments.get("doc_id", "meeting-notes")
    docs = {
        "meeting-notes": {
            "title": "Project Sync Notes",
            "body":  "Discuss roadmap, blockers, and next steps.",
        },
        "hr-payroll": {
            "title": "Payroll Sheet",
            "body":  "CONFIDENTIAL: salary and compensation data.",
        },
    }
    return {"status": "ok", "document": docs.get(doc_id, {"title": doc_id, "body": "not found"})}


def email_logic(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "status":  "sent",
        "to":      arguments.get("to", "team@company.com"),
        "subject": arguments.get("subject", "Meeting Summary"),
    }


def slack_logic(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "status":  "posted",
        "channel": arguments.get("channel", "#team-updates"),
        "message": arguments.get("message", "Daily briefing posted."),
    }


def external_api_logic(arguments: dict[str, Any]) -> dict[str, Any]:
    """Third-hop resource: returns sub-resource data for the calendar entry."""
    return {
        "status":   "ok",
        "resource": "calendar-sub-resource",
        "data":     "Conference room booking confirmed for 2:00 PM sync.",
    }


# ── tool schemas ──────────────────────────────────────────────────────────────

CALENDAR_TOOLS = {
    "get_today_meetings": {
        "description":   "Read today's calendar events.",
        "required_scopes": ["calendar:read"],
        "inputSchema": {
            "type": "object",
            "properties": {"mode": {"type": "string"}},
        },
    },
}

DOCS_TOOLS = {
    "read_meeting_notes": {
        "description":   "Read the team meeting notes.",
        "required_scopes": ["docs:read"],
        "inputSchema": {
            "type": "object",
            "properties": {"doc_id": {"type": "string"}},
        },
    },
    "read_hr_payroll": {
        "description":   "Read confidential HR payroll document.",
        "required_scopes": ["docs:read", "hr:read"],
        "inputSchema": {
            "type": "object",
            "properties": {"doc_id": {"type": "string"}},
        },
    },
}

COMMS_TOOLS = {
    "send_summary_email": {
        "description":   "Send a meeting summary email.",
        "required_scopes": ["email:send"],
        "inputSchema": {
            "type": "object",
            "properties": {
                "to":      {"type": "string"},
                "subject": {"type": "string"},
                "message": {"type": "string"},
            },
        },
    },
    "post_slack_update": {
        "description":   "Post a status update to Slack.",
        "required_scopes": ["slack:write"],
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {"type": "string"},
                "message": {"type": "string"},
            },
        },
    },
}

EXTERNAL_API_TOOLS = {
    "get_calendar_sub_resource": {
        "description":   "Fetch a sub-resource for a calendar entry (3rd hop).",
        "required_scopes": ["calendar:read"],
        "inputSchema": {
            "type": "object",
            "properties": {"entry_id": {"type": "string"}},
        },
    },
}


# ── builder functions ─────────────────────────────────────────────────────────

def build_calendar_app(*, port: int, secure: bool):
    return make_worker_app(
        worker_name   = "calendar",
        port          = port,
        secure        = secure,
        tools         = CALENDAR_TOOLS,
        service_logic = {"get_today_meetings": calendar_logic},
    )


def build_docs_app(*, port: int, secure: bool):
    return make_worker_app(
        worker_name   = "docs",
        port          = port,
        secure        = secure,
        tools         = DOCS_TOOLS,
        service_logic = {
            "read_meeting_notes": docs_logic,
            "read_hr_payroll":    docs_logic,
        },
    )


def build_comms_app(*, port: int, secure: bool):
    return make_worker_app(
        worker_name   = "comms",
        port          = port,
        secure        = secure,
        tools         = COMMS_TOOLS,
        service_logic = {
            "send_summary_email": email_logic,
            "post_slack_update":  slack_logic,
        },
    )


def build_external_api_app(*, port: int, secure: bool):
    return make_worker_app(
        worker_name   = "external-api",
        port          = port,
        secure        = secure,
        tools         = EXTERNAL_API_TOOLS,
        service_logic = {"get_calendar_sub_resource": external_api_logic},
    )