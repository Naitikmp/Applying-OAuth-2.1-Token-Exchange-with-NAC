"""Factory for the specialist MCP worker servers."""

from __future__ import annotations

import json
from typing import Any, Callable

import httpx
from fastapi import FastAPI, HTTPException
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import TextContent, Tool

from nac_common import AUDIENCES, TRUSTED_ACTORS, chain_summary, token_preview, validate_token


WorkerHandler = Callable[[dict[str, Any]], dict[str, Any]]


def _make_sse_app(server: Server, transport: SseServerTransport, fastapi_app: FastAPI):
    class MixedASGIApp:
        def __init__(self, fastapi_app: FastAPI) -> None:
            self._fastapi = fastapi_app

        async def __call__(self, scope, receive, send) -> None:
            if scope.get("type") == "http":
                path = scope.get("path", "")
                if path == "/sse":
                    async with transport.connect_sse(scope, receive, send) as (r, w):
                        await server.run(r, w, server.create_initialization_options())
                    return
                if path == "/messages":
                    await transport.handle_post_message(scope, receive, send)
                    return
            await self._fastapi(scope, receive, send)

    return MixedASGIApp(fastapi_app)


def make_worker_app(
    *,
    worker_name: str,
    port: int,
    secure: bool,
    tools: dict[str, dict[str, Any]],
    service_logic: dict[str, WorkerHandler],
) -> FastAPI:
    """Create a specialist MCP server.

    tools = {
        "tool_name": {
            "description": "...",
            "inputSchema": {...}
        }
    }
    service_logic maps tool_name -> async/sync callable returning a JSON-serializable dict.
    """

    server = Server(f"{worker_name}-mcp")
    transport = SseServerTransport("/messages")
    fastapi_app = FastAPI(title=f"{worker_name} worker")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [Tool(name=name, description=meta["description"], inputSchema=meta["inputSchema"]) for name, meta in tools.items()]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        print(f"\n[{ 'Secure' if secure else 'Baseline' } {worker_name}] Tool called: '{name}' | args={arguments}")
        if name not in service_logic:
            return [TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}))]

        token = arguments.get("token", "")
        if not token:
            raise HTTPException(401, "missing token")

        if secure:
            expected_aud = AUDIENCES[worker_name]
            claims = validate_token(
                token,
                expected_audience=expected_aud,
                required_scopes=tools[name].get("required_scopes", []),
                trusted_actors=TRUSTED_ACTORS,
                enforce_audience=True,
                enforce_chain=True,
            )
        else:
            # Baseline: only signature/expiry are checked; audience and chain are ignored.
            claims = validate_token(
                token,
                expected_audience=AUDIENCES[worker_name],
                required_scopes=[],
                trusted_actors=None,
                enforce_audience=False,
                enforce_chain=False,
            )

        payload = service_logic[name](arguments)
        payload["subject"] = claims.get("sub")
        payload["aud"] = claims.get("aud")
        payload["act_chain"] = chain_summary(claims)
        payload["token_preview"] = token_preview(token)
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]

    @fastapi_app.get("/health")
    def health():
        return {"status": "ok", "server": worker_name, "port": port, "secure": secure}

    return _make_sse_app(server, transport, fastapi_app)


# --------------------- service logic helpers ---------------------


def calendar_logic(arguments: dict[str, Any]) -> dict[str, Any]:
    mode = arguments.get("mode", "today")
    if mode == "today":
        return {
            "status": "ok",
            "meeting": "2:00 PM project sync",
            "attendees": ["alice@company.com", "bob@company.com", "ops@company.com"],
        }
    return {"status": "ok", "detail": f"calendar mode={mode}"}


def docs_logic(arguments: dict[str, Any]) -> dict[str, Any]:
    doc_id = arguments.get("doc_id", "meeting-notes")
    docs = {
        "meeting-notes": {
            "title": "Project Sync Notes",
            "body": "Discuss roadmap, blockers, and next steps.",
        },
        "hr-payroll": {
            "title": "Payroll Sheet",
            "body": "CONFIDENTIAL: salary and compensation data.",
        },
    }
    return {"status": "ok", "document": docs.get(doc_id, {"title": doc_id, "body": "not found"})}


def email_logic(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "sent",
        "to": arguments.get("to", "team@company.com"),
        "subject": arguments.get("subject", "Meeting Summary"),
    }


def slack_logic(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "posted",
        "channel": arguments.get("channel", "#team-updates"),
        "message": arguments.get("message", "Daily briefing posted."),
    }


CALENDAR_TOOLS = {
    "get_today_meetings": {
        "description": "Read today's calendar and return the meeting that needs a summary.",
        "required_scopes": ["calendar:read"],
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string"},
                "mode": {"type": "string"},
            },
            "required": ["token"],
        },
    },
}

DOCS_TOOLS = {
    "read_meeting_notes": {
        "description": "Read the team meeting notes for the current task.",
        "required_scopes": ["docs:read"],
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string"},
                "doc_id": {"type": "string"},
            },
            "required": ["token"],
        },
    },
    "read_hr_payroll": {
        "description": "Attempt to read a confidential HR payroll document.",
        "required_scopes": ["docs:read", "hr:read"],
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string"},
                "doc_id": {"type": "string"},
            },
            "required": ["token"],
        },
    },
}

COMMS_TOOLS = {
    "send_summary_email": {
        "description": "Send a meeting summary email to the team.",
        "required_scopes": ["email:send"],
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string"},
                "to": {"type": "string"},
                "subject": {"type": "string"},
            },
            "required": ["token"],
        },
    },
    "post_slack_update": {
        "description": "Post a short status update to Slack.",
        "required_scopes": ["slack:write"],
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string"},
                "channel": {"type": "string"},
                "message": {"type": "string"},
            },
            "required": ["token"],
        },
    },
}


def build_calendar_app(*, port: int, secure: bool):
    return make_worker_app(worker_name="calendar", port=port, secure=secure, tools=CALENDAR_TOOLS, service_logic={"get_today_meetings": calendar_logic})


def build_docs_app(*, port: int, secure: bool):
    return make_worker_app(worker_name="docs", port=port, secure=secure, tools=DOCS_TOOLS, service_logic={"read_meeting_notes": docs_logic, "read_hr_payroll": docs_logic})


def build_comms_app(*, port: int, secure: bool):
    return make_worker_app(worker_name="comms", port=port, secure=secure, tools=COMMS_TOOLS, service_logic={"send_summary_email": email_logic, "post_slack_update": slack_logic})
