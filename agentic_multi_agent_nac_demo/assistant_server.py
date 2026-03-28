"""Top-level assistant MCP server.

The user talks to this server through an LLM-style agent.
The assistant then calls specialist MCP workers for calendar, docs, and comms.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import TextContent, Tool

from nac_common import AUDIENCES, ROOT_CLIENT_ID, exchange_token, token_preview


def _make_mcp_asgi(server: Server, transport: SseServerTransport, fastapi_app: FastAPI):
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


def make_assistant_app(*, secure: bool, oauth_url: str, worker_urls: dict[str, str], callback_url: str) -> FastAPI:
    server = Server("assistant-hub-mcp")
    transport = SseServerTransport("/messages")
    fastapi_app = FastAPI(title=("Secure" if secure else "Baseline") + " Assistant Hub")

    session_tokens: dict[str, str] = {}
    consent_state: dict[str, str] = {}

    async def _call_worker(worker_url: str, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        async with sse_client(f"{worker_url}/sse") as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, args)
                return json.loads(result.content[0].text)

    def _root_token_for(username: str) -> str:
        token = session_tokens.get(username)
        if not token:
            raise HTTPException(401, "not authenticated — call connect_workspace first")
        return token

    @fastapi_app.get("/oauth/callback")
    async def oauth_callback(code: str = "", state: str = ""):
        return {"status": "callback_received", "code_present": bool(code), "state": state}

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="connect_workspace",
                description="Connect the assistant hub to the user's workspace through OAuth.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "username": {"type": "string"},
                        "custom_redirect_uri": {"type": "string"},
                    },
                    "required": ["username"],
                },
            ),
            Tool(
                name="prepare_daily_briefing",
                description="Read calendar and notes, then email and Slack the summary.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "username": {"type": "string"},
                    },
                    "required": ["username"],
                },
            ),
            Tool(
                name="attempt_unauthorized_hr_read",
                description="Abuse test: try to read a confidential HR payroll document.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "username": {"type": "string"},
                    },
                    "required": ["username"],
                },
            ),
            Tool(
                name="inspect_session",
                description="Inspect the stored root token metadata.",
                inputSchema={"type": "object", "properties": {"username": {"type": "string"}}},
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        print(f"\n[{ 'Secure' if secure else 'Baseline' } Assistant] Tool called: '{name}' | args={arguments}")
        username = arguments.get("username", "alice")

        if name == "connect_workspace":
            return await _connect_workspace(arguments)
        if name == "prepare_daily_briefing":
            return await _prepare_daily_briefing(username)
        if name == "attempt_unauthorized_hr_read":
            return await _attempt_unauthorized_hr_read(username)
        if name == "inspect_session":
            token = session_tokens.get(username, "")
            return [TextContent(type="text", text=json.dumps({"username": username, "token_preview": token_preview(token), "has_token": bool(token)}, indent=2))]
        return [TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}))]

    async def _connect_workspace(args: dict[str, Any]) -> list[TextContent]:
        username = args.get("username", "alice")
        redirect_uri = args.get("custom_redirect_uri", callback_url)
        if secure and redirect_uri != callback_url:
            raise HTTPException(400, "redirect_uri rejected by secure assistant")

        state = str(uuid.uuid4())
        consent_state[state] = username
        auth_url = (
            f"{oauth_url}/login/oauth/authorize"
            f"?client_id={ROOT_CLIENT_ID}"
            f"&redirect_uri={callback_url if secure else redirect_uri}"
            f"&scope=calendar:read docs:read email:send slack:write"
            f"&state={state}"
        )

        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(auth_url, headers={"X-Simulated-User": username})
            final_url = str(resp.url)

        callback_body = None
        if "code=" in final_url:
            from urllib.parse import urlparse, parse_qs

            parsed = urlparse(final_url)
            qs = parse_qs(parsed.query)
            code = qs.get("code", [""])[0]
            if code:
                async with httpx.AsyncClient() as client:
                    token_resp = await client.post(
                        f"{oauth_url}/login/oauth/access_token",
                        json={
                            "code": code,
                            "client_id": ROOT_CLIENT_ID,
                            "redirect_uri": callback_url if secure else redirect_uri,
                        },
                    )
                callback_body = token_resp.json()
                session_tokens[username] = callback_body.get("access_token", "")

        print(f"  client_id used       : {ROOT_CLIENT_ID}")
        print(f"  redirected to        : {final_url}")
        print(f"  consent stored safely: {bool(callback_body)}")

        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "auth_url": auth_url,
                        "github_redirected_to": final_url,
                        "static_client_id_used": ROOT_CLIENT_ID,
                        "token_stored": bool(callback_body and callback_body.get("access_token")),
                    },
                    indent=2,
                ),
            )
        ]

    async def _prepare_daily_briefing(username: str) -> list[TextContent]:
        root = _root_token_for(username)
        try:
            if secure:
                # FIX: use correct parameter names — new_audience, new_scope (list), actor
                cal_token = exchange_token(
                    root,
                    new_audience=AUDIENCES["calendar"],
                    new_scope=["calendar:read"],
                    actor="assistant-hub",
                )
                docs_token = exchange_token(
                    root,
                    new_audience=AUDIENCES["docs"],
                    new_scope=["docs:read"],
                    actor="assistant-hub",
                )
                comms_token = exchange_token(
                    root,
                    new_audience=AUDIENCES["comms"],
                    new_scope=["email:send", "slack:write"],
                    actor="assistant-hub",
                )
            else:
                # Baseline: forward the root token unchanged (the anti-pattern we are demonstrating)
                cal_token = root
                docs_token = root
                comms_token = root

            calendar = await _call_worker(worker_urls["calendar"], "get_today_meetings", {"token": cal_token})
            notes = await _call_worker(worker_urls["docs"], "read_meeting_notes", {"token": docs_token, "doc_id": "meeting-notes"})
            email = await _call_worker(
                worker_urls["comms"],
                "send_summary_email",
                {
                    "token": comms_token,
                    "to": "team@company.com",
                    "subject": "Daily team briefing",
                    "message": f"Meeting: {calendar.get('meeting')} | Notes: {notes.get('document', {}).get('body')}",
                },
            )
            slack = await _call_worker(
                worker_urls["comms"],
                "post_slack_update",
                {
                    "token": comms_token,
                    "channel": "#team-updates",
                    "message": "Briefing sent. Calendar checked, notes summarized, email delivered.",
                },
            )

            payload = {
                "calendar": calendar,
                "notes": notes,
                "email": email,
                "slack": slack,
                "mode": "secure" if secure else "baseline",
            }
            return [TextContent(type="text", text=json.dumps(payload, indent=2))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e), "mode": "secure" if secure else "baseline"}, indent=2))]

    async def _attempt_unauthorized_hr_read(username: str) -> list[TextContent]:
        root = _root_token_for(username)
        try:
            if secure:
                # Even in the secure path the token reaches docs — but docs has no hr:read scope,
                # so the resource server rejects it.  This demonstrates scope attenuation.
                docs_token = exchange_token(
                    root,
                    new_audience=AUDIENCES["docs"],
                    new_scope=["docs:read"],
                    actor="assistant-hub",
                )
            else:
                docs_token = root

            result = await _call_worker(worker_urls["docs"], "read_hr_payroll", {"token": docs_token, "doc_id": "hr-payroll"})
            return [TextContent(type="text", text=json.dumps({"attack_result": result, "mode": "secure" if secure else "baseline"}, indent=2))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"blocked": True, "error": str(e), "mode": "secure" if secure else "baseline"}, indent=2))]

    @fastapi_app.get("/health")
    def health():
        return {"status": "ok", "server": "assistant-hub", "secure": secure}

    return _make_mcp_asgi(server, transport, fastapi_app)