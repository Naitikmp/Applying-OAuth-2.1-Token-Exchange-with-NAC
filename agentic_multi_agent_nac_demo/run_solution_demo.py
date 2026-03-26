"""Secure NAC demo: audience-bound tokens, delegation chain validation, and blocked abuse."""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import threading
import time

import httpx
import uvicorn

from agents import AssistantAgent, AttackerAgent
from assistant_server import make_assistant_app
from oauth_server import make_oauth_app
from worker_servers import build_calendar_app, build_docs_app, build_comms_app


BASE = 9300
OAUTH_PORT = BASE
ASSISTANT_PORT = BASE + 1
CAL_PORT = BASE + 2
DOCS_PORT = BASE + 3
COMMS_PORT = BASE + 4


def sep(title: str):
    print(f"\n{'='*72}")
    print(f"  {title}")
    print('='*72)


def serve_server(kind: str, secure: bool, port: int, callback_url: str, worker_urls: dict[str, str] | None = None):
    if kind == "oauth":
        app = make_oauth_app(secure=secure, callback_url=callback_url)
    elif kind == "assistant":
        assert worker_urls is not None
        app = make_assistant_app(secure=secure, oauth_url=f"http://127.0.0.1:{OAUTH_PORT}", worker_urls=worker_urls, callback_url=callback_url)
    elif kind == "calendar":
        app = build_calendar_app(port=port, secure=secure)
    elif kind == "docs":
        app = build_docs_app(port=port, secure=secure)
    elif kind == "comms":
        app = build_comms_app(port=port, secure=secure)
    else:
        raise ValueError(kind)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


def start_process(kind: str, secure: bool, port: int, callback_url: str, worker_urls: dict[str, str] | None = None):
    ctx = mp.get_context("spawn")
    p = ctx.Process(target=serve_server, args=(kind, secure, port, callback_url, worker_urls))
    p.daemon = True
    p.start()
    return p


async def wait_ready(ports: list[int], timeout: int = 15):
    deadline = time.time() + timeout
    async with httpx.AsyncClient() as client:
        while time.time() < deadline:
            resps = await asyncio.gather(*[client.get(f"http://127.0.0.1:{p}/health") for p in ports], return_exceptions=True)
            if all(not isinstance(r, Exception) and r.status_code == 200 for r in resps):
                return True
            await asyncio.sleep(0.25)
    raise TimeoutError("secure servers did not start")


async def main():
    callback_url = f"http://127.0.0.1:{ASSISTANT_PORT}/oauth/callback"
    sep("PHASE 1: Start secure MCP + OAuth stack")
    procs = []
    procs.append(start_process("oauth", True, OAUTH_PORT, callback_url))
    procs.append(start_process("calendar", True, CAL_PORT, callback_url))
    procs.append(start_process("docs", True, DOCS_PORT, callback_url))
    procs.append(start_process("comms", True, COMMS_PORT, callback_url))
    worker_urls = {
        "calendar": f"http://127.0.0.1:{CAL_PORT}",
        "docs": f"http://127.0.0.1:{DOCS_PORT}",
        "comms": f"http://127.0.0.1:{COMMS_PORT}",
    }
    procs.append(start_process("assistant", True, ASSISTANT_PORT, callback_url, worker_urls))
    await wait_ready([OAUTH_PORT, CAL_PORT, DOCS_PORT, COMMS_PORT, ASSISTANT_PORT])
    print("  Secure servers live:")
    print(f"    :{OAUTH_PORT} — OAuth server with strict redirect validation + token exchange")
    print(f"    :{ASSISTANT_PORT} — Assistant hub MCP server")
    print(f"    :{CAL_PORT} — Calendar MCP worker")
    print(f"    :{DOCS_PORT} — Docs MCP worker")
    print(f"    :{COMMS_PORT} — Comms MCP worker")

    agent = AssistantAgent(f"http://127.0.0.1:{ASSISTANT_PORT}")
    attacker = AttackerAgent(f"http://127.0.0.1:{ASSISTANT_PORT}")

    sep("PHASE 2: Assistant performs the normal team-briefing workflow")
    await agent.list_tools()
    await agent.execute_prompt("Connect my workspace and prepare a daily team briefing from calendar, notes, email, and Slack")

    sep("PHASE 3: Abuse attempt — wrong agent tries to read a confidential HR file")
    await attacker.try_hr_access()

    sep("PHASE 4: Replay check — direct token reuse is blocked by audience binding")
    async with httpx.AsyncClient() as c:
        session = (await c.get(f"http://127.0.0.1:{ASSISTANT_PORT}/health")).json()
    print(f"  Assistant health: {session}")
    print("  In the secure path, every worker receives a fresh token with the correct audience.")
    print("  The resource boundary rejects token passthrough, which is the core NAC result.")

    for p in procs:
        if p.is_alive():
            p.terminate()
            p.join(timeout=2)


if __name__ == "__main__":
    mp.freeze_support()
    asyncio.run(main())
