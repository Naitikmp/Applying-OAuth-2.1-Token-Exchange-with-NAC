"""Baseline demo: token passthrough, weak delegation, and confused-deputy behavior."""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import time

import httpx
import uvicorn

from agents import AssistantAgent, AttackerAgent
from assistant_server import make_assistant_app
from oauth_server import make_oauth_app
from worker_servers import build_calendar_app, build_docs_app, build_comms_app


BASE = 9200
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
    raise TimeoutError("baseline servers did not start")


async def main():
    callback_url = f"http://127.0.0.1:{ASSISTANT_PORT}/oauth/callback"
    sep("PHASE 1: Start baseline MCP + OAuth stack")
    procs = []
    procs.append(start_process("oauth", False, OAUTH_PORT, callback_url))
    procs.append(start_process("calendar", False, CAL_PORT, callback_url))
    procs.append(start_process("docs", False, DOCS_PORT, callback_url))
    procs.append(start_process("comms", False, COMMS_PORT, callback_url))
    worker_urls = {
        "calendar": f"http://127.0.0.1:{CAL_PORT}",
        "docs": f"http://127.0.0.1:{DOCS_PORT}",
        "comms": f"http://127.0.0.1:{COMMS_PORT}",
    }
    procs.append(start_process("assistant", False, ASSISTANT_PORT, callback_url, worker_urls))
    await wait_ready([OAUTH_PORT, CAL_PORT, DOCS_PORT, COMMS_PORT, ASSISTANT_PORT])
    print("  Baseline servers live:")
    print(f"    :{OAUTH_PORT} — OAuth server (weak consent + no NAC)")
    print(f"    :{ASSISTANT_PORT} — Assistant hub MCP server")
    print(f"    :{CAL_PORT} — Calendar MCP worker")
    print(f"    :{DOCS_PORT} — Docs MCP worker")
    print(f"    :{COMMS_PORT} — Comms MCP worker")

    agent = AssistantAgent(f"http://127.0.0.1:{ASSISTANT_PORT}")
    attacker = AttackerAgent(f"http://127.0.0.1:{ASSISTANT_PORT}")

    sep("PHASE 2: Assistant performs a normal team-briefing workflow")
    await agent.list_tools()
    await agent.execute_prompt("Connect my workspace and prepare a daily team briefing from calendar, notes, email, and Slack")

    sep("PHASE 3: Attack attempt — wrong agent reads a confidential HR file")
    await attacker.try_hr_access()

    async with httpx.AsyncClient() as c:
        store = (await c.get(f"http://127.0.0.1:{OAUTH_PORT}/consent-store")).json()
    print("\n  Consent store:")
    for k, v in store["consent_store"].items():
        print(f"    {k} → consented: {v}")

    sep("PHASE 4: Summary")
    print("  In the baseline, the assistant reuses the same token across workers.")
    print("  That makes the delegation chain flat, so a mis-scoped agent can act as if it were authorized.")
    print("  This is the problem your NAC paper fixes.")

    for p in procs:
        if p.is_alive():
            p.terminate()
            p.join(timeout=2)


if __name__ == "__main__":
    mp.freeze_support()
    asyncio.run(main())
