"""
Standalone evaluation runner — v3 (JTI server added).

Changes from v2:
  - Starts a dedicated in-memory JTI store server on port 9100 before
    launching the baseline and secure stacks.
  - Sets NAC_JTI_URL in the parent process before spawning children so all
    six child processes (oauth, assistant, 4 workers) inherit the env var
    and use the fast HTTP JTI backend instead of file-based FileLock.
  - The eval harness (main process) also inherits NAC_JTI_URL, so its
    direct exchange_token() calls register JTIs in the shared server.
  - wait_ready() now includes the JTI server port (9100).

Expected latency after this change:
  Baseline: ~120 ms   (unchanged)
  Secure:   ~140 ms   (~17% overhead)  ← was 670 ms / +457%
  The NAC protocol cost is ~12 ms RSA + ~2 ms JTI + ~8 ms HTTP = ~22 ms.

Usage:
    python run_eval.py [--rounds N]
"""

from __future__ import annotations

import argparse
import asyncio
import multiprocessing as mp
import os
import time

import httpx
import uvicorn

from assistant_server import make_assistant_app
from oauth_server      import make_oauth_app
from worker_servers    import build_calendar_app, build_docs_app, build_comms_app, build_external_api_app
from eval_harness      import run_evaluation

JTI_SERVER_PORT = int(os.getenv("JTI_SERVER_PORT", "9100"))
JTI_SERVER_URL  = f"http://127.0.0.1:{JTI_SERVER_PORT}"


def serve_jti_server(port: int) -> None:
    """Entry point for the JTI server subprocess."""
    from jti_server import make_jti_app
    uvicorn.run(make_jti_app(), host="127.0.0.1", port=port, log_level="error")


def serve_server(kind: str, secure: bool, port: int, callback_url: str, worker_urls: dict | None = None):
    # Workers must not hold the signing key
    if kind in ("calendar", "docs", "comms", "external-api"):
        os.environ["NAC_PUBLIC_ONLY"] = "1"

    if kind == "oauth":
        app = make_oauth_app(secure=secure, callback_url=callback_url)
    elif kind == "assistant":
        app = make_assistant_app(secure=secure, oauth_url=f"http://127.0.0.1:{port-1}",
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


def _launch_stack(base: int, secure: bool, ctx) -> list:
    cb = f"http://127.0.0.1:{base+1}/oauth/callback"
    wu = {
        "calendar":     f"http://127.0.0.1:{base+2}",
        "docs":         f"http://127.0.0.1:{base+3}",
        "comms":        f"http://127.0.0.1:{base+4}",
        "external-api": f"http://127.0.0.1:{base+5}",
    }
    procs = []
    for kind, port, wurl in [
        ("oauth",        base,   None),
        ("calendar",     base+2, None),
        ("docs",         base+3, None),
        ("comms",        base+4, None),
        ("external-api", base+5, None),
        ("assistant",    base+1, wu),
    ]:
        p = ctx.Process(target=serve_server, args=(kind, secure, port, cb, wurl))
        p.daemon = True
        p.start()
        procs.append(p)
    return procs


async def _wait_ready(all_ports: list[int], timeout: int = 30) -> None:
    deadline = time.time() + timeout
    async with httpx.AsyncClient() as c:
        while time.time() < deadline:
            resps = await asyncio.gather(
                *[c.get(f"http://127.0.0.1:{p}/health") for p in all_ports],
                return_exceptions=True,
            )
            if all(not isinstance(r, Exception) and r.status_code == 200 for r in resps):
                print(f"  All {len(all_ports)} servers ready.")
                return
            await asyncio.sleep(0.4)
    raise TimeoutError("Not all servers started in time")


async def main(rounds: int) -> None:
    print("\n" + "="*72)
    print("  NAC EVALUATION — launching JTI server + baseline + secure stacks")
    print("="*72 + "\n")

    # ── Set NAC_JTI_URL BEFORE spawning children so they all inherit it ───────
    # With multiprocessing.spawn on Windows, child processes start fresh Python
    # interpreters that inherit the parent's OS environment block.  Setting the
    # env var here (before any ctx.Process(...).start()) guarantees every child
    # picks it up when it imports nac_common.
    os.environ["NAC_JTI_URL"] = JTI_SERVER_URL
    print(f"  JTI backend: HTTP server at {JTI_SERVER_URL} (replaces file-based FileLock)")

    ctx   = mp.get_context("spawn")
    procs = []

    # ── Start JTI server first ────────────────────────────────────────────────
    jti_proc = ctx.Process(target=serve_jti_server, args=(JTI_SERVER_PORT,))
    jti_proc.daemon = True
    jti_proc.start()
    procs.append(jti_proc)

    # ── Start baseline + secure stacks ────────────────────────────────────────
    procs += _launch_stack(9200, False, ctx)   # baseline (insecure)
    procs += _launch_stack(9300, True,  ctx)   # secure (NAC)

    print("  Waiting for servers …")
    # JTI server + 12 stack servers = 13 total
    all_ports = [JTI_SERVER_PORT] + [9200 + i for i in range(6)] + [9300 + i for i in range(6)]
    await _wait_ready(all_ports, timeout=35)

    try:
        await run_evaluation(rounds=rounds)
    finally:
        for p in procs:
            if p.is_alive():
                p.terminate()
                p.join(timeout=2)
        print("\n[Eval] All server processes terminated.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=30,
                        help="Number of trials per attack scenario (default: 30)")
    args = parser.parse_args()
    mp.freeze_support()
    asyncio.run(main(rounds=args.rounds))