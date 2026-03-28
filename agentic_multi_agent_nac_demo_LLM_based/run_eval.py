"""
Standalone evaluation runner.

Starts both baseline and secure server stacks, waits for them to be ready,
then calls eval_harness.run_evaluation() and exits.

Usage:
    python run_eval.py [--rounds N]

Both stacks run simultaneously on different port ranges:
    Baseline: 9200-9205
    Secure:   9300-9305
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
from oauth_server     import make_oauth_app
from worker_servers   import build_calendar_app, build_docs_app, build_comms_app, build_external_api_app
from eval_harness     import run_evaluation


def serve_server(kind: str, secure: bool, port: int, callback_url: str, worker_urls: dict | None = None):
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


async def _wait_ready(bases: list[int], timeout: int = 25) -> None:
    all_ports = [b + i for b in bases for i in range(6)]
    deadline  = time.time() + timeout
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
    print("  NAC EVALUATION — launching baseline + secure stacks")
    print("="*72 + "\n")

    ctx   = mp.get_context("spawn")
    procs = []
    procs += _launch_stack(9200, False, ctx)   # baseline
    procs += _launch_stack(9300, True,  ctx)   # secure

    print("  Waiting for servers …")
    await _wait_ready([9200, 9300])

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
