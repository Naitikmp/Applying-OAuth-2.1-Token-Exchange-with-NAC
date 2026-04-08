"""
run_concurrent_stress.py — Concurrent Agent Stress Test
========================================================
Self-contained: starts its own secure NAC stack, runs the stress test,
then terminates all processes. No separate terminal needed.

Scenario
--------
N_AGENTS simultaneous agents each share the same root token T0.
Each agent fires N_ROUNDS rounds; each round concurrently exchanges T0
for 4 worker-specific child tokens (asyncio.gather), mirroring exactly
what assistant_server.py does in production.

Correctness property verified
------------------------------
No legitimate exchange request is rejected due to a JTI collision or
Redis race condition when multiple agents register jtis simultaneously.

Usage
-----
  # 1. Start Redis (only prerequisite)
  docker run -d -p 6379:6379 --name nac-redis redis:7-alpine

  # 2. Run this script (starts its own stack automatically)
  py -3.10 run_concurrent_stress.py

  Results are written to stress_results.json.
"""

from __future__ import annotations

import asyncio
import httpx
import json
import multiprocessing as mp
import os
import sys
import time
import uvicorn
from datetime import datetime

from assistant_server import make_assistant_app
from oauth_server      import make_oauth_app
from worker_servers    import (build_calendar_app, build_docs_app,
                               build_comms_app,    build_external_api_app)

# ── Secure stack ports ────────────────────────────────────────────────────────
BASE           = 9300
OAUTH_PORT     = BASE
ASSISTANT_PORT = BASE + 1
CAL_PORT       = BASE + 2
DOCS_PORT      = BASE + 3
COMMS_PORT     = BASE + 4
EXT_PORT       = BASE + 5

CALLBACK_URL   = f"http://127.0.0.1:{ASSISTANT_PORT}/oauth/callback"
OAUTH_BASE     = f"http://127.0.0.1:{OAUTH_PORT}"

WORKER_URLS    = {
    "calendar":     f"http://127.0.0.1:{CAL_PORT}",
    "docs":         f"http://127.0.0.1:{DOCS_PORT}",
    "comms":        f"http://127.0.0.1:{COMMS_PORT}",
    "external-api": f"http://127.0.0.1:{EXT_PORT}",
}

# ── Test parameters ───────────────────────────────────────────────────────────
N_AGENTS = 5    # simultaneous agents sharing one root token
N_ROUNDS = 30   # exchange rounds per agent

WORKERS: dict[str, list[str]] = {
    "calendar": ["calendar:read"],
    "docs":     ["docs:read"],
    "email":    ["email:send"],
    "slack":    ["slack:write"],
}


# ── Server startup (mirrors run_eval.py exactly) ──────────────────────────────

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


def _serve(kind: str, port: int) -> None:
    """Server entry-point for each child process."""
    if kind in ("calendar", "docs", "comms", "external-api"):
        os.environ["NAC_PUBLIC_ONLY"] = "1"

    if kind == "oauth":
        app = make_oauth_app(secure=True, callback_url=CALLBACK_URL)
    elif kind == "assistant":
        app = make_assistant_app(secure=True,
                                 oauth_url=OAUTH_BASE,
                                 worker_urls=WORKER_URLS,
                                 callback_url=CALLBACK_URL)
    elif kind == "calendar":
        app = build_calendar_app(port=port, secure=True)
    elif kind == "docs":
        app = build_docs_app(port=port, secure=True)
    elif kind == "comms":
        app = build_comms_app(port=port, secure=True)
    elif kind == "external-api":
        app = build_external_api_app(port=port, secure=True)
    else:
        raise ValueError(kind)

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


def _start_stack(ctx) -> list:
    """Spawn all 6 secure-stack server processes."""
    servers = [
        ("oauth",        OAUTH_PORT),
        ("calendar",     CAL_PORT),
        ("docs",         DOCS_PORT),
        ("comms",        COMMS_PORT),
        ("external-api", EXT_PORT),
        ("assistant",    ASSISTANT_PORT),
    ]
    procs = []
    for kind, port in servers:
        p = ctx.Process(target=_serve, args=(kind, port))
        p.daemon = True
        p.start()
        procs.append(p)
    return procs


async def _wait_ready(timeout: int = 30) -> None:
    """Poll /health on all 6 servers until all respond 200."""
    ports    = [OAUTH_PORT, CAL_PORT, DOCS_PORT, COMMS_PORT, EXT_PORT, ASSISTANT_PORT]
    deadline = time.time() + timeout
    async with httpx.AsyncClient() as client:
        while time.time() < deadline:
            resps = await asyncio.gather(
                *[client.get(f"http://127.0.0.1:{p}/health") for p in ports],
                return_exceptions=True,
            )
            if all(not isinstance(r, Exception) and r.status_code == 200
                   for r in resps):
                print(f"  All 6 servers ready.")
                return
            await asyncio.sleep(0.4)
    raise TimeoutError("Servers did not become ready within timeout.")


# ── Stress test logic ─────────────────────────────────────────────────────────

async def _get_root_token(client: httpx.AsyncClient) -> str:
    """Obtain a root access token via the simulated authorization code flow."""
    from urllib.parse import parse_qs, urlparse

    # GET /login/oauth/authorize — server returns a 302 redirect to CALLBACK_URL?code=...
    auth = await client.get(
        f"{OAUTH_BASE}/login/oauth/authorize",
        params={
            "client_id":    "assistant-hub",
            "redirect_uri": CALLBACK_URL,
            "scope":        "calendar:read docs:read email:send slack:write",
        },
        headers={"X-Simulated-User": "stress_alice"},
        follow_redirects=True,
    )
    code = parse_qs(urlparse(str(auth.url)).query).get("code", [""])[0]
    if not code:
        raise RuntimeError(f"No auth code in redirect URL: {auth.url}")

    tok = await client.post(
        f"{OAUTH_BASE}/login/oauth/access_token",
        json={"code":         code,
              "client_id":    "assistant-hub",
              "redirect_uri": CALLBACK_URL},
    )
    tok.raise_for_status()
    return tok.json()["access_token"]


async def _exchange_one(client: httpx.AsyncClient,
                        root_token: str,
                        audience: str,
                        scope: list[str]) -> dict:
    """Single RFC 8693 token exchange for one worker (form-encoded per spec)."""
    resp = await client.post(
        f"{OAUTH_BASE}/token/exchange",
        data={
            "grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token":        root_token,
            "subject_token_type":   "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience":             audience,
            "scope":                " ".join(scope),
            "actor_token":          "assistant-hub",
            "actor_token_type":     "urn:ietf:params:oauth:token-type:jwt",
        },
    )
    if resp.status_code == 200:
        return {"ok": True,  "audience": audience}
    return {"ok": False, "audience": audience,
            "status": resp.status_code, "body": resp.text[:200]}


async def _run_agent(agent_id: int, root_token: str) -> dict:
    """
    Run one agent through N_ROUNDS of 4-worker concurrent exchanges.
    Mirrors production assistant_server.py behaviour (asyncio.gather per round).
    """
    succeeded, failed, errors = 0, 0, []

    async with httpx.AsyncClient(timeout=15.0) as client:
        for rnd in range(N_ROUNDS):
            results = await asyncio.gather(*[
                _exchange_one(client, root_token, aud, scope)
                for aud, scope in WORKERS.items()
            ])
            for r in results:
                if r["ok"]:
                    succeeded += 1
                else:
                    failed += 1
                    errors.append(
                        f"agent={agent_id} round={rnd} aud={r['audience']} "
                        f"HTTP={r.get('status')} body={r.get('body', '')}"
                    )

    return {"agent_id": agent_id, "succeeded": succeeded,
            "failed": failed, "errors": errors}


async def _run_stress() -> int:
    total_ops = N_AGENTS * N_ROUNDS * len(WORKERS)
    print(f"\n  Agents          : {N_AGENTS}")
    print(f"  Rounds / agent  : {N_ROUNDS}")
    print(f"  Workers / round : {len(WORKERS)}")
    print(f"  Total exchanges : {total_ops}\n")

    async with httpx.AsyncClient(timeout=10.0) as client:
        root_token = await _get_root_token(client)
    print(f"  Root token obtained.  Launching {N_AGENTS} agents concurrently ...\n")

    t0 = time.monotonic()
    agent_results = await asyncio.gather(*[
        _run_agent(i, root_token) for i in range(N_AGENTS)
    ])
    elapsed = time.monotonic() - t0

    total_success = sum(r["succeeded"] for r in agent_results)
    total_fail    = sum(r["failed"]    for r in agent_results)
    passed        = total_fail == 0

    print(f"{'='*60}")
    print(f"  Total exchanges  : {total_ops}")
    print(f"  Succeeded        : {total_success}")
    print(f"  Failed           : {total_fail}  (false positives)")
    print(f"  Elapsed          : {elapsed:.2f}s")
    print(f"  Throughput       : {total_ops / elapsed:.1f} exchanges/s")
    print(f"{'='*60}")

    if passed:
        print("\n  PASS — No false positives under concurrent agent load.")
    else:
        print("\n  FAIL — Unexpected exchange failures:")
        for r in agent_results:
            for err in r["errors"]:
                print(f"    {err}")

    output = {
        "timestamp":            datetime.now().isoformat(),
        "n_agents":             N_AGENTS,
        "n_rounds":             N_ROUNDS,
        "n_workers":            len(WORKERS),
        "total_ops":            total_ops,
        "total_success":        total_success,
        "total_fail":           total_fail,
        "false_positives":      total_fail,
        "passed":               passed,
        "elapsed_s":            round(elapsed, 3),
        "throughput_ops_per_s": round(total_ops / elapsed, 2),
    }
    with open("stress_results.json", "w") as fh:
        json.dump(output, fh, indent=2)
    print(f"\n  Results saved to stress_results.json")
    return 0 if passed else 1


async def main() -> int:
    print("\n" + "="*60)
    print("  Concurrent Agent Stress Test")
    print("="*60)

    _check_redis()

    ctx   = mp.get_context("spawn")
    procs = _start_stack(ctx)

    print("  Waiting for servers ...")
    try:
        await _wait_ready(timeout=35)
    except TimeoutError as exc:
        print(f"\n[ERROR] {exc}")
        for p in procs:
            p.terminate()
        return 2

    try:
        return await _run_stress()
    finally:
        for p in procs:
            if p.is_alive():
                p.terminate()
                p.join(timeout=2)
        print("\n  All server processes terminated.")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
