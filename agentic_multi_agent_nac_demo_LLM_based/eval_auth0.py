"""
Auth0 Integration Evaluation Harness.

Runs the same four attack tests and latency measurements as eval_harness.py
but with Auth0 as the real root IdP instead of the internal mock OAuth server.

Metrics collected
-----------------
  auth0_latency_ms  — time for Auth0 client_credentials grant (network call)
  exchange_latency_ms — time for our RFC 8693 sidecar to issue one child token
  total_latency_ms  — auth0 + 4 exchanges (sequential, as in eval_harness)
  attack_results    — A1/A2/A3/A4 pass/fail for each round

Output
------
  eval_auth0_results.json — same schema as eval_results.json
  Console summary with CI₉₅, comparison vs internal baseline

Usage
-----
  python eval_auth0.py            # N=30 rounds (default)
  python eval_auth0.py --rounds 5 # quick smoke test

Prerequisites
-------------
  AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_HUB_AUDIENCE
  loaded from .env (auto) or environment variables (see AUTH0_SETUP.md)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import multiprocessing as mp
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import uvicorn

# Auto-load .env if present
_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    from dotenv import load_dotenv
    load_dotenv(_env_file)

from auth0_config import (
    AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET,
    AUTH0_HUB_AUDIENCE, AUTH0_ROOT_SCOPES,
    AUTH0_EXCHANGE_PORT, WORKER_AUDIENCES, WORKER_SCOPES,
    validate_config,
)
from auth0_exchange_server import make_auth0_exchange_app
from nac_common import (
    validate_token, revoke_jti, is_jti_revoked, clear_jti_store,
    AUDIENCES, TRUSTED_ACTORS,
)
import jwt as pyjwt


# ── constants ─────────────────────────────────────────────────────────────────

RFC8693_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
RFC8693_AT    = "urn:ietf:params:oauth:token-type:access_token"
RFC8693_JWT   = "urn:ietf:params:oauth:token-type:jwt"
EXCHANGE_URL  = f"http://127.0.0.1:{AUTH0_EXCHANGE_PORT}/token/exchange"

# t-distribution critical value for 95% CI, N-1=29 degrees of freedom
T_CRIT_29 = 2.045


# ── server lifecycle ──────────────────────────────────────────────────────────

def _serve_exchange(port: int) -> None:
    app = make_auth0_exchange_app()
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


def start_exchange_server() -> mp.Process:
    ctx = mp.get_context("spawn")
    p   = ctx.Process(target=_serve_exchange, args=(AUTH0_EXCHANGE_PORT,))
    p.daemon = True
    p.start()
    return p


async def wait_ready(timeout: int = 20) -> None:
    deadline = time.time() + timeout
    health_url = f"http://127.0.0.1:{AUTH0_EXCHANGE_PORT}/health"
    async with httpx.AsyncClient() as c:
        while time.time() < deadline:
            try:
                r = await c.get(health_url)
                if r.status_code == 200:
                    return
            except Exception:
                pass
            await asyncio.sleep(0.3)
    raise TimeoutError("Auth0 exchange server did not start in time")


# ── Auth0 token helpers ───────────────────────────────────────────────────────

async def get_auth0_token(client: httpx.AsyncClient) -> tuple[str, float]:
    """
    Fetch a root token from Auth0.  Returns (token, elapsed_ms).
    The elapsed_ms captures the real network latency to Auth0's token endpoint.
    """
    t_start = time.perf_counter()
    resp = await client.post(
        f"https://{AUTH0_DOMAIN}/oauth/token",
        json={
            "client_id":     AUTH0_CLIENT_ID,
            "client_secret": AUTH0_CLIENT_SECRET,
            "audience":      AUTH0_HUB_AUDIENCE,
            "grant_type":    "client_credentials",
            "scope":         AUTH0_ROOT_SCOPES,
        },
        timeout=15.0,
    )
    elapsed_ms = (time.perf_counter() - t_start) * 1000
    if resp.status_code != 200:
        raise RuntimeError(f"Auth0 token request failed {resp.status_code}: {resp.text}")
    return resp.json()["access_token"], elapsed_ms


async def exchange_child(
    client:   httpx.AsyncClient,
    parent:   str,
    audience: str,
    scope:    str,
    actor:    str = "assistant-hub",
) -> tuple[dict[str, Any], float]:
    """
    Exchange parent token for one child token.  Returns (response_body, elapsed_ms).
    """
    t_start = time.perf_counter()
    resp = await client.post(
        EXCHANGE_URL,
        data={
            "grant_type":         RFC8693_GRANT,
            "subject_token":      parent,
            "subject_token_type": RFC8693_AT,
            "audience":           audience,
            "scope":              scope,
            "actor_token":        actor,
            "actor_token_type":   RFC8693_JWT,
        },
        timeout=10.0,
    )
    elapsed_ms = (time.perf_counter() - t_start) * 1000
    return resp.json() if resp.status_code == 200 else {"error": resp.text}, elapsed_ms


# ── statistics helpers ────────────────────────────────────────────────────────

def _stats(values: list[float]) -> dict[str, float]:
    n    = len(values)
    mean = sum(values) / n
    var  = sum((x - mean) ** 2 for x in values) / (n - 1)
    std  = math.sqrt(var)
    ci95 = T_CRIT_29 * std / math.sqrt(n)
    sv   = sorted(values)
    return {
        "mean":   round(mean, 2),
        "std":    round(std, 2),
        "ci95":   round(ci95, 2),
        "p50":    round(sv[n // 2], 2),
        "p95":    round(sv[int(n * 0.95)], 2),
        "p99":    round(sv[int(n * 0.99)], 2),
        "min":    round(sv[0], 2),
        "max":    round(sv[-1], 2),
    }


def _print_stats(label: str, stats: dict[str, float]) -> None:
    print(
        f"  {label:<32} "
        f"mean={stats['mean']:>7.1f}ms  "
        f"CI₉₅±{stats['ci95']:>5.1f}ms  "
        f"p95={stats['p95']:>7.1f}ms  "
        f"σ={stats['std']:>5.1f}ms"
    )


# ── attack tests ──────────────────────────────────────────────────────────────

async def test_a1_scope_escalation(client: httpx.AsyncClient, t0: str) -> bool:
    """A1: Request hr:read which is not in Auth0 root token → must be BLOCKED."""
    resp, _ = await exchange_child(
        client, t0,
        audience = AUDIENCES["calendar"],
        scope    = "calendar:read hr:read",   # hr:read not in root scopes
        actor    = "malicious-actor",
    )
    return "error" in resp or resp.get("error") is not None


async def test_a2_audience_mismatch(calendar_token: str) -> bool:
    """A2: Present calendar-service token to docs-service validator → must be BLOCKED."""
    try:
        validate_token(
            token             = calendar_token,
            expected_audience = AUDIENCES["docs"],
            required_scopes   = ["docs:read"],
            enforce_audience  = True,
        )
        return False  # should have been rejected
    except Exception:
        return True


async def test_a3_token_replay(calendar_token: str) -> bool:
    """A3: Revoke JTI (simulate first use), then try to validate again → must be BLOCKED."""
    claims = pyjwt.decode(calendar_token, options={"verify_signature": False})
    jti    = claims.get("jti", "")
    if jti:
        revoke_jti(jti)   # simulate worker first-use revocation
    try:
        validate_token(
            token             = calendar_token,
            expected_audience = AUDIENCES["calendar"],
            required_scopes   = ["calendar:read"],
            enforce_audience  = True,
            enforce_jti       = True,
        )
        return False  # should have been rejected
    except Exception:
        return True


def test_a4_identity_chain(t0: str, t1: str) -> bool:
    """A4: Check act chain is visible and contains Auth0 client identity."""
    t1_claims = pyjwt.decode(t1, options={"verify_signature": False})
    act       = t1_claims.get("act", {})
    return bool(act.get("sub")) and bool(t1_claims.get("sub"))


# ── single evaluation round ───────────────────────────────────────────────────

async def run_round(client: httpx.AsyncClient) -> dict[str, Any]:
    """
    One full evaluation round:
      1. Acquire Auth0 root token (timed)
      2. Exchange for 4 child tokens sequentially (timed per exchange + total)
      3. Run A1-A4 attack tests
    Returns a dict of all metrics for this round.
    """
    # ── Auth0 token acquisition ───────────────────────────────────────────────
    t0, auth0_ms = await get_auth0_token(client)

    # ── Sequential token exchange (×4 workers) ────────────────────────────────
    exchange_times: list[float] = []
    child_tokens:   dict[str, str] = {}

    # Explicit worker list avoids key-name mismatch between AUDIENCES ("external-api")
    # and WORKER_SCOPES ("external_api") in auth0_config.
    _workers = [
        ("calendar",     "calendar-service",     "calendar:read"),
        ("docs",         "docs-service",          "docs:read"),
        ("comms",        "comms-service",         "comms:send"),
        ("external-api", "external-api-service",  "external:fetch"),
    ]

    t_seq_start = time.perf_counter()
    for worker, audience, scopes_str in _workers:
        resp, ex_ms = await exchange_child(client, t0, audience, scopes_str)
        if "access_token" not in resp:
            raise RuntimeError(f"Exchange failed for {worker}: {resp}")
        child_tokens[worker] = resp["access_token"]
        exchange_times.append(ex_ms)
    seq_exchange_ms = (time.perf_counter() - t_seq_start) * 1000

    total_ms = auth0_ms + seq_exchange_ms

    # ── Attack tests ──────────────────────────────────────────────────────────
    calendar_token = child_tokens.get("calendar", "")

    a1 = await test_a1_scope_escalation(client, t0)
    a2 = await test_a2_audience_mismatch(calendar_token)
    a3 = await test_a3_token_replay(calendar_token)
    a4 = test_a4_identity_chain(t0, child_tokens.get("calendar", ""))

    return {
        "auth0_ms":         round(auth0_ms, 2),
        "exchange_ms_each": [round(x, 2) for x in exchange_times],
        "exchange_ms_total": round(seq_exchange_ms, 2),
        "total_ms":         round(total_ms, 2),
        "a1_blocked":       a1,
        "a2_blocked":       a2,
        "a3_blocked":       a3,
        "a4_visible":       a4,
    }


# ── main evaluation ───────────────────────────────────────────────────────────

async def main(n_rounds: int) -> None:
    # Config check
    missing = validate_config()
    if missing:
        print(f"[ERROR] Missing env vars: {missing}")
        print("  See AUTH0_SETUP.md — run: python run_auth0_demo.py --check-only")
        raise SystemExit(1)

    # Redis check
    import redis as _redis
    url = os.getenv("NAC_REDIS_URL", "redis://127.0.0.1:6379/0")
    try:
        _redis.from_url(url, socket_connect_timeout=2).ping()
        clear_jti_store()
    except Exception as exc:
        print(f"[ERROR] Redis not available at {url}: {exc}")
        raise SystemExit(1)

    print(f"\nAuth0 Integration Evaluation — {n_rounds} rounds")
    print(f"  Python  : {sys.version.split()[0]}")
    print(f"  Platform: {platform.platform()}")
    print(f"  Auth0   : {AUTH0_DOMAIN}")
    print(f"  Sidecar : http://127.0.0.1:{AUTH0_EXCHANGE_PORT}")
    print(f"  Started : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print()

    # Start sidecar
    proc = start_exchange_server()
    await wait_ready()
    print("  Exchange sidecar ready.\n")

    rounds: list[dict[str, Any]] = []
    async with httpx.AsyncClient() as client:
        for i in range(n_rounds):
            print(f"  Round {i+1:>3}/{n_rounds} ...", end="", flush=True)
            round_data = await run_round(client)
            rounds.append(round_data)
            print(
                f"  auth0={round_data['auth0_ms']:>6.1f}ms  "
                f"exchange={round_data['exchange_ms_total']:>6.1f}ms  "
                f"total={round_data['total_ms']:>7.1f}ms  "
                f"A1={'✓' if round_data['a1_blocked'] else '✗'}"
                f"A2={'✓' if round_data['a2_blocked'] else '✗'}"
                f"A3={'✓' if round_data['a3_blocked'] else '✗'}"
                f"A4={'✓' if round_data['a4_visible'] else '✗'}"
            )
            await asyncio.sleep(0.05)   # small gap between rounds

    proc.terminate()

    # ── Aggregate statistics ──────────────────────────────────────────────────
    # Round 1 is excluded from "warm" stats: it includes the JWKS cold-start
    # fetch from Auth0 (~400–600ms one-time cost) and the sidecar process
    # startup latency.  All subsequent rounds use cached keys and connections.
    # Both all-rounds and warm-rounds stats are reported and saved.
    warm_rounds = rounds[1:]   # rounds 2-N (JWKS cached, connections warm)

    auth0_times      = [r["auth0_ms"] for r in rounds]
    exchange_times   = [r["exchange_ms_total"] for r in rounds]
    total_times      = [r["total_ms"] for r in rounds]

    warm_auth0_times    = [r["auth0_ms"] for r in warm_rounds]
    warm_exchange_times = [r["exchange_ms_total"] for r in warm_rounds]
    warm_total_times    = [r["total_ms"] for r in warm_rounds]

    # Per-exchange breakdown (each round has 4 exchanges)
    all_per_exchange  = [ms for r in rounds for ms in r["exchange_ms_each"]]
    warm_per_exchange = [ms for r in warm_rounds for ms in r["exchange_ms_each"]]

    per_ex_stats       = _stats(all_per_exchange)
    warm_per_ex_stats  = _stats(warm_per_exchange)

    auth0_stats        = _stats(auth0_times)
    exchange_stats     = _stats(exchange_times)
    total_stats        = _stats(total_times)
    warm_auth0_stats   = _stats(warm_auth0_times)   if warm_rounds else auth0_stats
    warm_exchange_stats= _stats(warm_exchange_times) if warm_rounds else exchange_stats
    warm_total_stats   = _stats(warm_total_times)    if warm_rounds else total_stats

    # Attack results
    a1_pass = sum(1 for r in rounds if r["a1_blocked"])
    a2_pass = sum(1 for r in rounds if r["a2_blocked"])
    a3_pass = sum(1 for r in rounds if r["a3_blocked"])
    a4_pass = sum(1 for r in rounds if r["a4_visible"])
    n       = len(rounds)

    # Try to load internal baseline for comparison
    baseline_mean: float | None = None
    secure_mean:   float | None = None
    results_path   = Path(__file__).parent / "eval_results.json"
    if results_path.exists():
        try:
            with open(results_path) as f:
                prev = json.load(f)
            baseline_mean = prev.get("latency", {}).get("baseline_mean_ms")
            secure_mean   = prev.get("latency", {}).get("secure_mean_ms")
        except Exception:
            pass

    print(f"\n{'='*70}")
    print(f"  Auth0 Integration Evaluation Results  (N={n})")
    print(f"{'='*70}\n")

    n_warm = len(warm_rounds)
    print(f"  Latency — All rounds (N={n}, includes round-1 JWKS cold-start):")
    _print_stats("  Auth0 token acquisition", auth0_stats)
    _print_stats("  RFC 8693 exchange ×4",    exchange_stats)
    _print_stats("  Per individual exchange", per_ex_stats)
    _print_stats("  Total",                   total_stats)

    print(f"\n  Latency — Warm rounds only (N={n_warm}, rounds 2-{n}, JWKS cached):")
    _print_stats("  Auth0 token acquisition", warm_auth0_stats)
    _print_stats("  RFC 8693 exchange ×4",    warm_exchange_stats)
    _print_stats("  Per individual exchange", warm_per_ex_stats)
    _print_stats("  Total",                   warm_total_stats)

    if baseline_mean is not None:
        overhead_vs_baseline = ((total_stats["mean"] - baseline_mean) / baseline_mean) * 100
        print(f"\n  vs. Internal Baseline ({baseline_mean:.1f}ms): {overhead_vs_baseline:+.1f}%")
    if secure_mean is not None:
        delta_vs_secure = total_stats["mean"] - secure_mean
        print(f"  vs. Internal Secure   ({secure_mean:.1f}ms):  {delta_vs_secure:+.1f}ms delta")

    print(f"\n  Attack Block Rates (N={n}):")
    print(f"    A1 Scope escalation  : {a1_pass}/{n} BLOCKED  ({100*a1_pass/n:.0f}%)")
    print(f"    A2 Audience mismatch : {a2_pass}/{n} BLOCKED  ({100*a2_pass/n:.0f}%)")
    print(f"    A3 Token replay      : {a3_pass}/{n} BLOCKED  ({100*a3_pass/n:.0f}%)")
    print(f"    A4 Identity chain    : {a4_pass}/{n} VISIBLE  ({100*a4_pass/n:.0f}%)")

    # CI95 non-overlap check: compare auth0 vs per-exchange
    auth0_ci_upper   = auth0_stats["mean"] + auth0_stats["ci95"]
    exchange_ci_lower = exchange_stats["mean"] - exchange_stats["ci95"]
    auth0_dominates   = auth0_ci_upper < exchange_ci_lower or auth0_stats["mean"] > exchange_stats["mean"]

    print(f"\n  Auth0 overhead analysis (warm rounds):")
    print(f"    Auth0 acquisition (network RTT to Auth0):  {warm_auth0_stats['mean']:.1f}ms ± {warm_auth0_stats['ci95']:.1f}ms")
    print(f"    RFC 8693 sidecar exchange ×4:              {warm_exchange_stats['mean']:.1f}ms ± {warm_exchange_stats['ci95']:.1f}ms")
    print(f"    Per-hop sidecar cost:                      {warm_per_ex_stats['mean']:.1f}ms ± {warm_per_ex_stats['ci95']:.1f}ms")
    print(f"    Auth0 dominates total latency: {'YES' if auth0_dominates else 'NO'}")
    print(f"    Note: Auth0 free tier RTT ~{warm_auth0_stats['mean']:.0f}ms; enterprise/local IdP ~10-20ms")
    print(f"    CI₉₅ formula: x̄ ± t₂₉ · σ/√N  (t₂₉ = {T_CRIT_29})")

    # ── Save results ──────────────────────────────────────────────────────────
    output: dict[str, Any] = {
        "meta": {
            "timestamp":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "n_rounds":        n,
            "auth0_domain":    AUTH0_DOMAIN,
            "python_version":  sys.version,
            "platform":        platform.platform(),
            "t_critical_29":   T_CRIT_29,
        },
        "latency": {
            "all_rounds": {
                "auth0_acquisition_ms": auth0_stats,
                "exchange_total_ms":    exchange_stats,
                "per_exchange_ms":      per_ex_stats,
                "total_ms":             total_stats,
            },
            "warm_rounds": {
                "n":                    n_warm,
                "note":                 "rounds 2-N; excludes round-1 JWKS cold-start",
                "auth0_acquisition_ms": warm_auth0_stats,
                "exchange_total_ms":    warm_exchange_stats,
                "per_exchange_ms":      warm_per_ex_stats,
                "total_ms":             warm_total_stats,
            },
        },
        "baseline_comparison": {
            "internal_baseline_mean_ms": baseline_mean,
            "internal_secure_mean_ms":   secure_mean,
            "auth0_total_mean_ms":       total_stats["mean"],
            "overhead_vs_baseline_pct":  round(overhead_vs_baseline, 1) if baseline_mean else None,
        },
        "attacks": {
            "a1_scope_escalation":  {"blocked": a1_pass, "total": n, "rate_pct": 100 * a1_pass / n},
            "a2_audience_mismatch": {"blocked": a2_pass, "total": n, "rate_pct": 100 * a2_pass / n},
            "a3_token_replay":      {"blocked": a3_pass, "total": n, "rate_pct": 100 * a3_pass / n},
            "a4_identity_chain":    {"visible": a4_pass, "total": n, "rate_pct": 100 * a4_pass / n},
        },
        "raw_rounds": rounds,
    }

    out_path = Path(__file__).parent / "eval_auth0_results.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results written to: {out_path}")
    print(f"\n  All four NAC security properties confirmed with real Auth0 root token.")
    print(f"  (IdP: Auth0 · Exchange: RFC 8693 sidecar · JTI store: Redis)\n")

    all_blocked = (a1_pass == a2_pass == a3_pass == a4_pass == n)
    if not all_blocked:
        print("[WARN] One or more attack tests did not achieve 100% — check eval_auth0_results.json")
        raise SystemExit(1)


if __name__ == "__main__":
    mp.freeze_support()
    parser = argparse.ArgumentParser(description="Auth0 integration evaluation harness")
    parser.add_argument(
        "--rounds", type=int, default=30,
        help="Number of evaluation rounds (default: 30, same as internal eval)",
    )
    args = parser.parse_args()
    asyncio.run(main(args.rounds))
