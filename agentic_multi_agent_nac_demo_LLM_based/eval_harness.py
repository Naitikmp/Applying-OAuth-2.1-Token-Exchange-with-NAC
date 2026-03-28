"""
NAC Evaluation Harness — v2.

Runs all four attack scenarios in both baseline and secure modes,
collects binary success/failure, latency distributions, and token-size
measurements, then prints a results table suitable for the paper's
evaluation section.

Attack scenarios
----------------
A1  Scope escalation      — mis-scoped agent reads hr-payroll document
A2  Lateral movement      — calendar-bound token replayed at docs worker
A3  Token replay          — captured child token reused for a 2nd call
A4  Identity attribution  — audit-log act_chain completeness rate

Latency measurement
-------------------
Measures end-to-end prepare_daily_briefing wall-clock time over N rounds
for both baseline and secure, reporting mean / p50 / p95 / p99 / overhead%.

Token-size measurement
----------------------
Compares root token vs. per-worker child token byte sizes to quantify
the overhead introduced by the nested act claim.

Usage
-----
    python eval_harness.py [--rounds N] [--assistant-base-url URL]
    (servers must already be running)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import time
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any

import httpx
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

import audit_log
from nac_common import (
    AUDIENCES, CHILD_TOKEN_TTL, ROOT_CLIENT_ID,
    exchange_token, get_signing_key, issue_root_token,
    token_size_bytes, chain_depth, scope_to_list,
    get_public_key,  # ensure key material is generated
)


# ── configurable endpoints ────────────────────────────────────────────────────

BASELINE_BASE  = int(os.getenv("BASELINE_BASE",  "9200"))
SECURE_BASE    = int(os.getenv("SECURE_BASE",    "9300"))

def ports(base: int) -> dict[str, str]:
    return {
        "oauth":     f"http://127.0.0.1:{base}",
        "assistant": f"http://127.0.0.1:{base+1}",
        "calendar":  f"http://127.0.0.1:{base+2}",
        "docs":      f"http://127.0.0.1:{base+3}",
        "comms":     f"http://127.0.0.1:{base+4}",
        "ext":       f"http://127.0.0.1:{base+5}",
    }

BASELINE_URLS = ports(BASELINE_BASE)
SECURE_URLS   = ports(SECURE_BASE)


# ── result containers ─────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    attack_id:   str
    description: str
    mode:        str
    trials:      int
    successes:   int           # attack succeeded (vulnerability present)
    blocked:     int           # attack blocked (NAC working)
    errors:      int           # unexpected error during trial
    raw_outcomes: list[bool] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        return self.successes / self.trials if self.trials else 0.0

    @property
    def block_rate(self) -> float:
        return self.blocked / self.trials if self.trials else 0.0


@dataclass
class LatencyResult:
    mode:        str
    n:           int
    mean_ms:     float
    p50_ms:      float
    p95_ms:      float
    p99_ms:      float
    min_ms:      float
    max_ms:      float
    stdev_ms:    float


@dataclass
class TokenSizeResult:
    token_type:   str
    mode:         str
    size_bytes:   int
    chain_depth:  int


# ── token factory (eval uses signing key directly for test token generation) ──

def _make_root_token(username: str = "alice") -> str:
    return issue_root_token(
        username  = username,
        client_id = ROOT_CLIENT_ID,
        scopes    = ["calendar:read", "docs:read", "email:send", "slack:write"],
    )


def _make_child_token(root: str, worker: str, scope: list[str]) -> str:
    return exchange_token(
        parent_token = root,
        new_audience = AUDIENCES[worker],
        new_scope    = scope,
        actor        = "assistant-hub",
    )


def _make_malicious_token(worker: str) -> str:
    """Root-level token with ALL scopes — simulates a stolen broad-scope token."""
    return issue_root_token(
        username  = "attacker",
        client_id = "evil-client",
        scopes    = ["calendar:read", "docs:read", "hr:read", "email:send", "slack:write", "admin"],
    )


# ── worker direct caller (bypasses MCP for speed) ─────────────────────────────

async def _call_worker_direct(
    worker_url: str,
    tool_name:  str,
    args:       dict[str, Any],
    token:      str,
) -> dict[str, Any]:
    """Call a worker tool directly over MCP-SSE with the token in auth header."""
    headers = {"Authorization": f"Bearer {token}"}
    async with sse_client(f"{worker_url}/sse", headers=headers) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, args)
            text = result.content[0].text if result.content else "{}"
            return json.loads(text)


# ── attack runners ────────────────────────────────────────────────────────────

async def _run_a1_scope_escalation(urls: dict, secure: bool, n: int) -> AttackResult:
    """A1: mis-scoped agent reads hr-payroll without hr:read scope."""
    mode     = "secure" if secure else "baseline"
    result   = AttackResult("A1", "Scope escalation (HR read)", mode, n, 0, 0, 0)
    docs_url = urls["docs"]

    for _ in range(n):
        root  = _make_root_token()
        # Token has docs:read but NOT hr:read — should be blocked in secure
        if secure:
            token = _make_child_token(root, "docs", ["docs:read"])
        else:
            token = root
        try:
            resp = await _call_worker_direct(docs_url, "read_hr_payroll", {"doc_id": "hr-payroll"}, token)
            # Attack succeeded if payroll data came back
            if resp.get("document", {}).get("title") == "Payroll Sheet":
                result.successes += 1
                result.raw_outcomes.append(True)
            elif resp.get("error_code") in ("SCOPE_INSUFFICIENT", "WRONG_AUDIENCE", "TOKEN_INVALID"):
                result.blocked += 1
                result.raw_outcomes.append(False)
            else:
                result.blocked += 1
                result.raw_outcomes.append(False)
        except Exception:
            result.errors += 1
            result.raw_outcomes.append(False)

    return result


async def _run_a2_lateral_movement(urls: dict, secure: bool, n: int) -> AttackResult:
    """A2: calendar-scoped token replayed against docs worker."""
    mode     = "secure" if secure else "baseline"
    result   = AttackResult("A2", "Lateral movement (cross-service replay)", mode, n, 0, 0, 0)
    docs_url = urls["docs"]

    for _ in range(n):
        root = _make_root_token()
        # Calendar token: aud=calendar-service
        if secure:
            cal_token = _make_child_token(root, "calendar", ["calendar:read"])
        else:
            cal_token = root   # baseline: no audience binding

        try:
            resp = await _call_worker_direct(docs_url, "read_meeting_notes", {"doc_id": "meeting-notes"}, cal_token)
            if resp.get("document") and not resp.get("error_code"):
                result.successes += 1
                result.raw_outcomes.append(True)
            else:
                result.blocked += 1
                result.raw_outcomes.append(False)
        except Exception:
            result.errors += 1
            result.raw_outcomes.append(False)

    return result


async def _run_a3_token_replay(urls: dict, secure: bool, n: int) -> AttackResult:
    """A3: captured child token replayed for a second call."""
    mode     = "secure" if secure else "baseline"
    result   = AttackResult("A3", "Token replay (jti revocation)", mode, n, 0, 0, 0)
    cal_url  = urls["calendar"]

    for _ in range(n):
        root      = _make_root_token()
        cal_token = _make_child_token(root, "calendar", ["calendar:read"]) if secure else root

        # First call (legitimate) — this revokes the jti in secure mode
        try:
            await _call_worker_direct(cal_url, "get_today_meetings", {}, cal_token)
        except Exception:
            result.errors += 1
            result.raw_outcomes.append(False)
            continue

        # Second call (replay)
        try:
            resp = await _call_worker_direct(cal_url, "get_today_meetings", {}, cal_token)
            if resp.get("meeting") and not resp.get("error_code"):
                result.successes += 1
                result.raw_outcomes.append(True)
            else:
                result.blocked += 1
                result.raw_outcomes.append(False)
        except Exception:
            result.blocked += 1
            result.raw_outcomes.append(False)

    return result


async def _run_a4_identity_attribution(urls: dict, secure: bool, n: int) -> AttackResult:
    """A4: measure fraction of calls that carry a verifiable act chain."""
    from audit_log import attribution_rate, clear_log

    mode    = "secure" if secure else "baseline"
    result  = AttackResult("A4", "Identity attribution (act chain completeness)", mode, n, 0, 0, 0)
    cal_url = urls["calendar"]

    clear_log()

    for _ in range(n):
        root  = _make_root_token()
        token = _make_child_token(root, "calendar", ["calendar:read"]) if secure else root
        try:
            await _call_worker_direct(cal_url, "get_today_meetings", {}, token)
        except Exception:
            result.errors += 1

    rate = attribution_rate(mode)
    attributed   = round(rate * (n - result.errors))
    unattributed = (n - result.errors) - attributed

    # For A4: "attack succeeds" means the log is UNATTRIBUTABLE (baseline vulnerability)
    result.successes = unattributed   # vulnerability: can't tell who called
    result.blocked   = attributed     # "blocked": call IS attributable (secure working)
    result.raw_outcomes = [False] * attributed + [True] * unattributed

    return result


# ── latency measurement ───────────────────────────────────────────────────────

async def _measure_latency(assistant_url: str, root_token: str, n: int, mode: str) -> LatencyResult:
    """Measure end-to-end prepare_daily_briefing wall-clock time over n rounds."""
    durations: list[float] = []
    headers = {"Authorization": f"Bearer {root_token}"}

    async with sse_client(f"{assistant_url}/sse", headers=headers) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for _ in range(n):
                t0 = perf_counter()
                await session.call_tool("prepare_daily_briefing", {})
                durations.append((perf_counter() - t0) * 1000)  # ms

    durations.sort()
    return LatencyResult(
        mode     = mode,
        n        = n,
        mean_ms  = statistics.mean(durations),
        p50_ms   = durations[n // 2],
        p95_ms   = durations[int(n * 0.95)],
        p99_ms   = durations[int(n * 0.99)],
        min_ms   = durations[0],
        max_ms   = durations[-1],
        stdev_ms = statistics.stdev(durations) if n > 1 else 0.0,
    )


# ── token size measurement ────────────────────────────────────────────────────

def _measure_token_sizes() -> list[TokenSizeResult]:
    root   = _make_root_token()
    cal    = _make_child_token(root, "calendar", ["calendar:read"])
    docs   = _make_child_token(root, "docs",     ["docs:read"])
    # Simulate 3-hop: calendar token → external-api token
    ext    = _make_child_token(cal,  "external-api", ["calendar:read"])

    return [
        TokenSizeResult("root (0-hop)",         "both",    token_size_bytes(root), chain_depth(root)),
        TokenSizeResult("calendar child (1-hop)","secure",  token_size_bytes(cal),  chain_depth(cal)),
        TokenSizeResult("docs child (1-hop)",    "secure",  token_size_bytes(docs), chain_depth(docs)),
        TokenSizeResult("external-api (2-hop)",  "secure",  token_size_bytes(ext),  chain_depth(ext)),
    ]


# ── results printer ───────────────────────────────────────────────────────────

def _print_attack_table(results: list[AttackResult]) -> None:
    print("\n" + "="*80)
    print("  ATTACK SUCCESS RATES")
    print("="*80)
    header = f"  {'ID':<4} {'Description':<38} {'Mode':<10} {'Trials':>6} {'Succeed':>8} {'Block%':>8}"
    print(header)
    print("  " + "-"*76)
    for r in results:
        flag = "VULN" if r.success_rate > 0.1 else "SAFE"
        print(
            f"  {r.attack_id:<4} {r.description:<38} {r.mode:<10} "
            f"{r.trials:>6} {r.successes:>8} {r.block_rate:>7.0%}  [{flag}]"
        )
    print()


def _print_latency_table(results: list[LatencyResult]) -> None:
    print("="*80)
    print("  LATENCY (prepare_daily_briefing, ms)")
    print("="*80)
    print(f"  {'Mode':<12} {'N':>4} {'Mean':>8} {'P50':>8} {'P95':>8} {'P99':>8} {'Stdev':>8}")
    print("  " + "-"*60)
    vals = {}
    for r in results:
        vals[r.mode] = r
        print(f"  {r.mode:<12} {r.n:>4} {r.mean_ms:>8.1f} {r.p50_ms:>8.1f} {r.p95_ms:>8.1f} {r.p99_ms:>8.1f} {r.stdev_ms:>8.1f}")
    if "baseline" in vals and "secure" in vals:
        overhead = ((vals["secure"].mean_ms - vals["baseline"].mean_ms) / vals["baseline"].mean_ms) * 100
        print(f"\n  NAC overhead: {overhead:+.1f}% mean latency")
    print()


def _print_token_size_table(results: list[TokenSizeResult]) -> None:
    print("="*80)
    print("  TOKEN SIZE OVERHEAD")
    print("="*80)
    print(f"  {'Token type':<28} {'Mode':<10} {'Bytes':>8} {'Chain depth':>12}")
    print("  " + "-"*60)
    for r in results:
        print(f"  {r.token_type:<28} {r.mode:<10} {r.size_bytes:>8} {r.chain_depth:>12}")
    root_size  = next(r.size_bytes for r in results if "root" in r.token_type)
    child_size = next(r.size_bytes for r in results if "1-hop" in r.token_type)
    overhead   = child_size - root_size
    print(f"\n  Per-hop size overhead: +{overhead} bytes ({overhead/root_size:.0%})")
    print()


# ── main ──────────────────────────────────────────────────────────────────────

async def run_evaluation(rounds: int = 30) -> None:
    print(f"\n{'='*80}")
    print(f"  NAC EVALUATION HARNESS  (N={rounds} trials per scenario)")
    print(f"{'='*80}\n")

    # Ensure key material exists for direct token generation
    get_public_key()
    get_signing_key()

    # ── Attack results ────────────────────────────────────────────────────────
    print("[Eval] Running attack scenarios …")

    attack_results: list[AttackResult] = []
    for secure, urls in [(False, BASELINE_URLS), (True, SECURE_URLS)]:
        print(f"\n  → {'Secure' if secure else 'Baseline'} mode")
        attack_results.append(await _run_a1_scope_escalation(urls, secure, rounds))
        attack_results.append(await _run_a2_lateral_movement(urls, secure, rounds))
        attack_results.append(await _run_a3_token_replay(urls, secure, rounds))
        attack_results.append(await _run_a4_identity_attribution(urls, secure, rounds))

    _print_attack_table(attack_results)

    # ── Reduction summary ─────────────────────────────────────────────────────
    print("="*80)
    print("  ATTACK REDUCTION SUMMARY")
    print("="*80)
    for aid in ["A1", "A2", "A3", "A4"]:
        base_r   = next(r for r in attack_results if r.attack_id == aid and r.mode == "baseline")
        secure_r = next(r for r in attack_results if r.attack_id == aid and r.mode == "secure")
        reduction = base_r.success_rate - secure_r.success_rate
        print(f"  {aid}: baseline={base_r.success_rate:.0%}  secure={secure_r.success_rate:.0%}  reduction={reduction:+.0%}")

    all_base_s = sum(r.successes for r in attack_results if r.mode == "baseline")
    all_base_t = sum(r.trials   for r in attack_results if r.mode == "baseline")
    all_sec_s  = sum(r.successes for r in attack_results if r.mode == "secure")
    all_sec_t  = sum(r.trials   for r in attack_results if r.mode == "secure")
    overall_reduction = ((all_base_s / all_base_t) - (all_sec_s / all_sec_t)) / (all_base_s / all_base_t) * 100 if all_base_s else 0
    print(f"\n  Overall attack reduction: {overall_reduction:.0f}%  (paper claim: ~85%)")
    print()

    # ── Token size ────────────────────────────────────────────────────────────
    print("[Eval] Measuring token sizes …")
    size_results = _measure_token_sizes()
    _print_token_size_table(size_results)

    # ── Latency ───────────────────────────────────────────────────────────────
    print("[Eval] Measuring latency (requires running servers) …")
    lat_results: list[LatencyResult] = []
    for secure, urls in [(False, BASELINE_URLS), (True, SECURE_URLS)]:
        mode = "secure" if secure else "baseline"
        try:
            # Get a root token for the latency session
            root = _make_root_token()
            # For latency we need the assistant to have a stored session
            # Simplest: connect via the assistant first
            async with httpx.AsyncClient() as c:
                auth_url = (
                    f"{urls['oauth']}/login/oauth/authorize"
                    f"?client_id=assistant-hub"
                    f"&redirect_uri=http://127.0.0.1:{int(urls['assistant'].split(':')[-1])}/oauth/callback"
                    f"&scope=calendar:read+docs:read+email:send+slack:write"
                    f"&state=eval"
                )
                resp = await c.get(auth_url, headers={"X-Simulated-User": "alice"}, follow_redirects=True)
                final = str(resp.url)
                if "code=" in final:
                    from urllib.parse import parse_qs, urlparse
                    code = parse_qs(urlparse(final).query).get("code", [""])[0]
                    tok_r = await c.post(
                        f"{urls['oauth']}/login/oauth/access_token",
                        json={"code": code, "client_id": "assistant-hub",
                              "redirect_uri": f"http://127.0.0.1:{int(urls['assistant'].split(':')[-1])}/oauth/callback"},
                    )
                    root = tok_r.json().get("access_token", root)

            lat = await _measure_latency(urls["assistant"], root, rounds, mode)
            lat_results.append(lat)
        except Exception as exc:
            print(f"  [Latency] {mode} servers not reachable ({exc}); skipping latency measurement.")

    if lat_results:
        _print_latency_table(lat_results)
    else:
        print("  (Start servers with run_problem_demo.py and run_solution_demo.py to measure latency)\n")

    print("="*80)
    print("  EVALUATION COMPLETE")
    print("="*80)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NAC evaluation harness")
    parser.add_argument("--rounds", type=int, default=30, help="Number of trials per attack scenario")
    args = parser.parse_args()
    asyncio.run(run_evaluation(rounds=args.rounds))
