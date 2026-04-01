# Applying OAuth 2.1 Token Exchange with Nested Actor Claims to MCP Workflows

**Reference implementation and empirical evaluation** for the paper:
*"Applying OAuth 2.1 Token Exchange with Nested Actor Claims to MCP Workflows — Design, Implementation, and Security Evaluation"*

---

## The Problem

The **Model Context Protocol (MCP)** enables AI assistants to orchestrate multiple downstream tool services on behalf of a user. A pervasive implementation anti-pattern — **token passthrough** — causes the assistant to forward the user's original OAuth access token unchanged to every service it calls.

This violates three security properties simultaneously:

| Property | Violation in Token Passthrough |
|---|---|
| Audience binding | A token issued for Service A is accepted at Services B, C, D |
| Scope attenuation | All permissions forwarded in full regardless of what each service needs |
| Delegation chain | The audit trail cannot prove which agent made each call |

The MCP security specification calls this the **Confused Deputy Problem**:
> https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices#confused-deputy-problem

## The Solution

**RFC 8693 (OAuth 2.0 Token Exchange) with Nested Actor Claims (NAC)**. At each delegation hop, the orchestrator exchanges the parent token for a fresh child token via an HTTP POST to `/token/exchange`. Each child token carries:
- `aud` bound to exactly the target service
- `scope` attenuated to only what that service requires
- An `act` claim recording the full delegation chain

Workers hold only the public key (`NAC_PUBLIC_ONLY=1`). The child token's `jti` is revoked in Redis after first use (one-time-use semantics).

---

## Architecture

```
                    ┌────────────────────────────────┐
                    │      OAuth Server :9300         │
                    │  POST /token/exchange (RFC8693) │
                    │  Redis JTI store  :6379         │
                    └─────────────┬──────────────────┘
                                  │ root token (aud=assistant-hub)
                    ┌─────────────▼──────────────────┐
     Alice ────────►│    Assistant Hub :9301          │◄── MCP client connects here
    (JWT in header) │  MCP Server + HTTP orchestrator │
                    │  asyncio.gather → 4 RFC 8693    │
                    │  token exchanges in parallel    │
                    └──┬─────────┬───────┬───────┬───┘
          cal_token    │  docs   │ email │ slack │     (each token: different aud + scope)
                    ┌──▼──┐  ┌───▼─┐ ┌──▼───┐ ┌▼──────────────┐
                    │ Cal │  │Docs │ │Comms │ │External-API   │
                    │:9302│  │:9303│ │:9304 │ │:9305  (3-hop) │
                    └─────┘  └─────┘ └──────┘ └───────────────┘
```

**Secure token flow:**
1. Alice authenticates → OAuth issues root JWT (`aud=assistant-hub`, all scopes)
2. Hub fires 4 concurrent RFC 8693 exchanges → 4 service-specific child tokens
3. Each worker validates `aud`, `scope`, `act_chain`, and `jti` (revoked after first use)
4. Every audit log entry carries `act_chain: ["assistant-hub"]` → 100% attribution

**Baseline (insecure):** root token forwarded unchanged. Steps 2–4 are skipped.

---

## System Requirements

- Python 3.10+
- Redis 7+ (JTI token revocation store)
- Optional: Anthropic API key (Claude-powered LLM agent planner)

---

## Installation

```bash
# 1. Start Redis (keep this running)
docker run -d -p 6379:6379 --name nac-redis redis:7-alpine

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Optional: install matplotlib for paper figures
pip install matplotlib numpy
```

---

## Quick Start

```bash
# Show the problem — all 4 attacks succeed with token passthrough
python run_problem_demo.py

# Show the solution — all 4 attacks blocked by NAC
python run_solution_demo.py

# Full evaluation: 30 trials × 4 attacks + latency + token sizes + per-hop cost
python run_eval.py --rounds 30

# Generate paper figures (after run_eval.py completes)
python generate_charts.py

# Use real Claude LLM as the multi-agent planner
ANTHROPIC_API_KEY=sk-... python run_solution_demo.py
```

---

## Security Properties Enforced

| Property | Mechanism | Demonstrated by |
|---|---|---|
| Audience binding | `aud` claim checked per worker | A2 blocks with `WRONG_AUDIENCE` |
| Scope attenuation | child scope ⊆ parent scope, enforced at exchange | A1 blocks with `SCOPE_INSUFFICIENT` |
| Delegation chain | `act` claim records every hop | A4: 100% attribution in audit log |
| Replay prevention | `jti` revoked in Redis after first use | A3 blocks with `TOKEN_REPLAY` |
| N-hop support | Depth limit `MAX_CHAIN_DEPTH=10` | 3-hop chain demonstrated |
| Key separation | Workers hold public key only (`NAC_PUBLIC_ONLY=1`) | Cannot forge tokens |

---

## Attack Scenarios

| ID | Name | How the attack works | Baseline | Secure | OWASP |
|---|---|---|---|---|---|
| A1 | Scope escalation | Read `hr-payroll` without `hr:read` in scope | Succeeds | `SCOPE_INSUFFICIENT` | LLM06 |
| A2 | Lateral movement | Replay `aud=calendar` token at docs worker | Succeeds | `WRONG_AUDIENCE` | LLM07 |
| A3 | Token replay | Reuse captured child token for a 2nd call | Succeeds | `TOKEN_REPLAY` | LLM08 |
| A4 | Identity attribution | Measure `act_chain` completeness in audit log | 0% | 100% | LLM09 |

---

## Verified Results (Redis backend, N=30 trials)

**Attack block rates — 100% for all 4 attacks:**

| Attack | Baseline | Secure | Block rate |
|---|---|---|---|
| A1 Scope escalation | 30/30 succeed | 0/30 succeed | **100%** |
| A2 Lateral movement | 30/30 succeed | 0/30 succeed | **100%** |
| A3 Token replay | 30/30 succeed | 0/30 succeed | **100%** |
| A4 Identity attribution | 0% attributed | 100% attributed | — |

**Latency (`prepare_daily_briefing`, N=30):**

| Mode | Mean | P50 | P95 | P99 | Stdev |
|---|---|---|---|---|---|
| Baseline | 112.9 ms | 108.7 ms | 142.8 ms | 150.1 ms | 11.5 ms |
| Secure (NAC) | 155.4 ms | 151.7 ms | 185.6 ms | 188.5 ms | 10.7 ms |
| **Overhead** | **+42.5 ms (+37.7%)** | | | | **stdev ratio: 0.93×** |

The stdev ratio of **0.93×** is a key result: Redis eliminates cross-process scheduling jitter. The NAC overhead is *predictable* — the same variance as the baseline.

**Token size overhead (negligible):**

| Token | Bytes | vs root |
|---|---|---|
| Root (0-hop) | 732 B | baseline |
| 1-hop child | 736–747 B | +0.5–2.0% |
| 2-hop child (external-api) | 792 B | +8.2% |

---

## Demo vs Production Overhead

| Context | Overhead | Explanation |
|---|---|---|
| **Demo (measured)** | **+37.7%** (+42.5 ms) | Single machine; OAuth server event loop serialises RSA signing across 4 concurrent requests |
| **Production (estimated)** | **~7–15%** | Dedicated OAuth service, co-located Redis (~0.1 ms/op), multi-worker uvicorn |
| **Theoretical minimum** | **~1–3 ms/hop** | RSA sign (~3 ms) + Redis SET (~0.1 ms), irreducible floor |

The eval harness reports a **parallel estimate of ~123.5 ms** (+9.4%): if the 4 token exchanges ran truly concurrently (multi-worker OAuth), that is the production floor.

---

## File Map

| File | Role |
|---|---|
| `nac_common.py` | JWT issuance, RFC 8693 exchange, Redis JTI store, chain validation |
| `oauth_server.py` | Authorization server — `/token/exchange` (RFC 8693 compliant) |
| `assistant_server.py` | MCP hub: exposes tools to clients, calls workers via token exchange |
| `worker_servers.py` | Calendar / Docs / Comms / External-API MCP workers |
| `agents.py` | `SimpleLLMPlanner`, `RealLLMAgent` (Claude Sonnet), 4 attack agents |
| `audit_log.py` | Structured JSON-line audit logger |
| `eval_harness.py` | Attack + latency + token-size + per-hop-cost evaluation harness |
| `generate_charts.py` | Produces 5 publication-quality figures from `eval_results.json` |
| `run_problem_demo.py` | Launches insecure baseline stack on ports 9200–9205 |
| `run_solution_demo.py` | Launches secure NAC stack on ports 9300–9305 |
| `run_eval.py` | Starts both stacks and runs the full eval harness |

---

## Port Layout

| Stack | OAuth | Assistant | Calendar | Docs | Comms | Ext-API |
|---|---|---|---|---|---|---|
| Baseline (insecure) | 9200 | 9201 | 9202 | 9203 | 9204 | 9205 |
| Secure (NAC) | 9300 | 9301 | 9302 | 9303 | 9304 | 9305 |
| Redis | 6379 | — | — | — | — | — |

---

## Generated Figures

| File | Content |
|---|---|
| `nac_fig1_attacks.png` | Attack success rates: baseline vs secure (N=30) |
| `nac_fig2_latency.png` | Latency percentile breakdown + parallel estimate |
| `nac_fig3_token_sizes.png` | Token byte sizes by chain depth |
| `nac_fig4_summary.png` | One-page combined summary (paper appendix) |
| `nac_fig5_hop_costs.png` | Per-hop cost linearity — requires `run_eval.py` first |

---

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `NAC_REDIS_URL` | `redis://127.0.0.1:6379/0` | Redis connection for JTI store |
| `NAC_PUBLIC_ONLY` | `0` | Set to `1` on workers — blocks private key access |
| `NAC_KEY_DIR` | `.nac_keys/` | RSA key pair directory (auto-generated on first run) |
| `NAC_LOG_FILE` | `$TMPDIR/nac_audit.log` | Structured audit log path |
| `ANTHROPIC_API_KEY` | — | Enables Claude as real LLM planner |

---

## MCP and Multi-Agent Correctness

This implementation correctly models the MCP confused-deputy scenario:

- The **assistant hub** is a real MCP server (`mcp.server.Server` + `SseServerTransport`)
- All **workers** are real MCP servers with proper tool handlers
- All **agents** use `mcp.client.session.ClientSession` over SSE — standard MCP client
- The JWT is passed in the `Authorization: Bearer` header — correct MCP transport-level auth
- The **real LLM planner** runs a ReAct tool-use loop (Claude's `tool_use` API) over live MCP tools
- The hub acts as both an MCP server (to the agent) and an HTTP client (to workers) — the hub-and-spoke topology the MCP spec identifies as the confused-deputy attack surface

The architecture is directly applicable to industry: replace the stub services with real calendar/email/Slack APIs, configure the OAuth server against your identity provider (Okta, Azure AD, etc.), and the RFC 8693 exchange pattern works unchanged.

---

## Standards Referenced

- **RFC 8693** — OAuth 2.0 Token Exchange (IETF, 2020)
- **RFC 9068** — JWT Profile for OAuth 2.0 Access Tokens
- **MCP Security Best Practices** — Model Context Protocol specification
- **IETF CAAM draft** — Cross-domain Attributes in Authentication and Authorization Mechanisms
- **OWASP GenAI Top 10** — LLM06 Excessive Agency, LLM07, LLM08, LLM09
- **Hardy 1988** — "The Confused Deputy (or why capabilities might have been invented)"
- **Google A2A Protocol** — Agent-to-agent communication (gap comparison)

---

## Known Limitations

- All latency measurements are on a single localhost machine; absolute numbers are environment-dependent; the *relative* overhead between baseline and secure is the paper's claim
- OAuth consent is simulated via `X-Simulated-User` header; no PKCE, no real browser flow
- Worker business logic returns deterministic stub data (no real calendar/email/Slack APIs)
- The LLM planner falls back to a rule-based planner when no API key is set
- Redis is single-instance; production deployments should use Redis Cluster or Sentinel
