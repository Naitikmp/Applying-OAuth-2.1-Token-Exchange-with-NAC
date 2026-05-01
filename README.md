# Secure Delegation for MCP Agentic Workflows

Reference implementation and evaluation harness for the security pattern
described in the accompanying paper `paper_6.tex`
(_"Secure Delegation for MCP Agentic Workflows via OAuth Token Exchange
and Nested Actor Claims"_).

The pattern defines four security properties for MCP hub-to-worker
delegation:

- **P1** Audience binding — each token is valid only at one target service
- **P2** Scope attenuation — child tokens carry the minimum scope a worker needs
- **P3** Delegation chain visibility — every delegation hop is recorded in a nested `act` claim
- **P4** Atomic single-use enforcement — each child token is consumed on first presentation

Token passthrough (the default in many current MCP deployments) violates all
four simultaneously. This repository provides a full working implementation
of the RFC 8693 Nested Actor Claims pattern that restores them by
construction.

---

## Key measured results

All results are reproducible from this repository using the commands below.

| Measurement | Value | Produced by |
|---|---|---|
| Attack block rate (A1 scope, A2 lateral, A3 replay) | 100% (30/30 each) | `run_eval.py` |
| Attribution rate (A4) | 100% (30/30) | `run_eval.py` |
| Ablation independence (720 trials × 6 configs) | Full NAC is the only config that blocks all four | `run_ablation.py` |
| Per-hop cryptographic cost | 2.15 ms (RSA-2048 + Redis) | `run_eval.py` |
| O(k) linearity, k = 1…10 hops | R² = 0.9999 | `run_eval.py` |
| Co-located end-to-end overhead | +35.6% | `run_eval.py` |
| Real distributed Docker overhead | +217 ms (baseline 20.8 ms → secure 238.2 ms) | `run_distributed_real.py` |
| Concurrent stress test (5 agents × 30 rounds) | 600/600 ops, 143 exchanges/s | `run_concurrent_stress.py` |
| Auth0 real-IdP validation (M2M) | 100% (30/30) | `eval_auth0.py` |
| Alternative-pattern comparison | Only NAC satisfies all four properties | `run_alt_comparison.py` |

---

## Quick start (3 commands)

```bash
# 0. Install deps and start Redis (once)
pip install -r requirements.txt
docker run -d -p 6379:6379 --name nac-redis redis:7-alpine

# 1. See the problem — all four attacks succeed under token passthrough
python run_problem_demo.py

# 2. See the solution — all four attacks blocked under RFC 8693 NAC
python run_solution_demo.py

# 3. Reproduce the measured numbers (N=30 trials)
python run_eval.py --rounds 30
```

---

## Repository layout

### Core library

| File | Role |
|---|---|
| `nac_common.py` | JWT issuance, RFC 8693 exchange, Redis JTI store (register / revoke / atomic consume) |
| `oauth_server.py` | Authorization server with `/token/exchange` and consent endpoints |
| `assistant_server.py` | MCP hub — concurrent token exchange per worker |
| `worker_servers.py` | MCP workers (Calendar / Docs / Comms / External-API) |
| `agents.py` | Agent planners (stub + optional Claude) and attacker agents |
| `audit_log.py` | Structured JSON-line audit logger |

### Demo scripts

| File | Shows |
|---|---|
| `run_problem_demo.py` | Baseline stack on ports 9200–9205; all four attacks succeed |
| `run_solution_demo.py` | Secure NAC stack on ports 9300–9305; all four attacks blocked |

### Evaluation scripts

| File | Measures | Output |
|---|---|---|
| `run_eval.py` | Attack block rates + end-to-end latency + per-hop cost | `results/eval_results.json` |
| `eval_harness.py` | Library used by `run_eval.py` | — |
| `run_ablation.py` | 720-trial ablation: 6 configs × 4 attacks × 30 trials | `results/ablation_results.json` |
| `run_concurrent_stress.py` | 5 concurrent agents × 30 rounds; Redis atomicity under load | `results/stress_results.json` |
| `run_alt_comparison.py` | Measured comparison against Passthrough, Passthrough+Aud, Introspection, Token Vault | `alt_comparison_results.json` |
| `run_distributed_real.py` | End-to-end latency against a real containerised six-service topology | `distributed_real_results.json` |
| `generate_charts.py` | Paper figures from evaluation results | `figures/*.png` |

### Distributed deployment (Docker)

| File | Role |
|---|---|
| `Dockerfile` | Common image for oauth server + benchmark workers |
| `docker-compose.distributed.yml` | 6-service stack (redis + oauth + 4 workers) on a Docker bridge network |
| `service_bench_oauth.py` | Containerised oauth server entrypoint |
| `service_bench_worker.py` | Minimal HTTP worker (pure validation, no MCP) used inside containers |

### Auth0 real-IdP integration

| File | Role |
|---|---|
| `auth0_config.py` | Reads `.env`, derives Auth0 settings |
| `auth0_exchange_server.py` | RFC 8693 sidecar that validates Auth0 JWTs and issues NAC child tokens |
| `run_auth0_demo.py` | 18-check end-to-end Auth0 demo |
| `eval_auth0.py` | Auth0 evaluation harness (30-trial attack test) |
| `AUTH0_SETUP.md` | Step-by-step Auth0 tenant setup guide (~15 min) |

### Paper

| File | Role |
|---|---|
| `paper_6.tex` | LaTeX source — compile twice with `pdflatex paper_6.tex` |

---

## Full evaluation suite

```bash
# Main evaluation (attack block rates, latency, per-hop cost)
python run_eval.py --rounds 30
# → results/eval_results.json

# Ablation study (720 trials)
python run_ablation.py --trials 30
# → results/ablation_results.json

# Concurrent stress test
python run_concurrent_stress.py
# → results/stress_results.json

# Alternative-pattern comparison
python run_alt_comparison.py --trials 30
# → alt_comparison_results.json

# Real distributed evaluation (Docker)
docker compose -f docker-compose.distributed.yml up --build -d
python run_distributed_real.py --trials 30
docker compose -f docker-compose.distributed.yml down
# → distributed_real_results.json

# Generate figures
python generate_charts.py
# → figures/nac_fig*.png

# Auth0 validation (requires .env setup — see AUTH0_SETUP.md)
python eval_auth0.py --rounds 30
# → results/eval_auth0_results.json
```

---

## Port layout

| Stack | OAuth / Sidecar | Hub | Calendar | Docs | Comms | External |
|---|---|---|---|---|---|---|
| Baseline (insecure) | 9200 | 9201 | 9202 | 9203 | 9204 | 9205 |
| Secure (NAC) | 9300 | 9301 | 9302 | 9303 | 9304 | 9305 |
| Auth0 sidecar | 9400 | — | — | — | — | — |
| Redis | 6379 | — | — | — | — | — |
| Docker distributed | 9300 (oauth) | — | 9302 | 9303 | 9304 | 9305 |

---

## Auth0 integration (optional)

Validates the RFC 8693 sidecar pattern against a live production identity
provider. ~15 minutes to set up.

```bash
# After configuring .env (see AUTH0_SETUP.md):
python run_auth0_demo.py --check-only    # validate config
python run_auth0_demo.py                 # full end-to-end demo
python eval_auth0.py --rounds 30         # 30-trial attack test with real tokens
```

`AUTH0_SETUP.md` contains the detailed setup steps (API creation, M2M
client configuration, `.env` template, troubleshooting).

---

## Design invariants

1. **`NAC_PUBLIC_ONLY=1` on workers** — workers cannot load the private signing key; worker compromise does not enable token forgery.
2. **Atomic JTI consumption** — workers use `consume_jti()` (Redis Lua script) rather than a separate check-then-revoke pair. No TOCTOU race.
3. **`CHILD_TOKEN_TTL + 60 = 180 s` cleanup horizon** — revoked JTIs survive the token's full remaining lifetime.
4. **`asyncio.gather` in `assistant_server.py`** — concurrent token exchange (optional batch optimisation; sequential per-request exchange also supported).
5. **Redis as JTI state store** — sub-millisecond atomic operations; supports Lua scripts for single-shot check-and-mark.

---

## Optional: real Claude LLM planner

```bash
ANTHROPIC_API_KEY=sk-ant-... python run_solution_demo.py
```

Uses Claude Sonnet as the MCP agent planner. Without the key, a
deterministic stub planner is used (identical security results).

---

## Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| Python | 3.10+ | runtime |
| Docker | any recent | Redis + distributed evaluation |
| Auth0 account | — | optional (for real-IdP demo only) |

---

## License

Released under MIT for reference-implementation use.
