# OAuth 2.1 Token Exchange with Nested Actor Claims for MCP Agentic Workflows

Reference implementation and evaluation harness for the paper:
> *Applying OAuth 2.1 Token Exchange with Nested Actor Claims to MCP Agentic Workflows*

The paper formalises and evaluates a security pattern that eliminates the **Confused Deputy Problem** in Model Context Protocol (MCP) hub-to-worker delegation. The pattern uses RFC 8693 (OAuth 2.0 Token Exchange) with Nested Actor Claims so that each worker receives a token scoped only to that worker — audience-bound, scope-attenuated, and one-time-use — rather than the user's original token forwarded unchanged.

---

## Architecture

```
         ┌──────────────┐
   user  │  OAuth Server │  issues root token T₀
    ──►  │  (port 9300)  │  (or Auth0 in real-IdP mode)
         └──────┬────────┘
                │ RFC 8693 /token/exchange  ×4 (concurrent)
         ┌──────▼────────┐
         │ Assistant Hub │  MCP orchestrator
         │  (port 9301)  │  exchanges T₀ → Tᵢ per worker
         └──┬──┬──┬──┬───┘
            │  │  │  │  each Tᵢ: aud=Wᵢ, scope=sᵢ, act chain, JTI
     ┌──────┘  │  │  └──────┐
     │         │  │         │
  Calendar   Docs  Comms  External
  (9302)    (9303) (9304)  (9305)
```

**Baseline stack** (ports 9200–9205): token passthrough — all 4 attacks succeed  
**Secure stack** (ports 9300–9305): RFC 8693 NAC — all 4 attacks blocked  
**Auth0 stack** (port 9400 sidecar): real IdP root token, same NAC enforcement

---

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Python | 3.10+ | runtime |
| Docker | any | Redis JTI store |
| Auth0 account | ---- | optional real-IdP demo only |

```bash
# 1. Clone and install
git clone <repo-url>
cd agentic_multi_agent_nac_demo_LLM_based
pip install -r requirements.txt

# 2. Start Redis (keep running in a separate terminal for all demos/evals)
docker run -d -p 6379:6379 --name nac-redis redis:7-alpine
```

---

## Quick Start — 3 Commands

```bash
# See the problem: token passthrough lets all 4 attacks succeed
python run_problem_demo.py

# See the solution: RFC 8693 NAC blocks all 4 attacks
python run_solution_demo.py

# Run the full evaluation (N=30 rounds, produces results/eval_results.json)
python run_eval.py --rounds 30
```

Expected output from `run_solution_demo.py`:
```
Attack A1 (scope escalation)   → BLOCKED  [SCOPE_INSUFFICIENT]
Attack A2 (lateral movement)   → BLOCKED  [WRONG_AUDIENCE]
Attack A3 (token replay)       → BLOCKED  [TOKEN_REPLAY]
Attack A4 (identity confusion) → RESOLVED [act chain: assistant-hub → alice]
```

---

## Running the Full Evaluation Suite

```bash
# Main evaluation — attack block rates + latency tables
python run_eval.py --rounds 30
# → results/eval_results.json

# Ablation study — 720 trials across 6 enforcement configurations
python run_ablation.py --trials 30
# → results/ablation_results.json

# Concurrent stress test — 5 agents × 30 rounds × 4 workers
python run_concurrent_stress.py
# → results/stress_results.json

# Generate paper figures from eval results
python generate_charts.py
# → figures/nac_fig1_attacks.png … nac_fig5_hop_costs.png

# Auth0 real-IdP evaluation (requires Auth0 setup — see below)
python eval_auth0.py --rounds 30
# → results/eval_auth0_results.json
```

---

## File Map

```
Core implementation
├── nac_common.py            JWT issuance, RFC 8693 exchange, Redis JTI store
├── oauth_server.py          Authorization server with /token/exchange endpoint
├── assistant_server.py      MCP hub — concurrent token exchange per worker
├── worker_servers.py        Calendar/Docs/Comms/External-API MCP workers
├── agents.py                SimpleLLMPlanner, RealLLMAgent (Claude), attack agents
├── audit_log.py             Structured JSON-line audit logger

Demo scripts
├── run_problem_demo.py      Baseline insecure stack (ports 9200–9205)
├── run_solution_demo.py     Secure NAC stack (ports 9300–9305)
├── run_eval.py              Runs both stacks and evaluation harness

Evaluation
├── eval_harness.py          Attack tests + latency + per-hop measurements
├── run_ablation.py          Ablation study: 720 trials × 6 enforcement configs
├── run_concurrent_stress.py Concurrent agent stress test (5 agents, 600 ops)
├── generate_charts.py       Paper figures from eval results

Auth0 integration
├── auth0_config.py          Auth0 settings (reads from .env)
├── auth0_exchange_server.py RFC 8693 sidecar — validates Auth0 JWTs, issues child tokens
├── run_auth0_demo.py        Auth0 demo (18 security checks)
├── eval_auth0.py            Auth0 evaluation harness
├── AUTH0_SETUP.md           Detailed Auth0 setup guide
├── .env.auth0.example       Environment variable template

Results (generated — not committed)
├── results/eval_results.json        Main evaluation results
├── results/ablation_results.json    Ablation study results
├── results/stress_results.json      Concurrent stress test results
└── results/eval_auth0_results.json  Auth0 validation results

Figures (generated — not committed)
├── figures/nac_fig1_attacks.png
├── figures/nac_fig2_latency.png
├── figures/nac_fig3_token_sizes.png
├── figures/nac_fig4_summary.png
└── figures/nac_fig5_hop_costs.png

Paper
└── paper_5.tex              LaTeX source (IEEEtran journal format)
```

---

## Port Layout

| Stack | OAuth / Sidecar | Hub | Calendar | Docs | Comms | External |
|-------|----------------|-----|----------|------|-------|----------|
| Baseline (insecure) | 9200 | 9201 | 9202 | 9203 | 9204 | 9205 |
| Secure (NAC) | 9300 | 9301 | 9302 | 9303 | 9304 | 9305 |
| Auth0 sidecar | 9400 | — | — | — | — | — |
| Redis | 6379 | — | — | — | — | — |

---

## Security Properties Verified

| ID | Property | JWT Claim | Attack Tested |
|----|----------|-----------|---------------|
| P1 | Audience binding | `aud` per worker | A2 lateral movement |
| P2 | Scope attenuation | child scope ⊆ parent | A1 scope escalation |
| P3 | Delegation chain visibility | nested `act` claim | A4 identity attribution |
| — | One-time-use JTI | `jti` + Redis revocation | A3 token replay |

---

## Key Results

| Metric | Value |
|--------|-------|
| Attack block rate A1–A4 | **100%** (30/30 each, N=30) |
| Ablation (720 trials) | Full NAC is the **only** config that blocks all 4 attacks |
| Per-hop crypto cost | **2.15 ms** (RSA-2048 sign + Redis write) |
| O(k) linearity | R² = 0.9999 over k = 1…10 hops |
| End-to-end overhead | +35.6% sequential; ~O(1) with concurrent issuance |
| Concurrent stress test | 600/600 ops, 0 false positives, 143 exchanges/s |
| Auth0 validation | **100%** (30/30) with live Auth0 M2M root tokens |

---

## Auth0 Real-IdP Integration

Validates the RFC 8693 sidecar pattern against a live Auth0 tenant.
**Auth0 Setup takes ~15 minutes.**

### Step 1 — Create API in Auth0 Dashboard

Applications → APIs → **+ Create API**
- Name: `MCP Hub`
- Identifier: `https://mcp-hub.example.com` ← this is `AUTH0_HUB_AUDIENCE`
- Signing Algorithm: RS256

Open the new API → **Permissions** tab → add each scope:

| Permission | Description |
|-----------|-------------|
| `calendar:read` | Read calendar events |
| `docs:read` | Read documents |
| `comms:send` | Send communications |
| `external:fetch` | Fetch from external APIs |

### Step 2 — Create M2M Application

Applications → Applications → **+ Create Application** → Machine to Machine
- Name: `MCP Hub M2M`
- Authorize for `MCP Hub` API → check all 4 scopes → Authorize
- Copy: **Domain**, **Client ID**, **Client Secret**

### Step 3 — Configure credentials

Create `.env` in the project root:

```
AUTH0_DOMAIN=YOUR_TENANT.us.auth0.com
AUTH0_CLIENT_ID=YOUR_CLIENT_ID
AUTH0_CLIENT_SECRET=YOUR_CLIENT_SECRET
AUTH0_HUB_AUDIENCE=https://mcp-hub.example.com
AUTH0_ROOT_SCOPES=calendar:read docs:read comms:send external:fetch
```

### Step 4 — Run

```bash
python run_auth0_demo.py --check-only   # validate config
python run_auth0_demo.py                # full 18-check demo
python eval_auth0.py --rounds 30        # evaluation with real tokens
```

See `AUTH0_SETUP.md` for detailed troubleshooting.

---

## Compile the Paper

```bash
pdflatex paper_5.tex && pdflatex paper_5.tex
```

Run twice — second pass resolves cross-references and figure placement.
Requires a TeX distribution with: IEEEtran, pgfplots, booktabs, tikz, colortbl.

---

## Optional: Real LLM Planner

```bash
ANTHROPIC_API_KEY=sk-ant-... python run_solution_demo.py
```

Uses Claude Sonnet as the MCP agent planner. Without the key, a deterministic stub planner is used (produces identical security results).

---

## Design Invariants

These are load-bearing for the paper's security claims.

1. **`NAC_PUBLIC_ONLY=1` on workers** — workers cannot load the private signing key
2. **`revoke_jti()` stores `time.time()`** not `0.0` — prevents immediate cleanup from deleting revocation records
3. **Cleanup horizon = `CHILD_TOKEN_TTL + 60 = 180s`** — revoked JTIs survive their token's full TTL
4. **`asyncio.gather` in `assistant_server.py`** — concurrent token exchange (O(1) overhead per Proposition 1)
5. **Redis as JTI store** — ~0.1 ms/op; file-based locks on Windows are ~65 ms/op
