# NAC for MCP — Research Demo v2

**"Applying OAuth 2.1 Token Exchange with Nested Actor Claims to MCP Workflows"**

This codebase is the proof-of-concept implementation accompanying the paper.
It demonstrates — and measures — four MCP token-passthrough attacks in a
baseline (insecure) stack, and shows how NAC blocks all four in the secure stack.

---

## Quick start

```bash
pip install -r requirements.txt

# Run baseline demo (all 4 attacks succeed)
python run_problem_demo.py

# Run secure NAC demo (all 4 attacks blocked)
python run_solution_demo.py

# Optional: set ANTHROPIC_API_KEY to use real Claude as the agent planner
ANTHROPIC_API_KEY=sk-... python run_solution_demo.py

# Run full evaluation (starts both stacks, measures everything)
python run_eval.py --rounds 30
```

---

## File map

| File | Purpose |
|---|---|
| `nac_common.py` | JWT issuance, exchange, validation, actor-chain walking |
| `audit_log.py` | Structured JSON-line audit logger |
| `oauth_server.py` | RFC 8693 compliant authorization server |
| `assistant_server.py` | Hub MCP server (all 4 attack tools) |
| `worker_servers.py` | Calendar / Docs / Comms / External-API MCP workers |
| `agents.py` | SimpleLLMPlanner, RealLLMAgent (Claude), all attack agents |
| `eval_harness.py` | Attack measurement, latency, token-size statistics |
| `run_problem_demo.py` | Baseline demo runner |
| `run_solution_demo.py` | Secure NAC demo runner |
| `run_eval.py` | Full evaluation runner |

---

## Attack scenarios

| ID | Name | Baseline | Secure |
|---|---|---|---|
| A1 | Scope escalation (HR payroll read) | Succeeds | BLOCKED (SCOPE_INSUFFICIENT) |
| A2 | Lateral movement (wrong audience) | Succeeds | BLOCKED (WRONG_AUDIENCE) |
| A3 | Token replay (jti reuse) | Succeeds | BLOCKED (TOKEN_REPLAY) |
| A4 | Identity confusion (act chain) | 0% attribution | 100% attribution |

---

## What changed from v1 (reviewer fixes)

### Security
- `validate_actor_chain` has a depth limit of 10 (prevents infinite-loop attack)
- Workers set `NAC_PUBLIC_ONLY=1` — they never load the signing key
- jti revocation: parent token jti is revoked after each exchange (replay prevention)
- Structured error codes: 401 TOKEN_MISSING, 403 WRONG_AUDIENCE / SCOPE_INSUFFICIENT / UNTRUSTED_ACTOR / TOKEN_REPLAY
- Token via HTTP Authorization header (not tool argument)

### RFC 8693 compliance
- `/token/exchange` uses form-encoded body with proper `grant_type` URN
- `subject_token_type`, `actor_token`, `actor_token_type`, `issued_token_type` present
- Assistant calls OAuth server HTTP endpoint (not a local function)
- Workers are pure relying parties with no signing capability

### Evaluation
- All 4 attacks implemented and measured with N trials
- Latency distribution: mean / p50 / p95 / p99 / stdev
- Token size overhead: root vs 1-hop vs 2-hop bytes
- Attribution rate metric for A4

### Architecture
- 3-hop chain: user → assistant → calendar → external-api
- Structured audit log (JSON lines, `/tmp/nac_audit.log`)
- Real LLM planner via Claude API (ReAct loop with MCP tools)

---

## Port layout

| Stack | OAuth | Assistant | Calendar | Docs | Comms | External-API |
|---|---|---|---|---|---|---|
| Baseline | 9200 | 9201 | 9202 | 9203 | 9204 | 9205 |
| Secure | 9300 | 9301 | 9302 | 9303 | 9304 | 9305 |

---

## Standards referenced

- **RFC 8693** — OAuth 2.0 Token Exchange
- **MCP Security Best Practices** — https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- **IETF CAAM draft** — Chain of authority for agentic models
- **OWASP GenAI Top 10** — LLM security guide
