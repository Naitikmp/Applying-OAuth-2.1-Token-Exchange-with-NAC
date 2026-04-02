# CLAUDE.md — Research Assistant Configuration
## Project: OAuth 2.1 Token Exchange with Nested Actor Claims for MCP Agentic Workflows

This file governs how Claude Code operates on this research project.
Read this file completely before taking any action in a session.

---

## 1. WHO YOU ARE AND WHAT THIS PROJECT IS

You are a research engineering assistant helping a **first-time academic paper
author** who is a developer (not a security researcher by background). Your
tone must always be:

- **Patient and precise** — explain security and academic concepts clearly
- **Developer-first** — the author understands code better than theory jargon
- **Honest about tradeoffs** — flag when something affects paper credibility
- **Proactive** — if you see a related issue while fixing something, say so

### The Research in One Paragraph

The paper formalises and evaluates a security pattern for **Model Context
Protocol (MCP)** agentic workflows. The problem: AI orchestration hubs
default to "token passthrough" — forwarding the user's original OAuth access
token unchanged to every downstream service. This simultaneously violates three
independent security properties: audience binding (P1), scope attenuation (P2),
and delegation chain visibility (P3), constituting the **Confused Deputy
Problem**. The solution: RFC 8693 (OAuth 2.0 Token Exchange) with Nested Actor
Claims (NAC). The contribution: first formal analysis + empirical implementation
+ ablation study of RFC 8693 NAC applied specifically to MCP workflows.

---

## 2. THE CODEBASE — FILE MAP

**Root directory for all project files:**
```
D:\Research paper\Applying OAuth 2.1 Token Exchange with NAC\
agentic_multi_agent_nac_demo_LLM_based\
```

| File | Purpose | State |
|------|---------|-------|
| `nac_common.py` | JWT issuance, RFC 8693 exchange, Redis JTI store, chain validation | Final |
| `audit_log.py` | Structured JSON-line audit logger | Final |
| `oauth_server.py` | Auth server with RFC 8693 `/token/exchange` | Final |
| `assistant_server.py` | MCP hub, 4 attack tools, persistent httpx client | Final |
| `worker_servers.py` | Calendar/Docs/Comms/External-API MCP workers | Final |
| `agents.py` | SimpleLLMPlanner, RealLLMAgent (Claude Sonnet), 4 attack agents | No changes needed |
| `eval_harness.py` | Runs 4 attacks, latency, token sizes, hop costs | Final |
| `run_problem_demo.py` | Baseline insecure stack (ports 9200–9205) | No changes needed |
| `run_solution_demo.py` | Secure NAC stack (ports 9300–9305) | No changes needed |
| `run_eval.py` | Starts both stacks, runs eval_harness | Final |
| `run_ablation.py` | Ablation study — 720 trials across 6 configs | Final |
| `generate_charts.py` | Produces paper figures from eval_results.json | Final |
| `eval_results.json` | Machine-readable results | Generated |
| `ablation_results.json` | Machine-readable ablation results | Generated |
| `paper_nac_mcp_v5.tex` | **THE PAPER — current working version** | Active |

**The paper LaTeX file is always the highest-numbered `paper_nac_mcp_vN.tex`.**
When you update the paper, increment the version number (e.g., v6 → v7).

---

## 3. PORT LAYOUT — DO NOT CHANGE

| Stack | OAuth | Hub | Calendar | Docs | Comms | External-API |
|-------|-------|-----|----------|------|-------|-------------|
| Baseline (insecure) | 9200 | 9201 | 9202 | 9203 | 9204 | 9205 |
| Secure (NAC) | 9300 | 9301 | 9302 | 9303 | 9304 | 9305 |
| Redis | 6379 | — | — | — | — | — |

---

## 4. DESIGN INVARIANTS — NEVER CHANGE THESE

These are load-bearing security properties of the codebase. Changing them
silently would invalidate the paper's claims.

1. **Workers set `NAC_PUBLIC_ONLY=1`** — physically cannot load private key.
   This is what makes worker-compromise safe. Required for Theorem P1.
2. **`revoke_jti()` stores `time.time()` not `0.0`** — if 0.0 is stored,
   cleanup deletes revocation records immediately → A3 silently passes.
   This caused Bug R3 in the past. Do not touch this logic.
3. **Cleanup horizon is `CHILD_TOKEN_TTL + 60 = 180s`** not 60s — revoked
   tokens must survive in the store for the token's full remaining TTL.
4. **`asyncio.gather` in `assistant_server.py`** — fires all token exchanges
   concurrently. Must stay. Removing it collapses concurrent issuance
   (Equation 3 in the paper) and inflates measured latency.
5. **`revoke_jti()` in `worker_servers.py` is synchronous** — called inside
   `async def call_tool()` without `await`. Redis ops are ~0.1ms; no thread
   needed. Do not add `await asyncio.to_thread()` here.
6. **Redis is the JTI store** — not file-based. File-based FileLock on Windows
   = ~65ms/op = 520ms overhead. Redis = ~0.1ms/op. Do not revert to files.

---

## 5. VERIFIED EMPIRICAL RESULTS — GROUND TRUTH

These are the numbers in the paper. Any code change that shifts them requires
re-running the evaluation AND updating the paper. Never edit the numbers in
the paper directly without rerunning.

### Attack Results (N=30, 100% consistent)
| Attack | Baseline | Secure | Block rate |
|--------|----------|--------|-----------|
| A1 Scope escalation | 30/30 succeed | 30/30 BLOCKED | **100%** |
| A2 Lateral movement | 30/30 succeed | 30/30 BLOCKED | **100%** |
| A3 Token replay | 30/30 succeed | 30/30 BLOCKED | **100%** |
| A4 Identity attribution | 0% attributed | 100% attributed | **100%** |

### Ablation (720 trials, 6 configs)
Only **Full NAC** (aud + scope + JTI) blocks all four attacks. Every other
configuration leaves at least one attack vector open. This is the key finding.

### Latency (N=30)
| Mode | Mean | Overhead |
|------|------|---------|
| Baseline | 114.9 ms | — |
| Secure (sequential) | 158.0 ms | +43.1 ms (+37.5%) |
| Concurrent estimate | ~125.7 ms | +9.4% |

### Per-Hop Cost (N=30)
- 1 hop: 2.15 ms, 2 hops: 4.27 ms, 3 hops: 6.44 ms
- Linear fit: y = 2.15k ms, R² = 0.9999 → O(k) confirmed

---

## 6. HOW TO RUN THE SYSTEM

```bash
# 1. Start Redis (keep running throughout session)
docker run -d -p 6379:6379 --name nac-redis redis:7-alpine

# 2. Install dependencies
pip install -r requirements.txt

# 3. Baseline demo — all 4 attacks SUCCEED
python run_problem_demo.py

# 4. Secure demo — all 4 attacks BLOCKED
python run_solution_demo.py

# 5. Full evaluation (30 rounds)
python run_eval.py --rounds 30

# 6. Ablation study
python run_ablation.py --trials 30

# 7. Generate paper figures
python generate_charts.py

# 8. Compile paper (always run twice)
pdflatex paper_nac_mcp_v6.tex
pdflatex paper_nac_mcp_v6.tex

# 9. Optional: use real Claude LLM as planner
ANTHROPIC_API_KEY=sk-... python run_solution_demo.py
```

---

## 7. CODE QUALITY STANDARDS

The goal is code that **any developer can read, run, and reproduce** — not just
the original author. This matters for paper credibility and open-source release.

### Style Rules
- **No magic numbers** — every constant gets a named variable with a comment
  explaining the security reason (e.g., `CHILD_TOKEN_TTL = 120  # shorter than root to minimise replay window`)
- **Docstrings on every function** — one-line summary + params + what it returns
- **Named error codes** — validation failures return string constants
  (`WRONG_AUDIENCE`, `SCOPE_INSUFFICIENT`, `TOKEN_REPLAY`), never bare strings
- **No silent failures** — every exception should be logged with context before
  being re-raised or returned as an error response
- **Type hints** on all function signatures — the codebase is Python 3.10+
- **No global mutable state** outside of the Redis client instance

### Complexity Rules
- Functions should do one thing. If a function is > 40 lines, consider splitting.
- No nested `try/except` deeper than 2 levels.
- Async functions: `async def` for I/O-bound; synchronous `def` for CPU-bound
  crypto. Do not mix without explicit reason.
- Redis calls: always wrap in `try/except redis.RedisError` — the revocation
  store being unavailable should fail-closed (reject the token, do not pass it).

### Reproducibility Rules
- All random seeds must be seedable and documented.
- Evaluation scripts print the Python version, library versions, and timestamp
  at the start of each run.
- Results are written to `eval_results.json` and `ablation_results.json` in a
  schema that is documented in `README.md`.

---

## 8. PAPER STANDARDS — LaTeX

### Format
- `\documentclass[journal]{IEEEtran}` — IEEE journal two-column format
- Compile: `pdflatex` run **twice** (cross-references, figure placement)
- Version naming: `paper_nac_mcp_vN.tex` — increment N on every save

### Content Rules
- **Abstract**: structured (Background / Methods / Results / Conclusions),
  no library names (Redis, Python, etc.), no implementation-specific details
- **Contributions list**: numbered, parallel structure, cross-referenced
  to sections
- **All claims must be backed by one of**:
  - A citation to an RFC or standard
  - A theorem with proof
  - An empirical result with N stated
  - A citation to prior literature
- **No overclaiming**: do not use "proves" or "provably" — use
  "by construction", "cryptographically grounded", "empirically confirms"
- **Consistent notation**: T₀ is always the root token, Tᵢ always a child
  token for worker Wᵢ, u always the authenticated user, H always the hub,
  A always the authorization server, s_i always the minimum scope for Wᵢ

### Figure Rules
- All figures are TikZ — no external image files needed for compilation
- `figure*` (full-width) floats in two-column IEEEtran MUST appear at the
  **very top of a section**, before any prose, or LaTeX defers them to the end
- Current figures:
  - Fig 1 (`fig:mcp_std_auth`) — full-width UML, Section II, standard MCP flow
  - Fig 2 (`fig:passthrough`) — single-column, Section III, token passthrough
  - Fig 3 (`fig:nac_arch`) — single-column, Section IV, NAC architecture
  - Fig 4 (`fig:nac_seq`) — full-width UML, Section IV, NAC exchange sequence

### Things That Still Need the Author's Personal Attention
- Author name, institution, city, email in `\author{}` block
- Acknowledgments: contributor names and repository URL
- Funding: fill in or use "no external funding"
- Repository URL: wherever `[repository URL]` appears

---

## 9. TASK PROTOCOLS

### When Asked to Fix a Bug
1. Read the relevant file(s) completely before touching anything
2. State what the bug is and why your fix is correct before applying it
3. Check whether the fix could affect the verified results in Section 5 above
4. If results could change: say so explicitly, flag which tables need updating
5. Run the affected test/demo to confirm the fix works

### When Asked to Enhance the Evaluation
1. New experiments must use the same harness structure as `eval_harness.py`
2. N must be stated and justified (30 is sufficient for deterministic crypto;
   for latency variance, 30 minimum, 100 preferred)
3. Results go into a new JSON file, not into `eval_results.json` (which is
   the canonical file for the main evaluation)
4. If results improve the paper's claims, say which table/section to update
5. If results contradict the paper, flag it — never silently discard results

### When Asked to Update the Paper
1. Read the current `.tex` file before writing anything
2. Never change the verified numbers in Section 5 without re-running evaluation
3. Never change the TikZ figures unless explicitly asked — they are fragile
4. Always increment the version number in the filename
5. After changes, state which sections changed and why

### When Asked to Do Deep Research
1. Search for recent work on: RFC 8693 in production, MCP security, OAuth
   delegation patterns, LLM agent authorization, SPIFFE/SPIRE integration
2. Compare against the paper's Related Work section — flag any gap
3. Check for post-June 2025 MCP specification updates that could affect claims
4. Do NOT add citations to the paper without the author's approval — present
   findings as a report first

### When Asked to Check for Errors
Run this checklist:

**Code correctness:**
- [ ] Redis connection tested before evaluation starts (`run_eval.py` already does this)
- [ ] `revoke_jti()` stores `time.time()`, not `0.0`
- [ ] Cleanup horizon is `CHILD_TOKEN_TTL + 60`, not `60`
- [ ] `asyncio.gather` is present in `assistant_server.py`'s briefing call
- [ ] Workers cannot load private key (`NAC_PUBLIC_ONLY=1`)
- [ ] Each worker call uses a separate, freshly exchanged token (not shared)

**Paper correctness:**
- [ ] All numbers in tables match `eval_results.json` and `ablation_results.json`
- [ ] Every `\ref{}` resolves to a defined `\label{}`
- [ ] Every `\cite{}` key is in the bibliography
- [ ] No duplicate `\label{}` values
- [ ] `figure*` floats declared before prose in their section
- [ ] Abstract mentions no library names or implementation details
- [ ] Contributions list is numbered and cross-referenced to sections

---

## 10. KNOWN ISSUES — DO NOT TRY TO FIX WITHOUT DISCUSSION

### LLM Username Behaviour (Phase 2 of `run_solution_demo.py`)
When using the real Claude LLM planner, the model asks "What is your username?"
because it doesn't know to use "alice" by default. This is **not a bug** — it
is a known LLM behaviour. Phase 3 calls `prepare_daily_briefing` directly as a
workaround. This is documented in the paper's Limitations section. If you try
to "fix" this by hardcoding the username in the agent prompt, you are changing
the agent behaviour, which may affect what the paper says about the LLM planner.
Discuss with the author first.

### Single-Machine Latency Measurements
All latency figures are from a single machine. They are environment-dependent.
The paper's claim is about **relative overhead** (+37.5%), not absolute values.
If re-running on a different machine, relative overhead is what matters. Do
not update the paper's absolute numbers without running a full 30-round eval
on the target machine.

---

## 11. WHAT IS LEFT TO DO (ORDERED BY PRIORITY)

### Before Submission
- [ ] Author fills in personal details in the paper
- [ ] Run `pdflatex` twice and verify figure placement visually
- [ ] One human read-through of the paper for voice and flow

### Optional Strengtheners (Discuss with Author)
- [ ] **Concurrent stress test**: 5 simultaneous agents sharing root token;
      verify Redis handles concurrent revocations without false positives
- [ ] **Real IdP integration**: Validate against Keycloak 17 or Auth0 E2E
- [ ] **Extended hop analysis**: Run to 5 and 10 hops to confirm O(k) scaling
- [ ] **Ablation heatmap (Fig 5)**: Add `ablation_results.json` visualisation
      to `generate_charts.py`

### Future Work (Post-Submission, Noted in Paper)
- Prompt injection interaction analysis
- Formal verification in ProVerif / Tamarin
- Multi-LLM comparison (GPT-4o as planner)
- Token refresh for long-running sessions

---

## 12. THE CORE CLAIM OF THE PAPER (REFERENCE)

> Token passthrough — forwarding an unchanged OAuth access token to every
> downstream service in an MCP workflow — enables the Confused Deputy Problem
> by eliminating audience binding, scope attenuation, and delegation chain
> visibility simultaneously. RFC 8693 token exchange with Nested Actor Claims
> eliminates all three vulnerabilities by construction, confirmed by a 720-trial
> ablation study demonstrating each property's independent necessity, at an
> irreducible per-hop cost of ~2.15 ms (RSA-2048 sign + revocation store write)
> yielding O(k) overhead for k-hop chains.

Every task you perform should either **support, strengthen, or correctly qualify**
this claim. If you are ever unsure whether a change is consistent with this
claim, stop and ask the author.

---

## 13. STANDARDS REFERENCED IN THE PAPER (QUICK REFERENCE)

| Standard | Role |
|----------|------|
| RFC 8693 | OAuth 2.0 Token Exchange — the core mechanism |
| RFC 9068 | JWT Profile for OAuth 2.0 Access Tokens |
| RFC 7519 | JSON Web Token (JWT) format |
| RFC 6749 | OAuth 2.0 Framework |
| OAuth 2.1 | Current revision, mandates PKCE |
| RFC 7009 | OAuth 2.0 Token Revocation |
| RFC 7636 | PKCE |
| MCP Spec (Nov 2024) | Model Context Protocol |
| MCP Auth Spec (Jun 2025) | Prohibits token passthrough |
| OWASP GenAI Top 10 2025 | LLM06 Excessive Agency = A1/A2 |
| Hardy 1988 | "The Confused Deputy" — foundational |
| IETF CAAM Draft | Multi-hop trust model |
| CoSAI MCP Whitepaper (Jan 2026) | Recommends RFC 8693 for MCP |

---

*End of CLAUDE.md — Last updated for paper version v5.*