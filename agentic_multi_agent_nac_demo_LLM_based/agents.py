"""
Agent implementations for the NAC demo — v2.

Agents:
  SimpleLLMPlanner    — rule-based planner, no API key needed (original approach)
  RealLLMAgent        — uses Claude claude-opus-4-6 via Anthropic API as the planner (requires
                        ANTHROPIC_API_KEY env var); falls back to SimpleLLMPlanner if absent
  AssistantAgent      — legitimate user agent (uses RealLLMAgent when possible)
  AttackerAgent       — scope escalation attack (A1)
  LateralMovementAgent — audience mismatch attack (A2)
  TokenReplayAgent    — jti replay attack (A3)
  IdentityConfusionAgent — audit-log attribution test (A4)

Token transport:
  All agents pass the JWT in the HTTP Authorization header when connecting to the
  assistant's SSE endpoint — not as a tool argument.  This matches real MCP usage.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from time import perf_counter
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.sse import sse_client


# ── simple rule-based planner (no LLM needed) ─────────────────────────────────

@dataclass
class AgentPlan:
    intent:     str
    tool_calls: list[tuple[str, dict[str, Any]]]


class SimpleLLMPlanner:
    """Keyword-based planner that stands in for an LLM."""

    def plan(self, user_prompt: str) -> AgentPlan:
        text       = user_prompt.lower()
        tool_calls: list[tuple[str, dict[str, Any]]] = []

        if any(k in text for k in ["connect", "workspace", "login", "auth"]):
            username = "alice"
            for part in text.split():
                if "@" in part or part.isalpha() and len(part) > 3:
                    username = part.strip(",.;")
                    break
            tool_calls.append(("connect_workspace", {"username": username}))

        if any(k in text for k in ["brief", "summary", "meeting", "today", "team"]):
            tool_calls.append(("prepare_daily_briefing", {}))

        if any(k in text for k in ["hr", "payroll", "salary", "escalat"]):
            tool_calls.append(("attempt_scope_escalation", {}))

        if any(k in text for k in ["lateral", "movement", "cross", "replay_lat"]):
            tool_calls.append(("attempt_lateral_movement", {}))

        if any(k in text for k in ["replay", "reuse", "capture"]):
            tool_calls.append(("attempt_token_replay", {}))

        if any(k in text for k in ["identity", "attribution", "audit", "who"]):
            tool_calls.append(("demonstrate_identity_attribution", {}))

        if not tool_calls:
            tool_calls.append(("inspect_session", {}))

        return AgentPlan(intent=user_prompt, tool_calls=tool_calls)


# ── real LLM planner (Claude claude-opus-4-6) ─────────────────────────────────────────

def _make_real_llm_planner():
    """
    Returns an async function that runs a full ReAct tool-use loop with Claude.
    Returns None if ANTHROPIC_API_KEY is not set.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return None

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
    except ImportError:
        print("[Agent] anthropic SDK not installed — falling back to SimpleLLMPlanner")
        return None

    async def llm_loop(session: ClientSession, user_prompt: str) -> list[dict[str, Any]]:
        """Run a Claude-driven tool-use loop over an MCP session."""
        # Convert MCP tools to Anthropic tool definitions
        mcp_tools = await session.list_tools()
        anthropic_tools = [
            {
                "name":        t.name,
                "description": t.description or "",
                "input_schema": t.inputSchema if isinstance(t.inputSchema, dict)
                                else {"type": "object", "properties": {}},
            }
            for t in mcp_tools.tools
        ]

        messages = [{"role": "user", "content": user_prompt}]
        results  = []

        print(f"[RealLLM] Starting Claude loop for: {user_prompt!r}")

        for _ in range(10):   # max iterations to prevent runaway loops
            response = client.messages.create(
                model      = "claude-sonnet-4-6",
                max_tokens = 1024,
                tools      = anthropic_tools,
                messages   = messages,
            )

            # Collect any text output
            for block in response.content:
                if hasattr(block, "text"):
                    print(f"[RealLLM] Claude: {block.text[:200]}")

            if response.stop_reason == "end_turn":
                break

            if response.stop_reason != "tool_use":
                break

            # Execute tool calls
            tool_results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                print(f"[RealLLM] Calling tool: {block.name}({json.dumps(block.input)[:80]})")
                mcp_result = await session.call_tool(block.name, block.input)
                result_text = mcp_result.content[0].text if mcp_result.content else "{}"
                results.append({"tool": block.name, "result": json.loads(result_text)})
                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": block.id,
                    "content":     result_text,
                })

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user",      "content": tool_results})

        return results

    return llm_loop


# ── base agent helpers ────────────────────────────────────────────────────────

class _BaseAgent:
    def __init__(self, server_url: str, token: str = "") -> None:
        self.server_url = server_url
        self.sse_url    = f"{server_url}/sse"
        self.token      = token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    async def _run(self, task_fn):
        async with sse_client(self.sse_url, headers=self._headers()) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                print(f"[{self.__class__.__name__}] Connected to '{init.serverInfo.name}'")
                return await task_fn(session)


# ── AssistantAgent ────────────────────────────────────────────────────────────

class AssistantAgent(_BaseAgent):
    """
    Legitimate user agent.  Uses the real LLM planner when ANTHROPIC_API_KEY is
    present, falls back to the rule-based planner otherwise.
    """

    def __init__(self, server_url: str, token: str = "") -> None:
        super().__init__(server_url, token)
        self.planner    = SimpleLLMPlanner()
        self._llm_loop  = _make_real_llm_planner()
        self.use_real_llm = self._llm_loop is not None

    async def list_tools(self):
        async def _task(session: ClientSession):
            result = await session.list_tools()
            print("\n[Agent] Available tools:")
            for t in result.tools:
                print(f"  • {t.name}: {t.description}")
        await self._run(_task)

    async def execute_prompt(self, user_prompt: str, external_url: str = "") -> list[dict]:
        plan = self.planner.plan(user_prompt)
        print(f"\n[Agent] Prompt: {plan.intent}")
        if self.use_real_llm:
            print("[Agent] Using real LLM planner (Claude claude-opus-4-6)")
        else:
            print("[Agent] Using rule-based planner (set ANTHROPIC_API_KEY for real LLM)")
        print("[Agent] Plan:")
        for name, args in plan.tool_calls:
            print(f"  → {name} {args}")

        results = []

        async def _task(session: ClientSession):
            if self.use_real_llm and self._llm_loop:
                llm_results = await self._llm_loop(session, user_prompt)
                results.extend(llm_results)
                return

            for tool_name, args in plan.tool_calls:
                if tool_name == "prepare_daily_briefing" and external_url:
                    args = {**args, "external_url": external_url}
                result = await session.call_tool(tool_name, args)
                text   = result.content[0].text if result.content else "{}"
                parsed = json.loads(text)
                results.append({"tool": tool_name, "result": parsed})
                print(f"\n[Agent] Tool result: {tool_name}")
                print(json.dumps(parsed, indent=2)[:800])

        await self._run(_task)
        return results

    async def measure_briefing(self, rounds: int = 30) -> dict[str, float]:
        """Measure latency for N rounds of prepare_daily_briefing."""
        durations: list[float] = []

        async def _task(session: ClientSession):
            for _ in range(rounds):
                t0 = perf_counter()
                await session.call_tool("prepare_daily_briefing", {})
                durations.append(perf_counter() - t0)

        await self._run(_task)

        durations.sort()
        n   = len(durations)
        avg = sum(durations) / n
        p50 = durations[n // 2]
        p95 = durations[int(n * 0.95)]
        p99 = durations[int(n * 0.99)]

        stats = {"mean": avg, "p50": p50, "p95": p95, "p99": p99,
                 "min": durations[0], "max": durations[-1], "n": n}
        print(f"\n[Agent] Latency over {n} rounds:")
        for k, v in stats.items():
            if k != "n":
                print(f"  {k:>5}: {v*1000:.1f} ms")
        return stats


# ── AttackerAgent (scope escalation — A1) ────────────────────────────────────

class AttackerAgent(_BaseAgent):
    """Mis-scoped agent attempting to read HR payroll (attack A1)."""

    async def try_scope_escalation(self) -> dict[str, Any]:
        result = {}

        async def _task(session: ClientSession):
            r = await session.call_tool("attempt_scope_escalation", {})
            result.update(json.loads(r.content[0].text))
            print("\n[Attacker] Scope escalation result:")
            print(json.dumps(result, indent=2))

        await self._run(_task)
        return result


# ── LateralMovementAgent (A2) ─────────────────────────────────────────────────

class LateralMovementAgent(_BaseAgent):
    """Agent that replays a calendar token against the docs worker (attack A2)."""

    async def try_lateral_movement(self) -> dict[str, Any]:
        result = {}

        async def _task(session: ClientSession):
            r = await session.call_tool("attempt_lateral_movement", {})
            result.update(json.loads(r.content[0].text))
            print("\n[LateralAttacker] Lateral movement result:")
            print(json.dumps(result, indent=2))

        await self._run(_task)
        return result


# ── TokenReplayAgent (A3) ─────────────────────────────────────────────────────

class TokenReplayAgent(_BaseAgent):
    """Agent that replays a captured child token (attack A3)."""

    async def try_token_replay(self) -> dict[str, Any]:
        result = {}

        async def _task(session: ClientSession):
            r = await session.call_tool("attempt_token_replay", {})
            result.update(json.loads(r.content[0].text))
            print("\n[ReplayAttacker] Token replay result:")
            print(json.dumps(result, indent=2))

        await self._run(_task)
        return result


# ── IdentityConfusionAgent (A4) ───────────────────────────────────────────────

class IdentityConfusionAgent(_BaseAgent):
    """Demonstrates audit-log attribution gap (attack A4)."""

    async def demonstrate(self) -> dict[str, Any]:
        result = {}

        async def _task(session: ClientSession):
            r = await session.call_tool("demonstrate_identity_attribution", {})
            result.update(json.loads(r.content[0].text))
            print("\n[IdentityAgent] Attribution result:")
            print(json.dumps(result, indent=2))

        await self._run(_task)
        return result
