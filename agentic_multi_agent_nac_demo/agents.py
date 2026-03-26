"""Simple agent layer used by both the problem and the solution demos."""

from __future__ import annotations

import json
from dataclasses import dataclass
from time import perf_counter

from mcp.client.session import ClientSession
from mcp.client.sse import sse_client


@dataclass
class AgentPlan:
    intent: str
    tool_calls: list[tuple[str, dict]]


class SimpleLLMPlanner:
    """Tiny rule-based planner that stands in for an LLM agent."""

    def plan(self, user_prompt: str) -> AgentPlan:
        text = user_prompt.lower().strip()
        tool_calls: list[tuple[str, dict]] = []

        if any(k in text for k in ["connect", "workspace", "login", "email", "calendar"]):
            tool_calls.append(("connect_workspace", {"username": "alice"}))

        if any(k in text for k in ["brief", "summary", "meeting", "today", "team"]):
            tool_calls.append(("prepare_daily_briefing", {"username": "alice"}))

        if any(k in text for k in ["hr", "payroll", "confidential", "secret"]):
            tool_calls.append(("attempt_unauthorized_hr_read", {"username": "alice"}))

        if not tool_calls:
            tool_calls.append(("inspect_session", {"username": "alice"}))

        return AgentPlan(intent=user_prompt, tool_calls=tool_calls)


class AssistantAgent:
    def __init__(self, server_url: str):
        self.server_url = server_url
        self.sse_url = f"{server_url}/sse"
        self.planner = SimpleLLMPlanner()

    async def _run(self, task_fn):
        async with sse_client(self.sse_url) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                print(f"[Agent] Connected to '{init.serverInfo.name}' (protocol {init.protocolVersion})")
                await task_fn(session)

    async def list_tools(self):
        async def _task(session: ClientSession):
            result = await session.list_tools()
            print("\n[Agent] Available tools:")
            for tool in result.tools:
                print(f"  • {tool.name}: {tool.description}")
        await self._run(_task)

    async def execute_prompt(self, user_prompt: str):
        plan = self.planner.plan(user_prompt)
        print(f"\n[Agent] User prompt: {plan.intent}")
        print("[Agent] Plan:")
        for tool_name, args in plan.tool_calls:
            print(f"  → {tool_name} {args}")

        async def _task(session: ClientSession):
            for tool_name, args in plan.tool_calls:
                result = await session.call_tool(tool_name, args)
                print(f"\n[Agent] Tool result: {tool_name}")
                print(result.content[0].text)

        await self._run(_task)

    async def measure_briefing(self, rounds: int = 3):
        durations = []
        async def _task(session: ClientSession):
            for _ in range(rounds):
                t0 = perf_counter()
                await session.call_tool("prepare_daily_briefing", {"username": "alice"})
                durations.append(perf_counter() - t0)
        await self._run(_task)
        avg = sum(durations) / len(durations)
        print(f"\n[Agent] avg call time: {avg:.4f}s")
        print(f"[Agent] min/max      : {min(durations):.4f}s / {max(durations):.4f}s")


class AttackerAgent:
    """A malicious or mis-scoped agent trying to do a task it should not do."""

    def __init__(self, server_url: str):
        self.server_url = server_url
        self.sse_url = f"{server_url}/sse"

    async def try_hr_access(self):
        async with sse_client(self.sse_url) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                print(f"[Attacker] Connected to '{init.serverInfo.name}'")
                result = await session.call_tool("attempt_unauthorized_hr_read", {"username": "alice"})
                print("\n[Attacker] HR access attempt result:")
                print(result.content[0].text)
