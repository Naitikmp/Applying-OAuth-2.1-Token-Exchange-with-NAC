"""
Structured audit logger for the NAC demo.

Writes one JSON line per event to a rotating log file (NAC_LOG_FILE env var).
Also clears the Redis JTI store on clear_log() so replay tests start clean.

Event types: TOKEN_ISSUED, TOKEN_EXCHANGED, TOKEN_VALIDATED, TOKEN_REJECTED,
             TOOL_CALLED, TOOL_BLOCKED, ATTACK_ATTEMPT
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


_default_log = Path(tempfile.gettempdir()) / "nac_audit.log"
LOG_FILE = Path(os.getenv("NAC_LOG_FILE", str(_default_log)))

TOKEN_ISSUED     = "TOKEN_ISSUED"
TOKEN_EXCHANGED  = "TOKEN_EXCHANGED"
TOKEN_VALIDATED  = "TOKEN_VALIDATED"
TOKEN_REJECTED   = "TOKEN_REJECTED"
TOOL_CALLED      = "TOOL_CALLED"
TOOL_BLOCKED     = "TOOL_BLOCKED"
TOOL_RESULT      = "TOOL_RESULT"
ATTACK_ATTEMPT   = "ATTACK_ATTEMPT"


def _write(entry: dict[str, Any]) -> None:
    entry["event_id"] = str(uuid.uuid4())[:8]
    entry["ts"] = round(time.time(), 4)
    line = json.dumps(entry)
    try:
        with LOG_FILE.open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(f"[AUDIT] {line}")


def log_token_issued(sub: str, audience: str, scope: list[str], jti: str, mode: str) -> None:
    _write({
        "event": TOKEN_ISSUED,
        "mode": mode,
        "sub": sub,
        "aud": audience,
        "scope": scope,
        "jti": jti,
    })


def log_token_exchanged(
    parent_sub: str,
    actor: str,
    new_audience: str,
    new_scope: list[str],
    mode: str,
    chain_depth: int,
) -> None:
    _write({
        "event": TOKEN_EXCHANGED,
        "mode": mode,
        "sub": parent_sub,
        "actor": actor,
        "new_aud": new_audience,
        "new_scope": new_scope,
        "chain_depth": chain_depth,
    })


def log_token_validated(
    sub: str,
    audience: str,
    scope: str,
    act_chain: list[str],
    worker: str,
    tool: str,
    mode: str,
) -> None:
    _write({
        "event": TOKEN_VALIDATED,
        "mode": mode,
        "worker": worker,
        "tool": tool,
        "sub": sub,
        "aud": audience,
        "scope": scope,
        "act_chain": act_chain,
        "attributable": len(act_chain) > 0,
    })


def log_token_rejected(
    reason: str,
    error_code: str,
    worker: str,
    tool: str,
    mode: str,
    token_preview: str = "",
) -> None:
    _write({
        "event": TOKEN_REJECTED,
        "mode": mode,
        "worker": worker,
        "tool": tool,
        "error_code": error_code,
        "reason": reason,
        "token_preview": token_preview[:32] if token_preview else "",
    })


def log_tool_called(tool: str, args_keys: list[str], worker: str, mode: str) -> None:
    _write({
        "event": TOOL_CALLED,
        "mode": mode,
        "worker": worker,
        "tool": tool,
        "arg_keys": args_keys,
    })


def log_tool_blocked(tool: str, reason: str, worker: str, mode: str) -> None:
    _write({
        "event": TOOL_BLOCKED,
        "mode": mode,
        "worker": worker,
        "tool": tool,
        "reason": reason,
    })


def log_attack_attempt(attack_type: str, agent: str, target: str, mode: str) -> None:
    _write({
        "event": ATTACK_ATTEMPT,
        "mode": mode,
        "attack_type": attack_type,
        "agent": agent,
        "target": target,
    })


def clear_log() -> None:
    """
    Clear the audit log and JTI store at the start of each demo run.

    Resets the Redis JTI store so replay tests start from a clean state.
    """
    try:
        LOG_FILE.write_text("")
    except Exception:
        pass

    try:
        from nac_common import clear_jti_store
        clear_jti_store()
    except Exception:
        pass


def read_log() -> list[dict[str, Any]]:
    try:
        lines = LOG_FILE.read_text().strip().splitlines()
        return [json.loads(ln) for ln in lines if ln.strip()]
    except Exception:
        return []


def attribution_rate(mode: str) -> float:
    entries = [e for e in read_log()
               if e.get("event") == TOKEN_VALIDATED and e.get("mode") == mode]
    if not entries:
        return 0.0
    attributable = sum(1 for e in entries if e.get("attributable", False))
    return attributable / len(entries)