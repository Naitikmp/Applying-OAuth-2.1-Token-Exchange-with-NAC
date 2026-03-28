"""
Structured audit logger for NAC demo.

Every security-relevant event — token issuance, exchange, validation, rejection,
tool call, tool block — is written as a JSON line to an append-only log file
AND printed to stdout.

The log is the primary evidence for the identity-confusion measurement:
- Baseline log entries carry sub=alice, act_chain=[] → zero attributability
- Secure log entries carry sub=alice, act_chain=["assistant-hub"] → full attributability
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

# Event type constants
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
    """Clear the log file and jti store at the start of each demo run."""
    try:
        LOG_FILE.write_text("")
    except Exception:
        pass
    # Also clear the jti store file so replay tests are fresh each run
    try:
        from nac_common import _JTI_STORE_PATH
        _JTI_STORE_PATH.write_text("{}")
    except Exception:
        pass


def read_log() -> list[dict[str, Any]]:
    """Return all log entries as parsed dicts."""
    try:
        lines = LOG_FILE.read_text().strip().splitlines()
        return [json.loads(ln) for ln in lines if ln.strip()]
    except Exception:
        return []


def attribution_rate(mode: str) -> float:
    """
    Fraction of TOOL_CALLED log entries that carry a non-empty act_chain
    — i.e. calls that can be attributed to a specific delegating agent.
    """
    entries = [e for e in read_log()
               if e.get("event") == TOKEN_VALIDATED and e.get("mode") == mode]
    if not entries:
        return 0.0
    attributable = sum(1 for e in entries if e.get("attributable", False))
    return attributable / len(entries)