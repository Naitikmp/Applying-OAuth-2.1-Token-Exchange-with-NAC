"""
In-memory JTI (JWT ID) store service — production-equivalent Redis substitute.

Provides a shared cross-process JTI registry via HTTP, eliminating the FileLock
bottleneck of the file-based store. On localhost each operation completes in ~1 ms;
in production this role would be filled by Redis (~0.1 ms).

Why this matters for the paper
-------------------------------
File-based JTI store (FileLock on Windows): ~65 ms per operation.
8 operations per prepare_daily_briefing call (4 × register + 4 × revoke),
ALL serialised through one lock → 8 × 65 ms = ~520 ms added latency.
This is an *implementation* artefact, not a NAC *protocol* cost.

With this in-memory HTTP service:
  - Each operation: ~1 ms (localhost HTTP to in-memory dict)
  - 8 operations, no lock contention: ~2 ms total (truly concurrent)
  - Total secure overhead: ~12 ms RSA + ~2 ms JTI + ~8 ms HTTP = ~22 ms
  - Latency: ~120 ms baseline + ~22 ms NAC = ~142 ms  (+~18%)

In production (co-located Redis, persistent TCP):
  - Each JTI op: ~0.1 ms  →  irreducible minimum ~1-3 ms per hop

JTI lifecycle
-------------
  1. OAuth server  →  POST /register   after issuing a new child token
  2. OAuth server  →  POST /revoke     after parent exchange (one-time parent)
  3. Worker server →  GET  /check/{jti} before accepting a token
  4. Worker server →  POST /revoke     after accepting a token (one-time child)

Port: 9100 (shared by both baseline and secure stacks — baseline ignores JTI,
secure stack uses it).  Configurable via JTI_SERVER_PORT env var.

Usage
-----
Started automatically by run_eval.py, run_solution_demo.py, run_problem_demo.py.
Can also be run standalone:  python jti_server.py
"""

from __future__ import annotations

import os
import threading
import time
from fastapi import FastAPI

JTI_SERVER_PORT: int = int(os.getenv("JTI_SERVER_PORT", "9100"))

# How long to keep revocation records (must outlive the child token TTL).
# CHILD_TOKEN_TTL = 120 s, so 300 s gives 2.5× headroom.
_CLEANUP_HORIZON_S: int = 300


def make_jti_app() -> FastAPI:
    """Return the FastAPI JTI store application (call once per process)."""
    app   = FastAPI(title="NAC JTI Store (in-memory)")
    _store: dict[str, float] = {}   # jti → exp-timestamp OR revocation-timestamp
    _lock  = threading.Lock()       # protects _store across concurrent HTTP requests

    def _cleanup_locked() -> None:
        """Remove stale entries (called under lock — cheap on small dicts)."""
        cutoff = time.time() - _CLEANUP_HORIZON_S
        stale  = [k for k, v in _store.items() if v < cutoff]
        for k in stale:
            del _store[k]

    # ── endpoints ─────────────────────────────────────────────────────────────

    @app.post("/register")
    def register(jti: str, exp: float) -> dict:
        """
        Register a freshly issued JTI.

        exp is the token's Unix expiry timestamp (a future time).
        Stored so that /check/{jti} returns revoked=False until a
        /revoke call overwrites it with the current time.
        """
        with _lock:
            _cleanup_locked()
            _store[jti] = exp       # future → not yet revoked
        return {"ok": True}

    @app.post("/revoke")
    def revoke(jti: str) -> dict:
        """
        Mark a JTI as spent.

        Stores time.time() (a *past or current* value) so that
        /check/{jti} immediately returns revoked=True.

        Key invariant (same as nac_common.py Bug R3 fix):
          - register stores a FUTURE timestamp  (exp > now)  → not revoked
          - revoke  stores a CURRENT timestamp  (≤ now)       → revoked
        The check compares stored_value <= time.time().
        """
        with _lock:
            _store[jti] = time.time()   # current time ≤ any future check → revoked
        return {"ok": True}

    @app.get("/check/{jti}")
    def check(jti: str) -> dict:
        """
        Return {"revoked": bool}.

        Semantics:
          - Unknown JTI → {"revoked": False}  (never registered — let it through;
            the OAuth server is the authoritative issuer)
          - Known JTI, stored_value > now → {"revoked": False}  (still valid)
          - Known JTI, stored_value ≤ now → {"revoked": True}   (spent or expired)
        """
        with _lock:
            if jti not in _store:
                return {"revoked": False}
            return {"revoked": _store[jti] <= time.time()}

    @app.delete("/clear")
    def clear() -> dict:
        """Clear all entries — called at the start of each demo run."""
        with _lock:
            n = len(_store)
            _store.clear()
        return {"ok": True, "cleared": n}

    @app.get("/health")
    def health() -> dict:
        with _lock:
            n = len(_store)
        return {"status": "ok", "service": "jti-store", "entries": n, "port": JTI_SERVER_PORT}

    return app


# ── standalone entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    print(f"[JTI Server] Starting in-memory JTI store on port {JTI_SERVER_PORT}")
    uvicorn.run(make_jti_app(), host="127.0.0.1", port=JTI_SERVER_PORT, log_level="error")