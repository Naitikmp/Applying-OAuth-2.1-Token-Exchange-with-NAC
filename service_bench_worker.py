"""
HTTP-only benchmark worker for the distributed evaluation.

Exposes a single POST /call endpoint that:
  1. Extracts the Bearer token from the Authorization header
  2. Runs the real validate_token() (audience, scope, act-chain, atomic JTI)
  3. Returns 200 OK on success or 403 with an error_code on failure

Used by run_distributed_real.py against a docker-compose deployment to measure
genuine cross-container NAC overhead.  No MCP/SSE layer — this isolates the
NAC security-check cost from MCP transport semantics.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Header, HTTPException

from nac_common import AUDIENCES, TRUSTED_ACTORS, validate_token


WORKER_NAME = os.environ["WORKER_NAME"]        # e.g. "calendar", "docs"
REQUIRED    = os.environ.get("REQUIRED_SCOPES", "").split()
SECURE      = os.environ.get("SECURE", "1") == "1"


app = FastAPI(title=f"bench-worker-{WORKER_NAME}")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "worker": WORKER_NAME}


@app.post("/call")
def call(authorization: str | None = Header(default=None)) -> dict[str, str]:
    if authorization is None or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="TOKEN_MISSING")
    token = authorization[7:].strip()

    if not SECURE:
        # Baseline: no validation, just accept
        return {"worker": WORKER_NAME, "status": "ok (baseline)"}

    try:
        claims = validate_token(
            token,
            expected_audience=AUDIENCES[WORKER_NAME],
            required_scopes=REQUIRED,
            trusted_actors=TRUSTED_ACTORS,
            enforce_audience=True,
            enforce_chain=True,
            enforce_jti=True,
        )
    except ValueError as exc:
        err = str(exc)
        code = "TOKEN_REPLAY" if "TOKEN_REPLAY" in err \
               else "SCOPE_INSUFFICIENT" if "missing" in err \
               else "VALIDATION_FAILED"
        raise HTTPException(status_code=403, detail=code)
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"INVALID_TOKEN: {exc}")

    return {"worker": WORKER_NAME, "sub": claims.get("sub", "?"),
            "aud": claims.get("aud", "?")}
