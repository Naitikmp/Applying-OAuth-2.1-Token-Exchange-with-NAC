"""
HTTP-only OAuth server entrypoint for the distributed benchmark.

Wraps make_oauth_app() in a uvicorn runner so it can start in a Docker
container.  The SECURE environment variable selects secure (RFC 8693) vs
baseline (passthrough) mode.

Also exposes a benchmark-only endpoint POST /bench/root_token that
bypasses the browser-based consent flow.  This endpoint exists solely to
bootstrap the distributed benchmark and is clearly namespaced under /bench.
"""
from __future__ import annotations

import os

import uvicorn

from nac_common import ROOT_CLIENT_ID, issue_root_token
from oauth_server import make_oauth_app


SECURE       = os.environ.get("SECURE", "1") == "1"
PORT         = int(os.environ.get("PORT", "9300"))
CALLBACK_URL = os.environ.get("CALLBACK_URL", "http://localhost/callback")


app = make_oauth_app(secure=SECURE, callback_url=CALLBACK_URL)


@app.post("/bench/root_token")
def _bench_root_token() -> dict[str, str]:
    """Benchmark-only: issue a root token for the distributed eval client.

    Bypasses the browser-based authorization code flow because the
    benchmark is not evaluating the user-consent path.  In production,
    root tokens are obtained via the standard OAuth 2.1 flow.
    """
    token = issue_root_token(
        username="alice",
        client_id=ROOT_CLIENT_ID,
        scopes=["calendar:read", "docs:read", "email:send"],
    )
    return {"access_token": token, "token_type": "Bearer"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning")
