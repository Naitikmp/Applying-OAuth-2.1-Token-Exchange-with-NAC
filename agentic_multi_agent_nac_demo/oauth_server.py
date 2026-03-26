"""OAuth server used by both the problem and the NAC solution demos."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from nac_common import ROOT_CLIENT_ID, exchange_token, issue_root_token


def make_oauth_app(*, secure: bool, callback_url: str) -> FastAPI:
    app = FastAPI(title=("Secure" if secure else "Baseline") + " OAuth Server")

    pending_codes: dict[str, dict[str, Any]] = {}
    consents: dict[str, bool] = {}

    registered_clients = {
        ROOT_CLIENT_ID: {
            "name": "Assistant Hub",
            "redirect_uris": [callback_url],
        }
    }

    def consent_key(username: str, client_id: str, redirect_uri: str) -> str:
        if secure:
            return f"{username}::{client_id}::{redirect_uri}"
        return f"{username}::{client_id}"

    @app.get("/login/oauth/authorize")
    async def authorize(
        request: Request,
        client_id: str,
        redirect_uri: str,
        scope: str = "calendar:read docs:read email:send slack:write",
        state: str = "",
        response_type: str = "code",
    ):
        username = request.headers.get("X-Simulated-User", "alice")

        if client_id not in registered_clients:
            return JSONResponse(status_code=400, content={"error": "unknown_client"})

        if secure and redirect_uri not in registered_clients[client_id]["redirect_uris"]:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_redirect_uri",
                    "detail": "redirect_uri must match a registered URI",
                    "registered_uris": registered_clients[client_id]["redirect_uris"],
                },
            )

        key = consent_key(username, client_id, redirect_uri)
        has_consent = consents.get(key, False)

        print(f"\n[{ 'Secure' if secure else 'Baseline' } OAuth] Authorization request")
        print(f"  User        : {username}")
        print(f"  client_id   : {client_id}")
        print(f"  redirect_uri: {redirect_uri}")
        print(f"  Consent     : {has_consent}")

        if not has_consent:
            consents[key] = True
            print("  Showing consent screen once, then storing consent.")
        else:
            print("  Consent already present — skipping consent screen.")

        code = str(uuid.uuid4())
        pending_codes[code] = {
            "username": username,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope.split(),
        }

        redirect_url = f"{redirect_uri}?code={code}&state={state}"
        print(f"  Redirecting to: {redirect_url}")
        return RedirectResponse(url=redirect_url, status_code=302)

    @app.post("/login/oauth/access_token")
    async def exchange_code(request: Request):
        body = await request.json()
        code = body.get("code")
        client_id = body.get("client_id")
        redirect_uri = body.get("redirect_uri")

        pending = pending_codes.pop(code, None)
        if not pending:
            raise HTTPException(400, "invalid_grant: code not found or already used")

        if secure and pending["redirect_uri"] != redirect_uri:
            raise HTTPException(400, "invalid_grant: redirect_uri mismatch")

        # ✅ FIX: correct signature
        token = issue_root_token(
            username=pending["username"],
            client_id=client_id,
            scopes=pending["scope"],
        )

        print(f"\n[{ 'Secure' if secure else 'Baseline' } OAuth] Token issued for '{pending['username']}' → client '{client_id}'")

        return {
            "access_token": token,
            "token_type": "Bearer",
            "scope": " ".join(pending["scope"]),
        }

    @app.post("/token/exchange")
    async def token_exchange(request: Request):
        body = await request.json()

        token = body.get("token", "")
        actor_sub = body.get("actor_sub", "unknown-actor")
        audience = body.get("audience", "")
        scope = body.get("scope", [])

        if not secure:
            return {"access_token": token, "token_type": "Bearer"}

        try:
            # ✅ FIX: correct signature mapping
            child = exchange_token(
                parent_token=token,
                new_audience=audience,
                new_scope=scope,
                actor=actor_sub,
            )
        except Exception as e:
            raise HTTPException(400, f"token exchange failed: {e}")

        print(f"\n[Secure OAuth] Token exchanged → actor '{actor_sub}' | aud '{audience}'")

        return {"access_token": child, "token_type": "Bearer"}

    @app.get("/consent-store")
    def consent_store():
        return {"consent_store": consents, "registered_clients": list(registered_clients.keys())}

    @app.get("/health")
    def health():
        return {"status": "ok", "server": "oauth", "secure": secure}

    return app