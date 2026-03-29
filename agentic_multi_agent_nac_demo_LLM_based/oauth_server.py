"""
OAuth 2.1 / RFC 8693 Authorization Server.

JTI operations (register + revoke) call Redis directly via the nac_common
helpers.  Each call takes ~0.1 ms, so no threading or async wrappers are
needed — they run inline in the event loop without meaningful blocking.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

import audit_log
from nac_common import (
    RFC8693_AT, RFC8693_GRANT, RFC8693_JWT,
    ROOT_CLIENT_ID, CHILD_TOKEN_TTL,
    make_child_token,
    get_public_key, get_signing_key, issue_root_token,
    is_jti_revoked, register_jti, revoke_jti, scope_to_list,
)

import jwt as pyjwt


def make_oauth_app(*, secure: bool, callback_url: str) -> FastAPI:
    mode = "secure" if secure else "baseline"
    app  = FastAPI(title=f"{mode.capitalize()} OAuth Server")

    # ── warm up key material at startup ──────────────────────────────────────
    get_public_key()
    if secure:
        get_signing_key()

    pending_codes: dict[str, dict[str, Any]] = {}
    consents:      dict[str, bool]            = {}

    registered_clients = {
        ROOT_CLIENT_ID: {
            "name":          "Assistant Hub",
            "redirect_uris": [callback_url],
        }
    }

    # ── helpers ───────────────────────────────────────────────────────────────

    def consent_key(username: str, client_id: str, redirect_uri: str) -> str:
        return f"{username}::{client_id}::{redirect_uri}" if secure else f"{username}::{client_id}"

    def _check_redirect_uri(client_id: str, redirect_uri: str) -> None:
        if secure and redirect_uri not in registered_clients[client_id]["redirect_uris"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "error":            "invalid_redirect_uri",
                    "registered_uris":  registered_clients[client_id]["redirect_uris"],
                },
            )

    # ── /authorize ────────────────────────────────────────────────────────────

    @app.get("/login/oauth/authorize")
    async def authorize(
        request:       Request,
        client_id:     str,
        redirect_uri:  str,
        scope:         str  = "calendar:read docs:read email:send slack:write",
        state:         str  = "",
        response_type: str  = "code",
    ):
        username = request.headers.get("X-Simulated-User", "alice")

        if client_id not in registered_clients:
            return JSONResponse(status_code=400, content={"error": "unknown_client"})

        _check_redirect_uri(client_id, redirect_uri)

        key = consent_key(username, client_id, redirect_uri)
        consents[key] = True

        print(f"\n[{mode.upper()} OAuth] /authorize  user={username} client={client_id}")

        code = str(uuid.uuid4())
        pending_codes[code] = {
            "username":     username,
            "client_id":    client_id,
            "redirect_uri": redirect_uri,
            "scope":        scope_to_list(scope),
        }

        location = f"{redirect_uri}?code={code}&state={state}"
        return RedirectResponse(url=location, status_code=302)

    # ── /access_token ─────────────────────────────────────────────────────────

    @app.post("/login/oauth/access_token")
    async def exchange_code(request: Request):
        body         = await request.json()
        code         = body.get("code", "")
        client_id    = body.get("client_id", "")
        redirect_uri = body.get("redirect_uri", "")

        pending = pending_codes.pop(code, None)
        if not pending:
            raise HTTPException(400, detail={"error": "invalid_grant", "detail": "code not found or already used"})

        if secure and pending["redirect_uri"] != redirect_uri:
            raise HTTPException(400, detail={"error": "invalid_grant", "detail": "redirect_uri mismatch"})

        token = issue_root_token(
            username  = pending["username"],
            client_id = client_id,
            scopes    = pending["scope"],
        )

        print(f"\n[{mode.upper()} OAuth] Root token issued  sub={pending['username']}  aud={client_id}")
        audit_log.log_token_issued(
            sub      = pending["username"],
            audience = client_id,
            scope    = pending["scope"],
            jti      = pyjwt.decode(token, options={"verify_signature": False}).get("jti", ""),
            mode     = mode,
        )

        return {
            "access_token": token,
            "token_type":   "Bearer",
            "scope":        " ".join(pending["scope"]),
        }

    # ── /token/exchange  (RFC 8693) ───────────────────────────────────────────

    @app.post("/token/exchange")
    async def token_exchange(
        grant_type:           str = Form(...),
        subject_token:        str = Form(...),
        subject_token_type:   str = Form(RFC8693_AT),
        audience:             str = Form(...),
        scope:                str = Form(""),
        actor_token:          str = Form(""),
        actor_token_type:     str = Form(RFC8693_JWT),
        requested_token_type: str = Form(RFC8693_AT),
    ):
        if grant_type != RFC8693_GRANT:
            raise HTTPException(
                status_code=400,
                detail={"error": "unsupported_grant_type", "expected": RFC8693_GRANT},
            )
        if subject_token_type != RFC8693_AT:
            raise HTTPException(status_code=400, detail={"error": "unsupported_subject_token_type"})

        # Baseline: echo parent token unchanged (the insecure passthrough pattern)
        if not secure:
            print(f"\n[BASELINE OAuth] /token/exchange — passthrough (NAC disabled)")
            return {
                "access_token":      subject_token,
                "issued_token_type": RFC8693_AT,
                "token_type":        "Bearer",
            }

        # ── Secure path: RFC 8693 exchange ────────────────────────────────────
        #
        # Step A — RSA sign (~3 ms, synchronous):
        #   make_child_token() decodes + validates + signs the new token.
        #
        # Step B — Redis JTI ops (~0.1 ms each):
        #   register(child_jti): mark new token as active.
        #   revoke(parent_jti):  mark parent as spent (one-time-use).
        #   Both calls are fast enough to run inline without threading.

        new_scope = scope_to_list(scope)
        actor     = actor_token if actor_token else "unknown-actor"

        # Step A: crypto
        try:
            child, child_jti, child_exp = make_child_token(
                parent_token = subject_token,
                new_audience = audience,
                new_scope    = new_scope,
                actor        = actor,
                ttl_seconds  = CHILD_TOKEN_TTL,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"error": "invalid_grant", "detail": str(exc)})
        except Exception as exc:
            raise HTTPException(status_code=500, detail={"error": "server_error", "detail": str(exc)})

        # Step B: Redis JTI ops (inline — ~0.1 ms each)
        parent_claims = pyjwt.decode(subject_token, options={"verify_signature": False})
        parent_jti    = parent_claims.get("jti", "")

        register_jti(child_jti, child_exp)
        if parent_jti:
            revoke_jti(parent_jti)

        print(
            f"\n[SECURE OAuth] /token/exchange  actor={actor}  "
            f"new_aud={audience}  scope={new_scope}"
        )
        audit_log.log_token_exchanged(
            parent_sub   = parent_claims.get("sub", ""),
            actor        = actor,
            new_audience = audience,
            new_scope    = new_scope,
            mode         = mode,
            chain_depth  = len(new_scope),
        )

        return {
            "access_token":      child,
            "issued_token_type": RFC8693_AT,
            "token_type":        "Bearer",
            "expires_in":        CHILD_TOKEN_TTL,
            "scope":             " ".join(new_scope),
        }

    # ── debug / inspection endpoints ──────────────────────────────────────────

    @app.get("/jwks")
    def jwks():
        from cryptography.hazmat.primitives import serialization as _ser
        pem = get_public_key().public_bytes(
            _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return {"key_type": "RSA", "algorithm": "RS256", "public_key_pem": pem}

    @app.get("/consent-store")
    def consent_store():
        return {"consent_store": consents, "registered_clients": list(registered_clients.keys())}

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "server": "oauth",
            "secure": secure,
            "jti_backend": "redis",
            "jti_url": os.getenv("NAC_REDIS_URL", "redis://127.0.0.1:6379/0"),
        }

    return app