"""
OAuth 2.1 / RFC 8693 Authorization Server.

Changes from v1:
  - /token/exchange is now a proper RFC 8693 endpoint (application/x-www-form-urlencoded).
  - grant_type must be the full URN.
  - subject_token_type and issued_token_type are validated and returned.
  - jti revocation list: every issued jti is registered; token exchange revokes the
    parent jti after a successful exchange (one-time-use child tokens).
  - Structured audit logging on every event.
  - /jwks endpoint returns the public key for external verifiers.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

import audit_log
from nac_common import (
    RFC8693_AT, RFC8693_GRANT, RFC8693_JWT,
    ROOT_CLIENT_ID, CHILD_TOKEN_TTL,
    make_child_token, _JTI_FILE_POOL,
    get_public_key, get_signing_key, issue_root_token,
    is_jti_revoked, register_jti, revoke_jti, scope_to_list,
)

import jwt as pyjwt


def make_oauth_app(*, secure: bool, callback_url: str) -> FastAPI:
    mode = "secure" if secure else "baseline"
    app  = FastAPI(title=f"{mode.capitalize()} OAuth Server")

    # Pre-warm keys and prime the thread pool so first request pays no cold cost.
    get_public_key()
    if secure:
        get_signing_key()
    # Submit a dummy no-op to each thread in the pool so all 8 threads are
    # alive before any real requests arrive.  Thread creation on Windows
    # costs ~10-15ms; priming here means every exchange call reuses a live thread.
    for _ in range(8):
        _JTI_FILE_POOL.submit(lambda: None)

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
        # Secure: redirect URI is part of the key (prevents open-redirect consent theft)
        # Baseline: only username + client_id (vulnerable to redirect URI substitution)
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

        key     = consent_key(username, client_id, redirect_uri)
        consented = consents.get(key, False)

        print(f"\n[{mode.upper()} OAuth] /authorize  user={username} client={client_id} consent={'yes' if consented else 'first-time'}")

        consents[key] = True

        code = str(uuid.uuid4())
        pending_codes[code] = {
            "username":     username,
            "client_id":    client_id,
            "redirect_uri": redirect_uri,
            "scope":        scope_to_list(scope),
        }

        location = f"{redirect_uri}?code={code}&state={state}"
        print(f"  → redirecting to {location}")
        return RedirectResponse(url=location, status_code=302)

    # ── /access_token ─────────────────────────────────────────────────────────

    @app.post("/login/oauth/access_token")
    async def exchange_code(request: Request):
        body        = await request.json()
        code        = body.get("code", "")
        client_id   = body.get("client_id", "")
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
        grant_type:         str = Form(...),
        subject_token:      str = Form(...),
        subject_token_type: str = Form(RFC8693_AT),
        audience:           str = Form(...),
        scope:              str = Form(""),
        actor_token:        str = Form(""),
        actor_token_type:   str = Form(RFC8693_JWT),
        requested_token_type: str = Form(RFC8693_AT),
    ):
        # RFC 8693 §2.1 — grant_type MUST be the token-exchange URN
        if grant_type != RFC8693_GRANT:
            raise HTTPException(
                status_code=400,
                detail={"error": "unsupported_grant_type", "expected": RFC8693_GRANT},
            )
        if subject_token_type != RFC8693_AT:
            raise HTTPException(
                status_code=400,
                detail={"error": "unsupported_subject_token_type"},
            )

        # Baseline path: just echo the parent token back (the broken pattern)
        if not secure:
            print(f"\n[BASELINE OAuth] /token/exchange — passthrough (NAC disabled)")
            return {
                "access_token":      subject_token,
                "issued_token_type": RFC8693_AT,
                "token_type":        "Bearer",
            }

        # Secure path: RFC 8693 exchange — truly async so 4 concurrent
        # requests from asyncio.gather interleave in the event loop.
        #
        # Step A — pure crypto, synchronous in event loop (~3ms, fast):
        # make_child_token() does JWT decode + scope check + RSA sign.
        # No file I/O here so event loop is NOT blocked between requests.
        #
        # Step B — file ops via PRE-WARMED pool (~0.1ms hand-off, not ~15ms spawn):
        # loop.run_in_executor(_JTI_FILE_POOL, ...) hands work to a live thread.
        # asyncio.gather runs register + revoke simultaneously per request.
        # 4 concurrent requests' file ops overlap in the 8-thread pool.
        new_scope = scope_to_list(scope)
        actor     = actor_token if actor_token else "unknown-actor"

        # Step A: crypto only, ~3ms, event loop stays free after this
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

        # Step B: file ops via pre-warmed pool — no thread-spawn overhead
        parent_claims = pyjwt.decode(subject_token, options={"verify_signature": False})
        parent_jti    = parent_claims.get("jti", "")
        loop          = asyncio.get_event_loop()
        file_tasks    = [loop.run_in_executor(_JTI_FILE_POOL, register_jti, child_jti, child_exp)]
        if parent_jti:
            file_tasks.append(loop.run_in_executor(_JTI_FILE_POOL, revoke_jti, parent_jti))
        await asyncio.gather(*file_tasks)

        print(
            f"\n[SECURE OAuth] /token/exchange  actor={actor}  "
            f"new_aud={audience}  scope={new_scope}"
        )
        audit_log.log_token_exchanged(
            parent_sub  = parent_claims.get("sub", ""),
            actor       = actor,
            new_audience = audience,
            new_scope    = new_scope,
            mode         = mode,
            chain_depth  = len(new_scope),   # proxy; real depth from chain_depth()
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
        """Public key in JWK-like format for external verifiers."""
        pub_pem = get_public_key().public_bytes(
            encoding=None.__class__.__mro__[0],   # type: ignore[arg-type] — handled below
            format=None.__class__.__mro__[0],      # type: ignore[arg-type]
        ) if False else None
        # Simpler: return PEM as string (real impl would return JWK Set)
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
        return {"status": "ok", "server": "oauth", "secure": secure}

    return app