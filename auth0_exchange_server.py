"""
Auth0-backed RFC 8693 token exchange sidecar.

Architecture
------------
Auth0 Token Vault (native RFC 8693) is an Enterprise-tier feature.  This
sidecar implements the same RFC 8693 exchange semantics for Auth0 free/standard
tenants — the "deploy a lightweight exchange sidecar" path described in the
paper's Practical Adoption Checklist (§ V.D).

Token flow
----------

  Auth0 M2M token T₀ (RS256, signed by Auth0, aud=hub-audience)
       │
       │  POST /token/exchange   subject_token=T₀
       ▼
  [this server]
    1. Validate T₀ against Auth0's JWKS endpoint
    2. Enforce scope attenuation (child scope ⊆ parent scope)
    3. Issue NAC child token T₁ (RS256, signed by our key)
    4. Register T₁'s JTI in Redis; revoke T₀'s JTI (one-time-use)
       │
       ▼
  Worker service
    ── validates T₁ against /jwks (our public key)
    ── enforces aud, scope, act chain, JTI (nac_common.validate_token)

For chained exchanges (hub's T₁ → worker's T₂), the subject_token is already
issued by us so it is validated against our local public key instead.

Endpoints
---------
  POST /token/exchange   RFC 8693 grant
  GET  /jwks             Our RSA public key (PEM, for workers)
  GET  /health           Liveness probe
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any

import datetime

import jwt
from fastapi import FastAPI, Form, HTTPException

import audit_log

# Clock skew tolerance for Auth0 token validation.
# Auth0's servers may be up to this many seconds ahead of the local clock.
# 30 s is the industry-standard leeway (RFC 7519 §4.1.6 recommends "a few minutes").
# This does NOT weaken security: exp and nbf are still strictly enforced within
# the leeway window; only iat validation is relaxed by this amount.
_AUTH0_CLOCK_SKEW = datetime.timedelta(seconds=30)
from nac_common import (
    ISSUER, CHILD_TOKEN_TTL,
    RFC8693_AT, RFC8693_GRANT, RFC8693_JWT,
    get_signing_key, get_public_key,
    register_jti, revoke_jti,
    scope_to_list, scope_to_str,
)
from auth0_config import AUTH0_DOMAIN, AUTH0_HUB_AUDIENCE


# ── Auth0 JWKS client ─────────────────────────────────────────────────────────
#
# PyJWKClient (PyJWT ≥ 2.4) fetches and caches Auth0's public keys automatically.
# The cache is refreshed when Auth0 rotates its signing keys.

_auth0_jwks_client: "jwt.PyJWKClient | None" = None


def _get_auth0_jwks_client() -> "jwt.PyJWKClient":
    """Return (or create) the cached Auth0 JWKS client."""
    global _auth0_jwks_client
    if _auth0_jwks_client is None:
        if not AUTH0_DOMAIN:
            raise RuntimeError(
                "AUTH0_DOMAIN is not configured.  "
                "Set it via the AUTH0_DOMAIN environment variable."
            )
        _auth0_jwks_client = jwt.PyJWKClient(
            f"https://{AUTH0_DOMAIN}/.well-known/jwks.json",
            cache_keys=True,
        )
    return _auth0_jwks_client


# ── subject-token validation ──────────────────────────────────────────────────

def _validate_subject_token(token: str) -> dict[str, Any]:
    """
    Validate an incoming subject_token using the correct key.

    Decision is made from the unverified ``iss`` claim:
    - iss == "https://<AUTH0_DOMAIN>/"  → Auth0 JWKS (real IdP)
    - iss == ISSUER                     → our local RSA public key (chained exchange)

    Returns the verified claims dict.
    Raises jwt.exceptions.PyJWTError on any validation failure.
    """
    # Peek at issuer without cryptographic verification
    unverified: dict[str, Any] = jwt.decode(
        token, options={"verify_signature": False}
    )
    issuer: str = unverified.get("iss", "")
    auth0_issuer = f"https://{AUTH0_DOMAIN}/"

    if issuer == auth0_issuer:
        # ── path A: root token from Auth0 ────────────────────────────────────
        # leeway absorbs clock skew between Auth0's servers and local machine.
        # Auth0 M2M tokens carry iat=<Auth0 server time>; if Auth0's clock is
        # slightly ahead, PyJWT raises ImmatureSignatureError without leeway.
        jwks_client = _get_auth0_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=AUTH0_HUB_AUDIENCE,
            leeway=_AUTH0_CLOCK_SKEW,
        )
        return claims

    elif issuer == ISSUER:
        # ── path B: chained child token (already issued by us) ───────────────
        claims = jwt.decode(
            token,
            get_public_key(),
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
        return claims

    else:
        raise jwt.exceptions.InvalidIssuerError(
            f"Untrusted token issuer: {issuer!r}. "
            f"Expected {auth0_issuer!r} or {ISSUER!r}."
        )


# ── child token issuance from pre-validated claims ────────────────────────────

def _issue_child_from_claims(
    parent_claims: dict[str, Any],
    new_audience:  str,
    new_scope:     list[str],
    actor:         str,
    ttl_seconds:   int = CHILD_TOKEN_TTL,
) -> tuple[str, str, float]:
    """
    Issue a NAC child token from already-validated parent claims.

    This function is used instead of nac_common.make_child_token() when the
    parent token is an Auth0 JWT (signed by Auth0's key, not ours).

    Enforces scope attenuation: new_scope must be a subset of parent scope.
    Carries the Auth0 ``azp`` (authorized party) claim into the act chain so
    the originating Auth0 client is always visible in the delegation record.

    Returns (child_token_str, child_jti, child_exp_float).
    Raises ValueError if scope escalation is attempted.
    """
    parent_scopes    = set(scope_to_list(parent_claims.get("scope", "")))
    requested_scopes = set(new_scope)
    escalated        = requested_scopes - parent_scopes
    if escalated:
        raise ValueError(
            f"SCOPE_ESCALATION_BLOCKED: {sorted(escalated)} "
            f"not present in parent token scopes {sorted(parent_scopes)}"
        )

    now = int(time.time())
    jti = str(uuid.uuid4())
    exp = float(now + ttl_seconds)

    # auth0_client records which Auth0 M2M application originated this session.
    # It appears as "auth0_client" inside the act claim for full audit visibility.
    auth0_client = parent_claims.get("azp") or parent_claims.get("client_id")

    act_claim: dict[str, Any] = {"sub": actor, "act": parent_claims.get("act")}
    if auth0_client:
        act_claim["auth0_client"] = auth0_client

    payload: dict[str, Any] = {
        "iss":        ISSUER,
        "sub":        parent_claims["sub"],
        "aud":        new_audience,
        "scope":      scope_to_str(new_scope),
        "iat":        now,
        "exp":        int(exp),
        "jti":        jti,
        # session_id: prefer Auth0 token's jti (stable session anchor), else generate one
        "session_id": parent_claims.get("jti") or str(uuid.uuid4()),
        "act":        act_claim,
    }
    child_token = jwt.encode(payload, get_signing_key(), algorithm="RS256")
    return child_token, jti, exp


# ── FastAPI application ───────────────────────────────────────────────────────

def make_auth0_exchange_app() -> FastAPI:
    """Build and return the Auth0-backed exchange sidecar ASGI application."""

    app = FastAPI(title="Auth0-backed RFC 8693 Token Exchange Sidecar")

    # Warm up key material at startup — fail fast if keys are missing
    get_signing_key()
    get_public_key()

    # ── POST /token/exchange ──────────────────────────────────────────────────

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
        """
        RFC 8693 token exchange endpoint.

        Accepts both Auth0 root tokens (T₀) and our own child tokens (for
        chained exchanges).  Validates cryptographic signature, enforces scope
        attenuation, issues a new child token, and records JTI operations in Redis.
        """
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

        # ── Step 1: validate incoming token against Auth0 JWKS or our key ────
        try:
            parent_claims = _validate_subject_token(subject_token)
        except jwt.exceptions.PyJWTError as exc:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_subject_token", "detail": str(exc)},
            )
        except RuntimeError as exc:
            raise HTTPException(
                status_code=500,
                detail={"error": "configuration_error", "detail": str(exc)},
            )

        new_scope = scope_to_list(scope)
        actor     = actor_token if actor_token else "assistant-hub"

        # ── Step 2: issue child token (scope attenuation enforced inside) ─────
        try:
            child, child_jti, child_exp = _issue_child_from_claims(
                parent_claims = parent_claims,
                new_audience  = audience,
                new_scope     = new_scope,
                actor         = actor,
                ttl_seconds   = CHILD_TOKEN_TTL,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_grant", "detail": str(exc)},
            )

        # ── Step 3: Redis JTI tracking (register child, revoke parent) ────────
        register_jti(child_jti, child_exp)
        parent_jti = parent_claims.get("jti")
        if parent_jti:
            revoke_jti(parent_jti)  # one-time-use: parent is spent after exchange

        issuer_type = (
            "auth0"
            if parent_claims.get("iss", "").startswith(f"https://{AUTH0_DOMAIN}")
            else "internal"
        )

        print(
            f"\n[Auth0 Sidecar] /token/exchange"
            f"  issuer={issuer_type}"
            f"  sub={parent_claims.get('sub', '')}"
            f"  actor={actor}"
            f"  new_aud={audience}"
            f"  scope={new_scope}"
        )
        audit_log.log_token_exchanged(
            parent_sub   = parent_claims.get("sub", ""),
            actor        = actor,
            new_audience = audience,
            new_scope    = new_scope,
            mode         = f"auth0_sidecar/{issuer_type}",
            chain_depth  = len(new_scope),  # placeholder — chain depth not tracked here
        )

        return {
            "access_token":      child,
            "issued_token_type": RFC8693_AT,
            "token_type":        "Bearer",
            "expires_in":        CHILD_TOKEN_TTL,
            "scope":             " ".join(new_scope),
        }

    # ── GET /jwks ─────────────────────────────────────────────────────────────

    @app.get("/jwks")
    def jwks():
        """
        Expose our RSA public key so workers can verify child tokens.

        Workers call this at startup (or cache it) and use it as the
        ``verify_key`` parameter in nac_common.validate_token().
        """
        from cryptography.hazmat.primitives import serialization as _ser
        pem = get_public_key().public_bytes(
            _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return {"key_type": "RSA", "algorithm": "RS256", "public_key_pem": pem}

    # ── GET /health ───────────────────────────────────────────────────────────

    @app.get("/health")
    def health():
        """Liveness probe used by run_auth0_demo.py startup wait loop."""
        return {
            "status":         "ok",
            "server":         "auth0-exchange-sidecar",
            "auth0_domain":   AUTH0_DOMAIN or "(not configured)",
            "auth0_audience": AUTH0_HUB_AUDIENCE,
            "jti_backend":    "redis",
            "jti_url":        os.getenv("NAC_REDIS_URL", "redis://127.0.0.1:6379/0"),
        }

    return app
