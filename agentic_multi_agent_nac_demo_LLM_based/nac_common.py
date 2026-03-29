"""
Shared NAC crypto and validation helpers.

JTI store
---------
RFC 8693 replay prevention requires every JWT ID (jti) to be tracked across
processes.  This implementation uses Redis — the industry-standard choice for
distributed token revocation.

Redis key layout:
  nac:jti:<jti>  →  "active"   (SET with EX = token TTL + 60 s)
  nac:jti:<jti>  →  "revoked"  (SET with EX = 300 s after first use)

Lifecycle:
  1. OAuth server  → register_jti(jti, exp)  after issuing every token
  2. OAuth server  → revoke_jti(parent_jti)  after parent token is exchanged
  3. Worker server → is_jti_revoked(jti)     before accepting a token
  4. Worker server → revoke_jti(jti)         after accepting (one-time-use)

Connection:
  Default: redis://127.0.0.1:6379/0
  Override: set NAC_REDIS_URL environment variable.

Latency at each call site: ~0.1 ms (co-located Redis, binary protocol).
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
import redis as _redis_lib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# ── constants ────────────────────────────────────────────────────────────────

ISSUER = "https://agentic-nac-demo.local"
ROOT_CLIENT_ID = "assistant-hub"

AUDIENCES: dict[str, str] = {
    "assistant":    "assistant-hub",
    "calendar":     "calendar-service",
    "docs":         "docs-service",
    "comms":        "comms-service",
    "hr":           "hr-service",
    "external-api": "external-api-service",
}

TRUSTED_ACTORS: set[str] = {
    "assistant-hub",
    "calendar-service",
    "docs-service",
    "comms-service",
}

MAX_CHAIN_DEPTH = 10
ROOT_TOKEN_TTL  = 300
CHILD_TOKEN_TTL = 120

RFC8693_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
RFC8693_AT    = "urn:ietf:params:oauth:token-type:access_token"
RFC8693_JWT   = "urn:ietf:params:oauth:token-type:jwt"


# ── key material paths ────────────────────────────────────────────────────────

BASE_DIR         = Path(__file__).resolve().parent
KEY_DIR          = Path(os.getenv("NAC_KEY_DIR", str(BASE_DIR / ".nac_keys")))
PRIVATE_KEY_PATH = KEY_DIR / "signing_private.pem"
PUBLIC_KEY_PATH  = KEY_DIR / "signing_public.pem"

_PUBLIC_ONLY: bool = os.getenv("NAC_PUBLIC_ONLY", "0") == "1"

_private_key = None
_public_key  = None


def _generate_keypair() -> tuple[bytes, bytes]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def ensure_key_material() -> None:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        return
    priv_pem, pub_pem = _generate_keypair()
    PRIVATE_KEY_PATH.write_bytes(priv_pem)
    PUBLIC_KEY_PATH.write_bytes(pub_pem)


def get_public_key():
    global _public_key
    if _public_key is None:
        ensure_key_material()
        _public_key = serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
    return _public_key


def get_signing_key():
    global _private_key
    if _PUBLIC_ONLY:
        raise RuntimeError(
            "NAC_PUBLIC_ONLY=1: this process must not access the signing key. "
            "Only the authorization server issues and exchanges tokens."
        )
    if _private_key is None:
        ensure_key_material()
        _private_key = serialization.load_pem_private_key(
            PRIVATE_KEY_PATH.read_bytes(), password=None
        )
    return _private_key


# ── scope helpers ─────────────────────────────────────────────────────────────

def scope_to_list(value: str | list[str] | None) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [s for s in value if s]
    return [s for s in value.split() if s]


def scope_to_str(value: str | list[str] | None) -> str:
    return " ".join(scope_to_list(value))


# ── Redis JTI store ───────────────────────────────────────────────────────────
#
# Redis is the standard production store for distributed token revocation.
# Each JTI is stored as a Redis key with an automatic expiry so no manual
# cleanup is needed.
#
# Key schema:  nac:jti:<jti>
#   value="active"   TTL=token_lifetime+60s  → registered, not yet spent
#   value="revoked"  TTL=300s                → spent (one-time-use enforced)
#
# is_jti_revoked() returns True only when the value is "revoked".
# An absent key (expired or never registered) returns False — the JWT
# signature check is the primary guard against forged tokens.

_NAC_REDIS_URL  = os.getenv("NAC_REDIS_URL", "redis://127.0.0.1:6379/0")
_JTI_PREFIX     = "nac:jti:"
_JTI_REVOKE_TTL = 300   # seconds to retain revocation records

_redis_client: "_redis_lib.Redis | None" = None


def _get_redis() -> "_redis_lib.Redis":
    global _redis_client
    if _redis_client is None:
        _redis_client = _redis_lib.from_url(
            _NAC_REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
        )
    return _redis_client


# ── JTI public API ────────────────────────────────────────────────────────────

def register_jti(jti: str, exp: float) -> None:
    """Record a freshly issued JTI in Redis with an automatic expiry."""
    ttl = max(1, int(exp - time.time()) + 60)
    _get_redis().set(f"{_JTI_PREFIX}{jti}", "active", ex=ttl)


def revoke_jti(jti: str) -> None:
    """Mark a JTI as spent.  Overwrites any prior value; key expires in 300 s."""
    _get_redis().set(f"{_JTI_PREFIX}{jti}", "revoked", ex=_JTI_REVOKE_TTL)


def is_jti_revoked(jti: str) -> bool:
    """Return True if the JTI has been revoked (value == 'revoked')."""
    return _get_redis().get(f"{_JTI_PREFIX}{jti}") == "revoked"


def clear_jti_store() -> None:
    """Delete all nac:jti:* keys — called at the start of each demo/eval run."""
    r = _get_redis()
    keys = r.keys(f"{_JTI_PREFIX}*")
    if keys:
        r.delete(*keys)


# ── token issuance (auth server only) ────────────────────────────────────────

def issue_root_token(username: str, client_id: str, scopes: list[str]) -> str:
    now = int(time.time())
    jti = str(uuid.uuid4())
    exp = now + ROOT_TOKEN_TTL
    payload = {
        "iss":        ISSUER,
        "sub":        username,
        "aud":        client_id,
        "scope":      scope_to_str(scopes),
        "iat":        now,
        "exp":        exp,
        "jti":        jti,
        "session_id": str(uuid.uuid4()),
    }
    register_jti(jti, float(exp))
    return jwt.encode(payload, get_signing_key(), algorithm="RS256")


def make_child_token(
    parent_token: str,
    new_audience:  str,
    new_scope:     list[str],
    actor:         str,
    ttl_seconds:   int = CHILD_TOKEN_TTL,
) -> tuple[str, str, float]:
    """
    Pure crypto — no file I/O.
    Returns (child_token, child_jti, child_exp).
    Caller registers/revokes jtis via the JTI store.
    """
    parent = jwt.decode(
        parent_token, get_public_key(),
        algorithms=["RS256"],
        options={"verify_aud": False},
    )
    parent_scopes    = set(scope_to_list(parent.get("scope")))
    requested_scopes = set(new_scope)
    escalated        = requested_scopes - parent_scopes
    if escalated:
        raise ValueError(f"scope escalation blocked: {escalated} not in parent token")
    now = int(time.time())
    jti = str(uuid.uuid4())
    exp = float(now + ttl_seconds)
    payload = {
        "iss":        ISSUER,
        "sub":        parent["sub"],
        "aud":        new_audience,
        "scope":      scope_to_str(new_scope),
        "iat":        now,
        "exp":        int(exp),
        "jti":        jti,
        "session_id": parent.get("session_id"),
        "act": {"sub": actor, "act": parent.get("act")},
    }
    child_token = jwt.encode(payload, get_signing_key(), algorithm="RS256")
    return child_token, jti, exp


def exchange_token(
    parent_token: str,
    new_audience:  str,
    new_scope:     list[str],
    actor:         str,
    ttl_seconds:   int = CHILD_TOKEN_TTL,
) -> str:
    """
    RFC 8693-style token exchange — auth server only.

    Enforces:
      1. Scope attenuation  — child scope must be ⊆ parent scope.
      2. Audience binding   — child token valid only on new_audience.
      3. Actor chain nesting — actor prepended to existing act chain.
    """
    parent = jwt.decode(
        parent_token, get_public_key(),
        algorithms=["RS256"],
        options={"verify_aud": False},
    )

    parent_scopes    = set(scope_to_list(parent.get("scope")))
    requested_scopes = set(new_scope)
    escalated        = requested_scopes - parent_scopes
    if escalated:
        raise ValueError(f"scope escalation blocked: {escalated} not in parent token")

    now = int(time.time())
    jti = str(uuid.uuid4())
    exp = now + ttl_seconds

    payload = {
        "iss":        ISSUER,
        "sub":        parent["sub"],
        "aud":        new_audience,
        "scope":      scope_to_str(new_scope),
        "iat":        now,
        "exp":        exp,
        "jti":        jti,
        "session_id": parent.get("session_id"),
        "act": {
            "sub": actor,
            "act": parent.get("act"),
        },
    }
    register_jti(jti, float(exp))
    return jwt.encode(payload, get_signing_key(), algorithm="RS256")


# ── token validation (all processes) ─────────────────────────────────────────

def validate_token(
    token:             str,
    expected_audience: str,
    required_scopes:   list[str],
    trusted_actors:    set[str] | None = None,
    enforce_audience:  bool = True,
    enforce_chain:     bool = False,
    enforce_jti:       bool = False,
) -> dict[str, Any]:
    pub = get_public_key()

    if enforce_audience:
        claims = jwt.decode(token, pub, algorithms=["RS256"], audience=expected_audience)
    else:
        claims = jwt.decode(token, pub, algorithms=["RS256"], options={"verify_aud": False})

    if enforce_jti:
        jti = claims.get("jti", "")
        if jti and is_jti_revoked(jti):
            raise ValueError("token replay detected: jti has been revoked")

    token_scopes = set(scope_to_list(claims.get("scope")))
    missing = [s for s in required_scopes if s not in token_scopes]
    if missing:
        raise ValueError(f"missing required scopes: {', '.join(missing)}")

    if enforce_chain and trusted_actors is not None:
        validate_actor_chain(claims, trusted_actors)

    return claims


def validate_actor_chain(
    claims:         dict[str, Any],
    trusted_actors: set[str] | list[str],
    max_depth:      int = MAX_CHAIN_DEPTH,
) -> None:
    trusted = set(trusted_actors)
    act     = claims.get("act")
    depth   = 0

    while act is not None:
        if depth >= max_depth:
            raise ValueError(
                f"act chain depth exceeds limit ({max_depth}); possible cycle or malformed token"
            )
        actor = act.get("sub")
        if actor and actor not in trusted:
            raise ValueError(f"untrusted actor in delegation chain: {actor!r}")
        act   = act.get("act")
        depth += 1


# ── evaluation helpers ────────────────────────────────────────────────────────

def token_size_bytes(token: str) -> int:
    return len(token.encode())


def chain_depth(token: str) -> int:
    claims = jwt.decode(
        token, get_public_key(),
        algorithms=["RS256"],
        options={"verify_aud": False},
    )
    depth = 0
    act   = claims.get("act")
    while act and depth < MAX_CHAIN_DEPTH + 1:
        depth += 1
        act = act.get("act")
    return depth


def token_preview(token: str) -> dict[str, Any]:
    claims = jwt.decode(
        token, get_public_key(),
        algorithms=["RS256"],
        options={"verify_aud": False},
    )
    return {
        "sub":        claims.get("sub"),
        "aud":        claims.get("aud"),
        "scope":      claims.get("scope"),
        "act":        claims.get("act"),
        "session_id": claims.get("session_id"),
        "jti":        claims.get("jti"),
        "exp":        claims.get("exp"),
        "size_bytes": token_size_bytes(token),
    }


def chain_summary(claims: dict[str, Any]) -> list[str]:
    chain = []
    act   = claims.get("act")
    depth = 0
    while act and depth < MAX_CHAIN_DEPTH:
        if actor := act.get("sub"):
            chain.append(actor)
        act   = act.get("act")
        depth += 1
    return chain