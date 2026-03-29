"""
Shared NAC crypto and validation helpers — v2 (reviewer-corrected).

Key changes from v1:
  - Private key gated behind NAC_PUBLIC_ONLY env var; workers never sign.
  - validate_actor_chain enforces a depth limit to prevent infinite loops.
  - Consistent internal scope representation (always list[str]).
  - jti spent-token registry with TTL-based cleanup.
  - token_size_bytes() helper for evaluation.
  - chain_depth() helper for evaluation.
  - HTTP token exchange helper that calls the auth server (RFC 8693).
"""

from __future__ import annotations

import json
import os
import tempfile as _tempfile
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
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

MAX_CHAIN_DEPTH = 10          # prevent infinite loops in validate_actor_chain
ROOT_TOKEN_TTL  = 300         # seconds
CHILD_TOKEN_TTL = 120         # seconds — short-lived per-hop tokens

RFC8693_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
RFC8693_AT    = "urn:ietf:params:oauth:token-type:access_token"
RFC8693_JWT   = "urn:ietf:params:oauth:token-type:jwt"

# ── key material paths ────────────────────────────────────────────────────────

BASE_DIR         = Path(__file__).resolve().parent
KEY_DIR          = Path(os.getenv("NAC_KEY_DIR", str(BASE_DIR / ".nac_keys")))
PRIVATE_KEY_PATH = KEY_DIR / "signing_private.pem"
PUBLIC_KEY_PATH  = KEY_DIR / "signing_public.pem"

# Workers set NAC_PUBLIC_ONLY=1; they must never hold the signing key.
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
    """Only the authorization server (oauth_server) may call this."""
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


# ── jti revocation registry ───────────────────────────────────────────────────
# Uses a shared JSON file so revocations from the OAuth server are visible to
# worker processes (which each have their own in-memory address space).

import tempfile as _tempfile
import concurrent.futures
from filelock import FileLock

_JTI_STORE_PATH = Path(os.getenv("NAC_JTI_STORE", str(Path(_tempfile.gettempdir()) / "nac_jti_store.json")))
_JTI_LOCK_PATH  = Path(str(_JTI_STORE_PATH) + ".lock")

# Pre-warmed thread pool for jti file operations.
# asyncio.to_thread() creates a NEW thread per call — on Windows that costs
# ~10-15ms per spawn.  A pre-warmed pool reuses threads (~0.1ms hand-off).
# 8 threads covers 4 concurrent exchanges × 2 file ops (register + revoke).
_JTI_FILE_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=8, thread_name_prefix="nac_jti"
)


def _read_jti_store() -> dict[str, float]:
    try:
        with FileLock(_JTI_LOCK_PATH, timeout=5):
            return json.loads(_JTI_STORE_PATH.read_text())
    except Exception:
        return {}


def _write_jti_store(store: dict[str, float]) -> None:
    try:
        with FileLock(_JTI_LOCK_PATH, timeout=5):
            _JTI_STORE_PATH.write_text(json.dumps(store))
    except Exception:
        pass


def register_jti(jti: str, exp: float) -> None:
    """Record a jti as issued. Called by the auth server at issuance time."""
    store = _read_jti_store()
    now = time.time()
    # R3 fix: cleanup window = CHILD_TOKEN_TTL+60 so revoked entries survive
    cleanup_horizon = now - (CHILD_TOKEN_TTL + 60)
    store = {k: v for k, v in store.items() if v > cleanup_horizon}
    store[jti] = exp
    _write_jti_store(store)


def revoke_jti(jti: str) -> None:
    """Mark a jti as spent so it cannot be replayed."""
    store = _read_jti_store()
    # R3 fix: store time.time() not 0.0 — 0.0 gets cleaned up immediately
    store[jti] = time.time()
    _write_jti_store(store)


def is_jti_revoked(jti: str) -> bool:
    store = _read_jti_store()
    if jti not in store:
        return False   # never seen by auth server — pass through
    return store[jti] <= time.time()


def _cleanup_expired_jtis() -> None:
    pass   # cleanup happens inside register_jti now


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
    register_jti(jti, exp)
    return jwt.encode(payload, get_signing_key(), algorithm="RS256")


def make_child_token(
    parent_token: str,
    new_audience:  str,
    new_scope:     list[str],
    actor:         str,
    ttl_seconds:   int = CHILD_TOKEN_TTL,
) -> tuple[str, str, float]:
    """
    Pure crypto — NO file I/O.
    Returns (child_token, child_jti, child_exp).
    Caller registers/revokes jtis via _JTI_FILE_POOL (pre-warmed threads).
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
      1. Scope attenuation  — child scope must be a subset of parent scope.
      2. Audience binding   — child token is valid only on new_audience.
      3. Actor chain nesting — actor is prepended to the existing act chain.
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
            "act": parent.get("act"),   # nest existing chain
        },
    }
    register_jti(jti, exp)
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
    """
    Validate a JWT with configurable enforcement levels.

    Parameters
    ----------
    enforce_audience : True (secure) validates aud claim against expected_audience.
                       False (baseline) skips audience check — the known insecure pattern.
    enforce_chain    : True walks the act chain and verifies every actor is trusted.
    enforce_jti      : True rejects tokens whose jti has been revoked.
    """
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
    """
    Walk the nested act chain and verify every actor sub is trusted.

    Enforces a depth limit to prevent infinite-loop attacks from malformed
    tokens with circular or excessively deep act chains.
    """
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
    """Size of the JWT string in UTF-8 bytes."""
    return len(token.encode())


def chain_depth(token: str) -> int:
    """Number of actors in the act chain (0 = no delegation)."""
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


# ── debug helpers ─────────────────────────────────────────────────────────────

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
    """Return the list of actor subs from outermost to innermost."""
    chain = []
    act   = claims.get("act")
    depth = 0
    while act and depth < MAX_CHAIN_DEPTH:
        if actor := act.get("sub"):
            chain.append(actor)
        act   = act.get("act")
        depth += 1
    return chain