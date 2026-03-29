"""
Shared NAC crypto and validation helpers — v3 (latency-corrected).

Key changes from v2:
  - JTI store is now an HTTP-based in-memory service (jti_server.py) when
    NAC_JTI_URL is set.  File-based fallback remains for offline use.
  - JTI functions read NAC_JTI_URL at call time (not import time), so the
    env var can be set after module import — critical for multiprocessing spawn
    where the parent sets NAC_JTI_URL before forking but after importing.
  - Thread-local httpx.Client per thread for JTI ops (safe + persistent TCP).
  - clear_jti_store() resets either backend.
  - _JTI_FILE_POOL kept for backward compat but not used on the hot path
    when a JTI server is configured.

Latency impact
--------------
File-based (v2):  ~65 ms/op × 8 ops serialised by FileLock  = ~520 ms overhead
HTTP JTI server:  ~1 ms/op  × 8 ops concurrent in thread pool = ~2 ms overhead
"""

from __future__ import annotations

import json
import os
import tempfile as _tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import concurrent.futures


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


# ── JTI store — HTTP service or file fallback ─────────────────────────────────
#
# WHY read NAC_JTI_URL at call time (not import time):
#   multiprocessing.spawn forks a fresh Python interpreter.  The child imports
#   nac_common early, but the parent may have set NAC_JTI_URL before spawning.
#   Reading the env var lazily (each call) ensures the child picks it up even
#   though the module-level code ran before os.environ was populated.
#
# Thread-local httpx.Client:
#   httpx.Client is not thread-safe for concurrent access from multiple threads.
#   Using threading.local() gives each thread its own client with its own
#   connection pool — safe and persistent (TCP connections reused within a thread).

_jti_thread_local = threading.local()


def _get_jti_url() -> str:
    """Return the JTI server URL if configured, else empty string."""
    return os.getenv("NAC_JTI_URL", "")


def _get_jti_http_client():
    """Return a thread-local persistent httpx.Client for the JTI server."""
    import httpx as _httpx
    url = _get_jti_url()
    existing_url = getattr(_jti_thread_local, "base_url", None)
    if existing_url != url or not hasattr(_jti_thread_local, "client"):
        _jti_thread_local.base_url = url
        _jti_thread_local.client   = _httpx.Client(
            base_url = url,
            timeout  = 3.0,
        )
    return _jti_thread_local.client


# ── file-based JTI store (fallback when no JTI server) ───────────────────────

_JTI_STORE_PATH = Path(os.getenv("NAC_JTI_STORE", str(Path(_tempfile.gettempdir()) / "nac_jti_store.json")))
_JTI_LOCK_PATH  = Path(str(_JTI_STORE_PATH) + ".lock")

# Pre-warmed thread pool — kept for backward compat and for oauth_server's
# fallback path.  Not used on the hot path when a JTI server is configured.
_JTI_FILE_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=8, thread_name_prefix="nac_jti"
)


def _read_jti_store() -> dict[str, float]:
    try:
        from filelock import FileLock
        with FileLock(_JTI_LOCK_PATH, timeout=5):
            return json.loads(_JTI_STORE_PATH.read_text())
    except Exception:
        return {}


def _write_jti_store(store: dict[str, float]) -> None:
    try:
        from filelock import FileLock
        with FileLock(_JTI_LOCK_PATH, timeout=5):
            _JTI_STORE_PATH.write_text(json.dumps(store))
    except Exception:
        pass


# ── JTI public API ────────────────────────────────────────────────────────────

def register_jti(jti: str, exp: float) -> None:
    """Record a jti as issued.  Uses HTTP JTI server if NAC_JTI_URL is set."""
    url = _get_jti_url()
    if url:
        try:
            _get_jti_http_client().post("/register", params={"jti": jti, "exp": exp})
        except Exception as exc:
            # Non-fatal: fall through to file-based backup
            print(f"[nac_common] JTI server register failed ({exc}); falling back to file store")
            _file_register_jti(jti, exp)
    else:
        _file_register_jti(jti, exp)


def _file_register_jti(jti: str, exp: float) -> None:
    store = _read_jti_store()
    now = time.time()
    cleanup_horizon = now - (CHILD_TOKEN_TTL + 60)
    store = {k: v for k, v in store.items() if v > cleanup_horizon}
    store[jti] = exp
    _write_jti_store(store)


def revoke_jti(jti: str) -> None:
    """Mark a jti as spent.  Uses HTTP JTI server if NAC_JTI_URL is set."""
    url = _get_jti_url()
    if url:
        try:
            _get_jti_http_client().post("/revoke", params={"jti": jti})
        except Exception as exc:
            print(f"[nac_common] JTI server revoke failed ({exc}); falling back to file store")
            _file_revoke_jti(jti)
    else:
        _file_revoke_jti(jti)


def _file_revoke_jti(jti: str) -> None:
    store = _read_jti_store()
    store[jti] = time.time()   # Bug R3 fix: store current time, NOT 0.0
    _write_jti_store(store)


def is_jti_revoked(jti: str) -> bool:
    """Return True if jti has been revoked.  Uses HTTP JTI server if NAC_JTI_URL is set."""
    url = _get_jti_url()
    if url:
        try:
            r = _get_jti_http_client().get(f"/check/{jti}")
            return bool(r.json().get("revoked", False))
        except Exception as exc:
            print(f"[nac_common] JTI server check failed ({exc}); falling back to file store")
    # File-based fallback
    store = _read_jti_store()
    if jti not in store:
        return False
    return store[jti] <= time.time()


def clear_jti_store() -> None:
    """
    Clear all JTI records — called at the start of each demo run.
    Resets whichever backend is active (HTTP server or file).
    """
    url = _get_jti_url()
    if url:
        try:
            _get_jti_http_client().delete("/clear")
            return
        except Exception:
            pass
    # File fallback
    try:
        _JTI_STORE_PATH.write_text("{}")
    except Exception:
        pass


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