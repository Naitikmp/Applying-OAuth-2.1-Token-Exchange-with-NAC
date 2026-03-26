"""
Shared NAC crypto and validation helpers.

This module is used by:
- oauth_server.py
- assistant_server.py
- worker_servers.py

Design goals:
- one shared signing keypair for all processes
- simple token issuance and token exchange
- audience binding
- scope attenuation
- nested actor-chain validation
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


ISSUER = "https://agentic-nac-demo.local"

ROOT_CLIENT_ID = "assistant-hub"

AUDIENCES = {
    "assistant": "assistant-hub",
    "calendar": "calendar-service",
    "docs": "docs-service",
    "comms": "comms-service",
    "hr": "hr-service",
}

TRUSTED_ACTORS = {
    "assistant-hub",
    "calendar-service",
    "docs-service",
    "comms-service",
}   

BASE_DIR = Path(__file__).resolve().parent
KEY_DIR = Path(os.getenv("NAC_KEY_DIR", str(BASE_DIR / ".nac_keys")))
PRIVATE_KEY_PATH = KEY_DIR / "signing_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "signing_public.pem"


def _generate_keypair() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def ensure_key_material() -> None:
    """
    Create a shared signing keypair once if it does not already exist.

    Every process loads the same files, so the JWT signature stays valid
    across the OAuth server, assistant, and worker servers.
    """
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        return

    private_pem, public_pem = _generate_keypair()

    PRIVATE_KEY_PATH.write_bytes(private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)


def _load_private_key():
    ensure_key_material()
    return serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)


def _load_public_key():
    ensure_key_material()
    return serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())


PRIVATE_KEY = _load_private_key()
PUBLIC_KEY = _load_public_key()


def _scope_list(scope_value: str | list[str] | None) -> list[str]:
    if not scope_value:
        return []
    if isinstance(scope_value, list):
        return [s for s in scope_value if s]
    return [s for s in scope_value.split() if s]


def token_preview(token: str) -> dict[str, Any]:
    """
    Decode a token without audience verification, useful for debug output.
    """
    claims = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], options={"verify_aud": False})
    return {
        "sub": claims.get("sub"),
        "aud": claims.get("aud"),
        "scope": claims.get("scope"),
        "act": claims.get("act"),
        "session_id": claims.get("session_id"),
        "exp": claims.get("exp"),
    }


def issue_root_token(username: str, client_id: str, scopes: list[str]) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": username,
        "aud": client_id,
        "scope": " ".join(scopes),
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")


def exchange_token(
    parent_token: str,
    new_audience: str,
    new_scope: list[str],
    actor: str,
    ttl_seconds: int = 120,
) -> str:
    """
    Token exchange with scope attenuation and nested actor claims.
    """
    parent = jwt.decode(parent_token, PUBLIC_KEY, algorithms=["RS256"], options={"verify_aud": False})

    parent_scopes = set(_scope_list(parent.get("scope")))
    requested_scopes = set(new_scope)

    if not requested_scopes.issubset(parent_scopes):
        raise ValueError("scope escalation detected")

    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": parent["sub"],
        "aud": new_audience,
        "scope": " ".join(new_scope),
        "iat": now,
        "exp": now + ttl_seconds,
        "session_id": parent.get("session_id"),
        "act": {
            "sub": actor,
            "act": parent.get("act"),
        },
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")


def validate_token(token: str, expected_aud: str, required_scopes: list[str]) -> dict[str, Any]:
    claims = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], audience=expected_aud)

    token_scopes = set(_scope_list(claims.get("scope")))
    missing = [scope for scope in required_scopes if scope not in token_scopes]
    if missing:
        raise ValueError(f"missing required scopes: {', '.join(missing)}")

    return claims


def validate_actor_chain(claims: dict[str, Any], trusted_actors: set[str] | list[str]) -> None:
    trusted = set(trusted_actors)
    act = claims.get("act")

    while act:
        actor = act.get("sub")
        if actor and actor not in trusted:
            raise ValueError(f"untrusted actor in chain: {actor}")
        act = act.get("act")


def validate_resource_token(
    token: str,
    expected_aud: str,
    required_scopes: list[str],
    trusted_actors: set[str] | list[str],
) -> dict[str, Any]:
    claims = validate_token(token, expected_aud=expected_aud, required_scopes=required_scopes)
    validate_actor_chain(claims, trusted_actors=trusted_actors)
    return claims

# ============================================================
# 🔍 DEBUG / VISUALIZATION HELPERS
# ============================================================

def chain_summary(claims: dict) -> list[str]:
    """
    Returns a readable list of delegation chain actors.

    Example:
        ["assistant-hub", "calendar-service"]
    """
    chain = []
    act = claims.get("act")

    while act:
        actor = act.get("sub")
        if actor:
            chain.append(actor)
        act = act.get("act")

    return chain