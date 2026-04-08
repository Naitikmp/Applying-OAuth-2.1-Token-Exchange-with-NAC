"""
Auth0 integration configuration — NAC demo (RFC 8693 sidecar pattern).

All sensitive values come from environment variables.
Copy .env.auth0.example to .env.auth0 and fill in your Auth0 tenant details,
then load with:  set -a && source .env.auth0 && set +a   (bash)
              or: $env:AUTH0_DOMAIN = "..."              (PowerShell)
"""

from __future__ import annotations

import os

# ── Auth0 Tenant ──────────────────────────────────────────────────────────────
# Found at: Auth0 Dashboard → Applications → your app → Settings → Domain
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "")
# e.g. "dev-abc123xyz.us.auth0.com"

# ── Machine-to-Machine Application ───────────────────────────────────────────
# Found at: Auth0 Dashboard → Applications → your M2M app → Settings
AUTH0_CLIENT_ID     = os.getenv("AUTH0_CLIENT_ID",     "")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET", "")

# ── Auth0 API resource identifier (the "hub" audience) ───────────────────────
# Set when you create the API: Auth0 → Applications → APIs → your API → Identifier
# Must match exactly — Auth0 puts this in the "aud" claim of issued tokens.
AUTH0_HUB_AUDIENCE = os.getenv("AUTH0_HUB_AUDIENCE", "https://mcp-hub.example.com")

# ── Scopes your API exposes ───────────────────────────────────────────────────
# Must be created in Auth0 → Applications → APIs → your API → Permissions tab
AUTH0_ROOT_SCOPES = os.getenv(
    "AUTH0_ROOT_SCOPES",
    "calendar:read docs:read comms:send external:fetch",
)

# ── Ports for the Auth0-integrated stack (9400-9405) ─────────────────────────
# Separated from the internal stacks (9200-9205 baseline, 9300-9305 secure)
AUTH0_EXCHANGE_PORT = int(os.getenv("AUTH0_EXCHANGE_PORT", "9400"))
AUTH0_HUB_PORT      = int(os.getenv("AUTH0_HUB_PORT",      "9401"))
AUTH0_CALENDAR_PORT = int(os.getenv("AUTH0_CALENDAR_PORT", "9402"))
AUTH0_DOCS_PORT     = int(os.getenv("AUTH0_DOCS_PORT",     "9403"))
AUTH0_COMMS_PORT    = int(os.getenv("AUTH0_COMMS_PORT",    "9404"))
AUTH0_EXTERNAL_PORT = int(os.getenv("AUTH0_EXTERNAL_PORT", "9405"))

# ── Worker audience identifiers (sub-resources under the hub audience) ────────
# These are what each child token's "aud" claim will be set to.
# Do NOT register these separately in Auth0 — they are enforced by our sidecar.
WORKER_AUDIENCES: dict[str, str] = {
    "calendar":     "calendar-service",
    "docs":         "docs-service",
    "comms":        "comms-service",
    "external_api": "external-api-service",
}

# ── Required scopes per worker (strict subset of AUTH0_ROOT_SCOPES) ───────────
WORKER_SCOPES: dict[str, list[str]] = {
    "calendar":     ["calendar:read"],
    "docs":         ["docs:read"],
    "comms":        ["comms:send"],
    "external_api": ["external:fetch"],
}


def validate_config() -> list[str]:
    """
    Return a list of missing required settings.
    Empty list means config is complete and the demo can run.
    """
    missing: list[str] = []
    for name, val in [
        ("AUTH0_DOMAIN",        AUTH0_DOMAIN),
        ("AUTH0_CLIENT_ID",     AUTH0_CLIENT_ID),
        ("AUTH0_CLIENT_SECRET", AUTH0_CLIENT_SECRET),
        ("AUTH0_HUB_AUDIENCE",  AUTH0_HUB_AUDIENCE),
    ]:
        if not val or val.startswith("YOUR_"):
            missing.append(name)
    return missing
