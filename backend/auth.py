"""
auth.py — Entra ID token validation + app JWT sign/verify, or local API-key auth

Two mutually exclusive auth modes, selected automatically by whether Entra is
configured (see AUTH_MODE below) -- there is no separate flag to keep in sync:

Entra mode (AZURE_AD_TENANT_ID set):
    AZURE_AD_TENANT_ID   — Entra tenant ID
    AZURE_AD_CLIENT_ID   — Entra app registration client ID
    JWT_SECRET_KEY       — 32+ byte random secret for signing app JWTs

Local mode (AZURE_AD_TENANT_ID unset):
    LOCAL_API_KEY         — shared secret; anyone with it gets admin access
    JWT_SECRET_KEY        — same as above, still required either way
"""
import os
import secrets
import time
import logging
from typing import Optional

import httpx
from jose import jwt, JWTError
from fastapi import HTTPException, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from db import DbReadinessError, get_user_by_oid

_logger = logging.getLogger("security")

TENANT_ID  = os.environ.get("AZURE_AD_TENANT_ID", "")
CLIENT_ID  = os.environ.get("AZURE_AD_CLIENT_ID", "")
JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "")
LOCAL_API_KEY = os.environ.get("LOCAL_API_KEY", "")

# Single source of truth for which mode is active -- both /api/auth/mode and
# the login routes derive from this rather than a separate flag, so the two
# can't drift out of sync with each other.
AUTH_MODE = "entra" if TENANT_ID else "local"

_APP_TOKEN_EXPIRY_HOURS = 8
_JWKS_CACHE_TTL_SECONDS = 3600

_jwks_cache: Optional[list] = None
_jwks_cache_ts: float = 0.0

bearer_scheme = HTTPBearer()


class AuthError(Exception):
    """Raised for any authentication failure. Carries a diagnostic code."""
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


# ── Local API-key auth (no Azure/Entra dependency) ──────────────────────────

def verify_local_api_key(key: str) -> bool:
    """Timing-safe comparison of a candidate key against LOCAL_API_KEY."""
    if not LOCAL_API_KEY or not key:
        return False
    return secrets.compare_digest(key, LOCAL_API_KEY)


# ── App JWT (issued by this backend) ────────────────────────────────────────

def create_app_token(entra_oid: str, email: str, display_name: str, role: str) -> str:
    """Sign and return an 8-hour app JWT."""
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET_KEY is not set")
    payload = {
        "sub":   entra_oid,
        "email": email,
        "name":  display_name,
        "role":  role,
        "iat":   int(time.time()),
        "exp":   int(time.time()) + _APP_TOKEN_EXPIRY_HOURS * 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_app_token(token: str) -> dict:
    """Verify app JWT signature and expiry. Returns payload dict. Raises AuthError on failure."""
    if not JWT_SECRET:
        raise AuthError("JWT_SECRET_MISSING", "JWT_SECRET_KEY is not set")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except JWTError as e:
        raise AuthError("TOKEN_INVALID", f"Invalid app token: {e}") from e


# ── Entra ID token validation (JWKS) ────────────────────────────────────────

async def _get_jwks() -> list:
    """Fetch JWKS from Entra with 1-hour in-memory cache."""
    global _jwks_cache, _jwks_cache_ts
    now = time.time()
    if _jwks_cache is not None and (now - _jwks_cache_ts) < _JWKS_CACHE_TTL_SECONDS:
        return _jwks_cache
    url = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
    async with httpx.AsyncClient(verify=True, timeout=10.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
    _jwks_cache = resp.json().get("keys", [])
    _jwks_cache_ts = now
    return _jwks_cache


async def validate_entra_token(id_token: str) -> dict:
    """
    Validate a Microsoft Entra id_token.
    Checks signature (via JWKS), iss, aud, exp, tid.
    Returns the decoded claims dict. Raises AuthError on any failure.
    """
    if not TENANT_ID or not CLIENT_ID:
        raise AuthError("CONFIG_MISSING", "AZURE_AD_TENANT_ID / AZURE_AD_CLIENT_ID not configured")
    try:
        keys = await _get_jwks()
        claims = jwt.decode(
            id_token,
            keys,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
            options={"verify_exp": True},
        )
    except JWTError as e:
        raise AuthError("TOKEN_INVALID", f"Entra token invalid: {e}") from e

    # Tenant binding — reject tokens from other tenants
    if claims.get("tid") != TENANT_ID:
        raise AuthError("TENANT_MISMATCH", "Token tenant mismatch")

    return claims


# ── FastAPI dependencies ─────────────────────────────────────────────────────

def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
):
    """
    FastAPI dependency. Verifies the app JWT, checks is_active, attaches
    request.state.user = {"oid", "email", "name", "role"}.
    """
    token = credentials.credentials
    try:
        payload = verify_app_token(token)
    except AuthError:
        _logger.warning(
            "AUTH_FAILURE ip=%s path=%s",
            getattr(request.client, "host", "unknown"),
            request.url.path,
        )
        raise HTTPException(status_code=401, detail="Not authenticated")

    oid = payload.get("sub")
    try:
        user = get_user_by_oid(oid) if oid else None
    except DbReadinessError:
        _logger.warning(
            "AUTH_STORAGE_UNAVAILABLE ip=%s path=%s",
            getattr(request.client, "host", "unknown"),
            request.url.path,
        )
        raise HTTPException(status_code=503, detail="Authentication unavailable")

    if not user or not user.get("is_active"):
        _logger.warning(
            "AUTH_FAILURE_INACTIVE ip=%s oid=%s path=%s",
            getattr(request.client, "host", "unknown"),
            oid,
            request.url.path,
        )
        raise HTTPException(status_code=401, detail="Not authenticated")

    request.state.user = {
        "oid":   oid,
        "email": user["email"],
        "name":  user["display_name"],
        "role":  user["role"],
    }


def require_admin(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
):
    """
    FastAPI dependency. Like require_auth but additionally enforces role='admin'.
    """
    require_auth(request, credentials)
    if request.state.user.get("role") != "admin":
        _logger.warning(
            "AUTHZ_FAILURE ip=%s oid=%s path=%s",
            getattr(request.client, "host", "unknown"),
            request.state.user.get("oid"),
            request.url.path,
        )
        raise HTTPException(status_code=403, detail="Forbidden")
