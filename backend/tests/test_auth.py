import pytest
import time
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Set required env vars before importing auth
os.environ.setdefault("AZURE_AD_TENANT_ID", "test-tenant-id")
os.environ.setdefault("AZURE_AD_CLIENT_ID", "test-client-id")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-that-is-at-least-32-bytes-long!")

import auth


def test_create_app_token_returns_string():
    token = auth.create_app_token(
        entra_oid="oid-001",
        email="alice@example.com",
        display_name="Alice",
        role="admin",
    )
    assert isinstance(token, str)
    assert len(token) > 20


def test_verify_app_token_valid_token():
    token = auth.create_app_token("oid-001", "a@example.com", "Alice", "viewer")
    payload = auth.verify_app_token(token)
    assert payload["sub"] == "oid-001"
    assert payload["email"] == "a@example.com"
    assert payload["role"] == "viewer"


def test_verify_app_token_wrong_secret_raises():
    token = auth.create_app_token("oid-001", "a@example.com", "Alice", "viewer")
    # Tamper the token by replacing the signature portion
    parts = token.split(".")
    tampered = parts[0] + "." + parts[1] + ".invalidsignature"
    with pytest.raises(auth.AuthError):
        auth.verify_app_token(tampered)


def test_verify_app_token_expired_raises(monkeypatch):
    # Issue a token that expires in -1 seconds (already expired)
    import jose.jwt as jose_jwt
    import datetime
    now = datetime.datetime.utcnow() - datetime.timedelta(hours=10)
    payload = {"sub": "oid-001", "email": "a@example.com", "role": "viewer", "exp": now}
    token = jose_jwt.encode(payload, os.environ["JWT_SECRET_KEY"], algorithm="HS256")
    with pytest.raises(auth.AuthError):
        auth.verify_app_token(token)


def test_validate_entra_token_bad_jwks_raises(monkeypatch):
    """validate_entra_token should raise AuthError when JWKS returns no usable keys."""
    async def mock_get_jwks():
        return []  # empty — forces JWTError → AuthError

    monkeypatch.setattr(auth, "_get_jwks", mock_get_jwks)

    import asyncio
    with pytest.raises(auth.AuthError):
        asyncio.run(auth.validate_entra_token("fake.token.here"))
