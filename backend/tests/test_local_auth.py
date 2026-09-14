import pytest
import sys
import os
import importlib
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db as db_module


def _fresh_auth_module(monkeypatch, *, tenant_id="", local_api_key="test-local-key-32chars-minimum"):
    """auth.py derives AUTH_MODE from AZURE_AD_TENANT_ID at import time, and
    every other test file in this suite imports it with a tenant id already
    set -- so a plain `import auth` here would silently reuse that cached,
    Entra-mode module. Force a fresh import under the env this test wants,
    and hand back a token to restore the previous module afterwards so we
    don't leak local mode into whatever test file runs next.
    """
    if tenant_id:
        monkeypatch.setenv("AZURE_AD_TENANT_ID", tenant_id)
        monkeypatch.setenv("AZURE_AD_CLIENT_ID", "test-client-id")
    else:
        monkeypatch.delenv("AZURE_AD_TENANT_ID", raising=False)
        monkeypatch.delenv("AZURE_AD_CLIENT_ID", raising=False)
    monkeypatch.setenv("LOCAL_API_KEY", local_api_key)
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-that-is-at-least-32-bytes-long!")

    prev = sys.modules.pop("auth", None)
    mod = importlib.import_module("auth")
    return mod, prev


@pytest.fixture
def local_auth(monkeypatch):
    mod, prev = _fresh_auth_module(monkeypatch, tenant_id="")
    try:
        yield mod
    finally:
        sys.modules.pop("auth", None)
        if prev is not None:
            sys.modules["auth"] = prev


@pytest.fixture
def entra_auth(monkeypatch):
    mod, prev = _fresh_auth_module(monkeypatch, tenant_id="test-tenant-id")
    try:
        yield mod
    finally:
        sys.modules.pop("auth", None)
        if prev is not None:
            sys.modules["auth"] = prev


def test_auth_mode_is_local_when_tenant_unset(local_auth):
    assert local_auth.AUTH_MODE == "local"


def test_auth_mode_is_entra_when_tenant_set(entra_auth):
    assert entra_auth.AUTH_MODE == "entra"


def test_verify_local_api_key_accepts_correct_key(local_auth):
    assert local_auth.verify_local_api_key("test-local-key-32chars-minimum") is True


def test_verify_local_api_key_rejects_wrong_key(local_auth):
    assert local_auth.verify_local_api_key("wrong-key") is False


def test_verify_local_api_key_rejects_empty_key(local_auth):
    assert local_auth.verify_local_api_key("") is False


def test_verify_local_api_key_rejects_when_unconfigured(monkeypatch):
    mod, prev = _fresh_auth_module(monkeypatch, tenant_id="", local_api_key="")
    monkeypatch.delenv("LOCAL_API_KEY", raising=False)
    sys.modules.pop("auth", None)
    mod = importlib.import_module("auth")
    try:
        assert mod.verify_local_api_key("anything") is False
    finally:
        sys.modules.pop("auth", None)
        if prev is not None:
            sys.modules["auth"] = prev


# ── Full-app integration: /api/auth/mode + /api/auth/local-login ───────────

def _stub_optional_deps():
    for mod in [
        "feedparser",
        "anthropic",
        "apscheduler",
        "apscheduler.schedulers",
        "apscheduler.schedulers.background",
    ]:
        sys.modules.setdefault(mod, types.ModuleType(mod))

    class _AnyInit:
        def __init__(self, *args, **kwargs):
            pass

    sys.modules["apscheduler.schedulers.background"].BackgroundScheduler = _AnyInit
    sys.modules["anthropic"].Anthropic = _AnyInit

    enrich_stub = types.ModuleType("enrichment")
    for fn in ["run_enrichment", "refresh_and_reenrich", "is_rematch_running", "run_stack_rematch"]:
        setattr(enrich_stub, fn, lambda *args, **kwargs: None)

    feed_manager_stub = types.ModuleType("feed_manager")
    feed_manager_stub.FEEDS = []
    feed_manager_stub.start_scheduler = lambda *args, **kwargs: None
    feed_manager_stub._triage_entry = lambda *args, **kwargs: None
    feed_manager_stub.triage_pending = lambda *args, **kwargs: None
    feed_manager_stub.retriage_batch = lambda *args, **kwargs: None
    feed_manager_stub.retriage_selected_batch = lambda *args, **kwargs: None
    feed_manager_stub.retriage_failed_batch = lambda *args, **kwargs: None
    feed_manager_stub.create_job = lambda *args, **kwargs: "job-1"
    feed_manager_stub.get_job = lambda *args, **kwargs: None
    feed_manager_stub.list_jobs = lambda *args, **kwargs: []
    feed_manager_stub.reextract_iocs_job = lambda *args, **kwargs: None
    feed_manager_stub.poll_single_feed = lambda *args, **kwargs: None

    return enrich_stub, feed_manager_stub


@pytest.fixture
def local_mode_client(tmp_path, monkeypatch):
    monkeypatch.delenv("AZURE_AD_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_AD_CLIENT_ID", raising=False)
    monkeypatch.setenv("LOCAL_API_KEY", "test-local-key-32chars-minimum")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-that-is-at-least-32-bytes-long!")

    enrich_stub, feed_manager_stub = _stub_optional_deps()
    monkeypatch.setitem(sys.modules, "enrichment", enrich_stub)
    monkeypatch.setitem(sys.modules, "feed_manager", feed_manager_stub)

    prev_auth = sys.modules.pop("auth", None)
    sys.modules.pop("main", None)
    sys.modules["db"] = db_module

    from fastapi.testclient import TestClient
    main_mod = importlib.import_module("main")

    try:
        with TestClient(main_mod.app, raise_server_exceptions=False) as client:
            yield client, main_mod
    finally:
        sys.modules.pop("main", None)
        sys.modules.pop("auth", None)
        if prev_auth is not None:
            sys.modules["auth"] = prev_auth


def test_auth_mode_endpoint_reports_local(local_mode_client):
    client, _ = local_mode_client
    response = client.get("/api/auth/mode")
    assert response.status_code == 200
    assert response.json() == {"mode": "local"}


def test_local_login_succeeds_and_token_grants_admin_access(local_mode_client):
    client, _ = local_mode_client
    response = client.post("/api/auth/local-login", json={"api_key": "test-local-key-32chars-minimum"})
    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert data["access_token"]

    me = client.get("/api/users", headers={"Authorization": f"Bearer {data['access_token']}"})
    assert me.status_code == 200


def test_local_login_rejects_wrong_key(local_mode_client):
    client, _ = local_mode_client
    response = client.post("/api/auth/local-login", json={"api_key": "wrong-key"})
    assert response.status_code == 401


def test_local_login_rejects_missing_key(local_mode_client):
    client, _ = local_mode_client
    response = client.post("/api/auth/local-login", json={})
    assert response.status_code == 401


@pytest.fixture
def entra_mode_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_AD_TENANT_ID", "test-tenant-id")
    monkeypatch.setenv("AZURE_AD_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-that-is-at-least-32-bytes-long!")

    enrich_stub, feed_manager_stub = _stub_optional_deps()
    monkeypatch.setitem(sys.modules, "enrichment", enrich_stub)
    monkeypatch.setitem(sys.modules, "feed_manager", feed_manager_stub)

    prev_auth = sys.modules.pop("auth", None)
    sys.modules.pop("main", None)
    sys.modules["db"] = db_module

    from fastapi.testclient import TestClient
    main_mod = importlib.import_module("main")

    try:
        with TestClient(main_mod.app, raise_server_exceptions=False) as client:
            yield client, main_mod
    finally:
        sys.modules.pop("main", None)
        sys.modules.pop("auth", None)
        if prev_auth is not None:
            sys.modules["auth"] = prev_auth


def test_auth_mode_endpoint_reports_entra(entra_mode_client):
    client, _ = entra_mode_client
    response = client.get("/api/auth/mode")
    assert response.status_code == 200
    assert response.json() == {"mode": "entra"}


def test_local_login_returns_404_in_entra_mode(entra_mode_client):
    client, _ = entra_mode_client
    response = client.post("/api/auth/local-login", json={"api_key": "anything"})
    assert response.status_code == 404
