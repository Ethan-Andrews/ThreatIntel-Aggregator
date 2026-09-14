"""HTTP-level tests for GET /api/exposure/metrics (Workstream F)."""

import importlib
import os
import sys
import types

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db as db_module


@pytest.fixture
def api_client(tmp_db, monkeypatch):
    for mod in ["feedparser", "anthropic", "apscheduler",
                "apscheduler.schedulers", "apscheduler.schedulers.background"]:
        sys.modules.setdefault(mod, types.ModuleType(mod))

    class _AnyInit:
        def __init__(self, *args, **kwargs):
            pass

    sys.modules["apscheduler.schedulers.background"].BackgroundScheduler = _AnyInit
    sys.modules["anthropic"].Anthropic = _AnyInit

    enrich_stub = types.ModuleType("enrichment")
    for fn in ["run_enrichment", "refresh_and_reenrich", "is_rematch_running", "run_stack_rematch"]:
        setattr(enrich_stub, fn, lambda *args, **kwargs: None)
    sys.modules["enrichment"] = enrich_stub

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
    feed_manager_stub.poll_single_feed = lambda *args, **kwargs: {"success": True, "error": "", "items_fetched": 0, "new_entries": 0}
    monkeypatch.setitem(sys.modules, "feed_manager", feed_manager_stub)

    os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-testing-only-32chars")
    os.environ.setdefault("AZURE_AD_TENANT_ID", "test-tenant-id")
    os.environ.setdefault("AZURE_AD_CLIENT_ID", "test-client-id")

    sys.modules.pop("main", None)
    sys.modules["db"] = db_module
    sys.modules.pop("enrichment", None)
    main_mod = importlib.import_module("main")

    with TestClient(main_mod.app, raise_server_exceptions=False) as client:
        yield client, main_mod


def _viewer_token(main_mod):
    db_module.init_db()
    db_module.upsert_user("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")
    return main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")


def test_requires_auth(api_client):
    client, _ = api_client
    assert client.get("/api/exposure/metrics").status_code == 401


def test_empty_db_returns_empty_shapes(api_client):
    client, main_mod = api_client
    token = _viewer_token(main_mod)
    response = client.get("/api/exposure/metrics", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"intake_by_day": [], "remediated_by_day": [], "standing": []}


def test_org_and_window_params_are_wired(api_client):
    client, main_mod = api_client
    token = _viewer_token(main_mod)
    conn = db_module._connect_db()
    conn.execute("INSERT INTO runzero_assets (id, org, site, alive) VALUES ('a1', 'Org', 'HQ', 1)")
    conn.execute(
        "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen) "
        "VALUES ('a1', 'h1', 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
    )
    conn.commit()
    conn.close()

    response = client.get(
        "/api/exposure/metrics?org=Org", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["standing"] == [
        {"org": "Org", "total_intake": 1, "still_standing": 1, "remediated": 0}
    ]

    windowed = client.get(
        "/api/exposure/metrics?window=1d", headers={"Authorization": f"Bearer {token}"},
    )
    assert windowed.json()["standing"] == []


def test_bad_window_400s(api_client):
    client, main_mod = api_client
    token = _viewer_token(main_mod)
    response = client.get(
        "/api/exposure/metrics?window=bogus", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
