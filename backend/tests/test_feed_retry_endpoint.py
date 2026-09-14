"""HTTP-level tests for POST /api/feeds/{feed_name}/retry -- the admin
"Retry Now" action backing Settings' Feed Health section. Mirrors
test_orchestrator_settings.py's api_client fixture, the only established
pattern in this suite for hitting an authenticated route through
TestClient without a real feed_manager import (feed_manager.py pulls in
anthropic/apscheduler/feedparser/httpx, none of which this test needs)."""

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
    feed_manager_stub.FEEDS = [{"name": "TestFeed", "url": "https://example.com/feed.xml", "tier": 1}]
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

    def _fake_poll_single_feed(feed_name):
        if feed_name != "TestFeed":
            raise ValueError(f"Unknown feed: {feed_name}")
        return {"success": True, "error": "", "items_fetched": 2, "new_entries": 1}

    feed_manager_stub.poll_single_feed = _fake_poll_single_feed
    monkeypatch.setitem(sys.modules, "feed_manager", feed_manager_stub)

    os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-testing-only-32chars")
    os.environ.setdefault("AZURE_AD_TENANT_ID", "test-tenant-id")
    os.environ.setdefault("AZURE_AD_CLIENT_ID", "test-client-id")

    sys.modules.pop("main", None)
    sys.modules["db"] = db_module
    sys.modules.pop("enrichment", None)
    main_mod = importlib.import_module("main")

    with TestClient(main_mod.app, raise_server_exceptions=False) as client:
        yield client, main_mod, feed_manager_stub


def _seed_admin_user(oid="admin-oid-1"):
    db_module.init_db()
    db_module.upsert_user(oid, "admin@example.com", "Admin User", "admin")


def _seed_viewer_user(oid="viewer-oid-1"):
    db_module.init_db()
    db_module.upsert_user(oid, "viewer@example.com", "Viewer User", "viewer")


def test_retry_requires_auth(api_client):
    client, _, _ = api_client
    response = client.post("/api/feeds/TestFeed/retry")
    assert response.status_code == 401


def test_retry_requires_admin_role(api_client):
    client, main_mod, _ = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.post("/api/feeds/TestFeed/retry",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


def test_retry_success_returns_poll_result(api_client):
    client, main_mod, _ = api_client
    _seed_admin_user()
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.post("/api/feeds/TestFeed/retry",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["new_entries"] == 1
    assert body["items_fetched"] == 2


def test_retry_unknown_feed_returns_404(api_client):
    client, main_mod, _ = api_client
    _seed_admin_user()
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.post("/api/feeds/NoSuchFeed/retry",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 404
