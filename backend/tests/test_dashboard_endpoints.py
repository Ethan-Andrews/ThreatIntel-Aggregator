"""HTTP-level tests for the dashboard/mitre-coverage window params
(Workstream D). Auth gating already covered elsewhere for these routes;
this focuses on the window/from/to contract."""

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


def _seed_entry(conn, hash_, ingested):
    conn.execute(
        "INSERT INTO entries (hash, source, ingested, published, triaged, severity, ttps) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (hash_, "src", ingested, ingested, 1, "Critical", "T1190"),
    )
    conn.commit()


def test_dashboard_stats_default_has_no_window(api_client):
    client, main_mod = api_client
    token = _viewer_token(main_mod)
    conn = db_module._connect_db()
    _seed_entry(conn, "hash-old", "2020-01-01 00:00:00")
    conn.close()

    response = client.get("/api/dashboard/stats", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_dashboard_stats_window_excludes_out_of_range_entries(api_client):
    client, main_mod = api_client
    token = _viewer_token(main_mod)
    conn = db_module._connect_db()
    _seed_entry(conn, "hash-old", "2020-01-01 00:00:00")
    conn.close()

    response = client.get(
        "/api/dashboard/stats?window=1d", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 0


def test_dashboard_stats_bad_window_400s(api_client):
    client, main_mod = api_client
    token = _viewer_token(main_mod)
    response = client.get(
        "/api/dashboard/stats?window=bogus", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400


def test_mitre_coverage_window_excludes_out_of_range_entries(api_client):
    client, main_mod = api_client
    token = _viewer_token(main_mod)
    conn = db_module._connect_db()
    conn.execute(
        "INSERT INTO entries (hash, source, ingested, published, triaged, severity, ttps) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("hash-old", "src", "2020-01-01 00:00:00", "2020-01-01", 1, "Critical", "T1053.005"),
    )
    conn.commit()
    conn.close()

    all_time = client.get("/api/mitre/coverage", headers={"Authorization": f"Bearer {token}"})
    assert all_time.json().get("T1053.005") == 1

    windowed = client.get(
        "/api/mitre/coverage?window=1d", headers={"Authorization": f"Bearer {token}"},
    )
    assert "T1053.005" not in windowed.json()
