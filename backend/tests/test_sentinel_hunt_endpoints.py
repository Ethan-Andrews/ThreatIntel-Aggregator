"""HTTP-level tests for /api/sentinel-hunts/* -- the Sentinel-native hunt/
query inventory endpoints. Mirrors test_hunt_sync_settings.py's api_client
fixture; the underlying modules (sentinel_hunt_sync.py, sentinel_hunt_
queries.py, sentinel_hunt_test.py) have their own dedicated unit tests, so
this focuses on auth gating, 404/400 handling, and request/response wiring."""

import importlib
import os
import sys
import types

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db as db_module
from detection_pipeline import sentinel_hunt_queries


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


def _seed_admin_user(oid="admin-oid-1"):
    db_module.init_db()
    db_module.upsert_user(oid, "admin@example.com", "Admin User", "admin")


def _seed_viewer_user(oid="viewer-oid-1"):
    db_module.init_db()
    db_module.upsert_user(oid, "viewer@example.com", "Viewer User", "viewer")


def _admin_token(main_mod):
    _seed_admin_user()
    return main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")


def _viewer_token(main_mod):
    _seed_viewer_user()
    return main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")


def _seed_hunt_and_query(conn, review_state="pending"):
    hunt_id = conn.execute(
        "INSERT INTO sentinel_hunts (sentinel_hunt_id, display_name, query_count) "
        "VALUES (?, ?, ?) RETURNING id",
        ("hunt-1", "Test Hunt", 1),
    ).fetchone()["id"]
    query_id = conn.execute(
        "INSERT INTO sentinel_hunt_queries "
        "(hunt_id, sentinel_saved_search_id, display_name, kql_body, review_state) "
        "VALUES (?, ?, ?, ?, ?) RETURNING id",
        (hunt_id, "q-1", "Query 1", "T | take 1", review_state),
    ).fetchone()["id"]
    conn.commit()
    return hunt_id, query_id


# --- auth gating -------------------------------------------------------------

@pytest.mark.parametrize("method,path", [
    ("get", "/api/sentinel-hunts"),
    ("get", "/api/sentinel-hunts/1"),
    ("get", "/api/sentinel-hunts/1/queries"),
    ("get", "/api/sentinel-hunts/queries/1"),
])
def test_read_endpoints_require_auth(api_client, method, path):
    client, _ = api_client
    response = getattr(client, method)(path)
    assert response.status_code == 401


@pytest.mark.parametrize("method,path", [
    ("post", "/api/sentinel-hunts/sync"),
    ("post", "/api/sentinel-hunts/queries/1/test"),
    ("post", "/api/sentinel-hunts/queries/1/tune"),
    ("post", "/api/sentinel-hunts/queries/1/tuning-suggestion/apply"),
    ("post", "/api/sentinel-hunts/queries/1/tuning-suggestion/dismiss"),
    ("patch", "/api/sentinel-hunts/queries/1/review"),
])
def test_write_endpoints_require_admin_role(api_client, method, path):
    client, main_mod = api_client
    token = _viewer_token(main_mod)
    kwargs = {"headers": {"Authorization": f"Bearer {token}"}}
    if method == "patch":
        kwargs["json"] = {"review_state": "approved"}
    response = getattr(client, method)(path, **kwargs)
    assert response.status_code == 403


# --- list / detail -------------------------------------------------------------

def test_list_sentinel_hunts_empty(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.get("/api/sentinel-hunts", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"total": 0, "items": []}


def test_list_sentinel_hunts_caps_limit_at_200(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.get(
        "/api/sentinel-hunts?limit=99999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200


def test_list_sentinel_hunts_searches_by_name(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    conn.execute(
        "INSERT INTO sentinel_hunts (sentinel_hunt_id, display_name, query_count) "
        "VALUES (?, ?, ?)",
        ("hunt-ps", "Suspicious PowerShell Activity", 0),
    )
    conn.execute(
        "INSERT INTO sentinel_hunts (sentinel_hunt_id, display_name, query_count) "
        "VALUES (?, ?, ?)",
        ("hunt-task", "Scheduled Task Creation", 0),
    )
    conn.commit()

    response = client.get(
        "/api/sentinel-hunts?search=powershell", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["sentinel_hunt_id"] == "hunt-ps"


def test_get_sentinel_hunt_404(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.get("/api/sentinel-hunts/999999", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404


def test_get_sentinel_hunt_found(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_id, _ = _seed_hunt_and_query(conn)

    response = client.get(f"/api/sentinel-hunts/{hunt_id}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["display_name"] == "Test Hunt"


def test_list_hunt_queries_404_for_missing_hunt(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.get(
        "/api/sentinel-hunts/999999/queries", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_list_hunt_queries_found(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_id, query_id = _seed_hunt_and_query(conn)

    response = client.get(
        f"/api/sentinel-hunts/{hunt_id}/queries", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["id"] == query_id
    assert "kql_body" not in body["items"][0]


def test_list_hunt_queries_rejects_invalid_disposition(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_id, _ = _seed_hunt_and_query(conn)

    response = client.get(
        f"/api/sentinel-hunts/{hunt_id}/queries?disposition=bogus",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400


def test_list_hunt_queries_filters_by_disposition_and_search(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_id, _ = _seed_hunt_and_query(conn)
    conn.execute(
        "INSERT INTO sentinel_hunt_queries "
        "(hunt_id, sentinel_saved_search_id, display_name, kql_body, backtest_disposition) "
        "VALUES (?, ?, ?, ?, ?)",
        (hunt_id, "q-tune", "Suspicious PowerShell Download", "T | take 1", "needs_tuning"),
    )
    conn.commit()

    response = client.get(
        f"/api/sentinel-hunts/{hunt_id}/queries?disposition=needs_tuning",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["sentinel_saved_search_id"] == "q-tune"

    response = client.get(
        f"/api/sentinel-hunts/{hunt_id}/queries?search=powershell",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["sentinel_saved_search_id"] == "q-tune"


def test_get_query_detail_404(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.get(
        "/api/sentinel-hunts/queries/999999", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_get_query_detail_includes_kql_body(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    _, query_id = _seed_hunt_and_query(conn)

    response = client.get(
        f"/api/sentinel-hunts/queries/{query_id}", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["kql_body"] == "T | take 1"


# --- sync ----------------------------------------------------------------------

def test_sync_disabled_returns_noop(api_client, monkeypatch):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)

    response = client.post("/api/sentinel-hunts/sync", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["enabled"] is False


# --- test / tune -----------------------------------------------------------------

def test_test_endpoint_404_for_missing_query(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.post(
        "/api/sentinel-hunts/queries/999999/test", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_test_endpoint_no_sentinel_client_records_error(api_client, monkeypatch):
    """No SentinelClient configured in this test environment -- confirms the
    endpoint still returns 200 with the gate/error recorded, not a 500."""
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_id, query_id = _seed_hunt_and_query(conn)

    response = client.post(
        f"/api/sentinel-hunts/queries/{query_id}/test",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["control_probe_result"]["gate_verdict"] in ("pass", "reject")
    assert body["last_tested_at"] is not None


def test_tune_endpoint_404_for_missing_query(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.post(
        "/api/sentinel-hunts/queries/999999/tune", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_tune_endpoint_requires_needs_tuning_disposition(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    _, query_id = _seed_hunt_and_query(conn)
    sentinel_hunt_queries.record_query_test_result(conn, query_id, {"tables": []}, "clean")

    response = client.post(
        f"/api/sentinel-hunts/queries/{query_id}/tune",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
    assert "needs_tuning" in response.json()["detail"]


# --- tuning-suggestion apply/dismiss ----------------------------------------------

def test_dismiss_tuning_suggestion_endpoint_404_for_missing_query(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.post(
        "/api/sentinel-hunts/queries/999999/tuning-suggestion/dismiss",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_dismiss_tuning_suggestion_endpoint_success(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    _, query_id = _seed_hunt_and_query(conn)
    sentinel_hunt_queries.record_query_tune_result(
        conn, query_id, {"disposition": "tuned", "final_body": "T | take 1 | where X != 1"},
    )

    response = client.post(
        f"/api/sentinel-hunts/queries/{query_id}/tuning-suggestion/dismiss",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["result"]["success"] is True
    assert body["query"]["tuning_suggestion"]["action"] == "dismissed"


def test_apply_tuning_suggestion_endpoint_404_for_missing_query(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.post(
        "/api/sentinel-hunts/queries/999999/tuning-suggestion/apply",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_apply_tuning_suggestion_endpoint_reports_failure_when_sync_disabled(api_client, monkeypatch):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    _, query_id = _seed_hunt_and_query(conn)
    sentinel_hunt_queries.record_query_tune_result(
        conn, query_id, {"disposition": "tuned", "final_body": "T | take 1 | where X != 1"},
    )

    response = client.post(
        f"/api/sentinel-hunts/queries/{query_id}/tuning-suggestion/apply",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["result"]["success"] is False
    assert "sync is off" in body["result"]["reason"]


# --- review ----------------------------------------------------------------------

def test_review_endpoint_updates_state(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    _, query_id = _seed_hunt_and_query(conn)

    response = client.patch(
        f"/api/sentinel-hunts/queries/{query_id}/review",
        headers={"Authorization": f"Bearer {token}"},
        json={"review_state": "approved"},
    )
    assert response.status_code == 200
    assert response.json()["review_state"] == "approved"


def test_review_endpoint_404_for_missing_query(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.patch(
        "/api/sentinel-hunts/queries/999999/review",
        headers={"Authorization": f"Bearer {token}"},
        json={"review_state": "approved"},
    )
    assert response.status_code == 404


def test_review_endpoint_rejects_invalid_state(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    _, query_id = _seed_hunt_and_query(conn)

    response = client.patch(
        f"/api/sentinel-hunts/queries/{query_id}/review",
        headers={"Authorization": f"Bearer {token}"},
        json={"review_state": "not-a-real-state"},
    )
    assert response.status_code == 422
