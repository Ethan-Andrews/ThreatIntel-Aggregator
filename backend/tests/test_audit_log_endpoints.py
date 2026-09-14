"""HTTP-level tests for /api/audit/* -- admin-only gating and request wiring.
audit_log.py's own combining/filtering logic has its own dedicated unit
tests (test_audit_log.py); this focuses on auth and the endpoint contract."""

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


@pytest.mark.parametrize("path", [
    "/api/audit/summary", "/api/audit/failures", "/api/audit/failure-breakdown",
])
def test_requires_auth(api_client, path):
    client, _ = api_client
    assert client.get(path).status_code == 401


@pytest.mark.parametrize("path", [
    "/api/audit/summary", "/api/audit/failures", "/api/audit/failure-breakdown",
])
def test_viewer_forbidden(api_client, path):
    client, main_mod = api_client
    token = _viewer_token(main_mod)
    response = client.get(path, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_annotation_endpoints_require_auth(api_client):
    client, _ = api_client
    assert client.patch("/api/audit/detection/1", json={"status": "fixed"}).status_code == 401
    assert client.delete("/api/audit/detection/1").status_code == 401


def test_annotation_endpoints_forbidden_for_viewer(api_client):
    client, main_mod = api_client
    token = _viewer_token(main_mod)
    headers = {"Authorization": f"Bearer {token}"}
    assert client.patch("/api/audit/detection/1", json={"status": "fixed"}, headers=headers).status_code == 403
    assert client.delete("/api/audit/detection/1", headers=headers).status_code == 403


def test_admin_gets_empty_summary_and_failures_on_a_fresh_db(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    headers = {"Authorization": f"Bearer {token}"}

    summary = client.get("/api/audit/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.json() == {"failing": 0, "passing": 0}

    failures = client.get("/api/audit/failures", headers=headers)
    assert failures.status_code == 200
    assert failures.json() == {"total": 0, "items": []}


def test_invalid_outcome_falls_back_to_unfiltered(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.get(
        "/api/audit/failures?outcome=bogus",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json() == {"total": 0, "items": []}


def test_limit_is_capped_at_200(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.get(
        "/api/audit/failures?limit=9999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200


def test_admin_gets_empty_breakdown_on_a_fresh_db(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.get(
        "/api/audit/failure-breakdown",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json() == {"categories": []}


def test_failures_category_param_filters_the_list(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    import json as json_module
    strategy_row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        ("T1059", "Command and Scripting Interpreter", "obj", []),
    ).fetchone()
    conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, name, "
        "static_gate_verdict, static_gate_findings) VALUES (?, ?, ?, ?, 'reject', ?)",
        (strategy_row["id"], "hash-1", "T | take 1", "Bad Rule",
         json_module.dumps([{"code": "no_table", "detail": "x"}])),
    )
    conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, name, "
        "static_gate_verdict, static_gate_findings) VALUES (?, ?, ?, ?, 'reject', ?)",
        (strategy_row["id"], "hash-2", "T | take 1", "Other Bad Rule",
         json_module.dumps([{"code": "memory_risk", "detail": "y"}])),
    )
    conn.commit()
    conn.close()

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get(
        "/api/audit/failures?category=Static+gate%3A+no_table",
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["title"] == "Bad Rule"

    # An unmatched category is a legitimate empty result, not an error.
    empty = client.get(
        "/api/audit/failures?category=not+a+real+category",
        headers=headers,
    )
    assert empty.status_code == 200
    assert empty.json() == {"total": 0, "items": []}


def test_breakdown_reflects_seeded_static_gate_rejection(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    import json as json_module
    strategy_row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        ("T1059", "Command and Scripting Interpreter", "obj", []),
    ).fetchone()
    conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, name, "
        "static_gate_verdict, static_gate_findings) VALUES (?, ?, ?, ?, 'reject', ?)",
        (strategy_row["id"], "hash-1", "T | take 1", "Bad Rule",
         json_module.dumps([{"code": "no_table", "detail": "x"}])),
    )
    conn.commit()
    conn.close()

    response = client.get(
        "/api/audit/failure-breakdown",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json() == {"categories": [{"category": "Static gate: no_table", "count": 1}]}


def _seed_failing_detection(name="Bad Rule"):
    conn = db_module._connect_db()
    strategy_row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        ("T1059", "Command and Scripting Interpreter", "obj", []),
    ).fetchone()
    row = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, name, static_gate_verdict) "
        "VALUES (?, ?, ?, ?, 'reject') RETURNING id",
        (strategy_row["id"], "hash-1", "T | take 1", name),
    ).fetchone()
    conn.commit()
    analytic_id = row["id"]
    conn.close()
    return analytic_id


def test_annotating_a_row_excludes_it_from_failing_and_status_all_still_finds_it(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    headers = {"Authorization": f"Bearer {token}"}
    analytic_id = _seed_failing_detection()

    before = client.get("/api/audit/summary", headers=headers).json()
    assert before == {"failing": 1, "passing": 0}

    patch = client.patch(
        f"/api/audit/detection/{analytic_id}",
        json={"status": "fixed", "notes": "closed manually"},
        headers=headers,
    )
    assert patch.status_code == 200
    assert patch.json()["status"] == "fixed"

    after = client.get("/api/audit/summary", headers=headers).json()
    assert after == {"failing": 0, "passing": 1}, "an annotated row must drop out of the failing count"

    default_list = client.get("/api/audit/failures?outcome=failing", headers=headers).json()
    assert default_list["total"] == 0

    fixed_only = client.get("/api/audit/failures?status=fixed", headers=headers).json()
    assert fixed_only["total"] == 1
    assert fixed_only["items"][0]["annotation_status"] == "fixed"
    assert fixed_only["items"][0]["annotation_notes"] == "closed manually"

    all_rows = client.get("/api/audit/failures?status=all", headers=headers).json()
    assert all_rows["total"] == 1


def test_clearing_an_annotation_restores_the_failing_count(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    headers = {"Authorization": f"Bearer {token}"}
    analytic_id = _seed_failing_detection()

    client.patch(f"/api/audit/detection/{analytic_id}", json={"status": "acknowledged"}, headers=headers)
    assert client.get("/api/audit/summary", headers=headers).json()["failing"] == 0

    cleared = client.delete(f"/api/audit/detection/{analytic_id}", headers=headers)
    assert cleared.status_code == 200
    assert client.get("/api/audit/summary", headers=headers).json()["failing"] == 1, \
        "clearing an annotation on a still-genuinely-failing row must restore it to the failing count"


def test_unrecognized_source_400s_without_touching_the_db(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.patch(
        "/api/audit/not_a_real_source/1", json={"status": "fixed"}, headers=headers,
    )
    assert response.status_code == 400

    conn = db_module._connect_db()
    count = conn.execute("SELECT COUNT(*) FROM audit_annotations").fetchone()[0]
    conn.close()
    assert count == 0


def test_trend_endpoint_requires_auth(api_client):
    client, _ = api_client
    assert client.get("/api/audit/trend").status_code == 401


def test_trend_endpoint_returns_empty_on_fresh_db(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.get("/api/audit/trend", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"trend": []}


def test_trend_endpoint_rejects_bad_bucket(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.get(
        "/api/audit/trend?bucket=fortnight", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400


def test_window_param_rejects_unrecognized_window(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.get(
        "/api/audit/failures?window=bogus", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400


def test_window_param_filters_summary(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    headers = {"Authorization": f"Bearer {token}"}
    analytic_id = _seed_failing_detection()
    conn = db_module._connect_db()
    conn.execute(
        "UPDATE analytics SET created_at = now() - interval '10 days' WHERE id = ?", (analytic_id,),
    )
    conn.commit()
    conn.close()

    all_time = client.get("/api/audit/summary", headers=headers).json()
    assert all_time == {"failing": 1, "passing": 0}

    windowed = client.get("/api/audit/summary?window=1d", headers=headers).json()
    assert windowed == {"failing": 0, "passing": 0}


def test_custom_window_without_from_to_400s(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.get(
        "/api/audit/summary?window=custom", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400


def test_unrecognized_status_filter_400s(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    response = client.get(
        "/api/audit/failures?status=not_a_real_status",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
