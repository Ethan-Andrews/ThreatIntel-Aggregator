"""HTTP-level tests for POST /api/detections/tuning-suggestions/{apply,
dismiss} -- mirrors test_alignment_endpoints.py's api_client fixture, the
established pattern for hitting an authenticated route through TestClient."""

import importlib
import json
import os
import sys
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))
import db as db_module
import hunts as hunts_module
import hunt_sync_settings


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
    feed_manager_stub.poll_single_feed = lambda *args, **kwargs: {
        "success": True, "error": "", "items_fetched": 0, "new_entries": 0,
    }
    monkeypatch.setitem(sys.modules, "feed_manager", feed_manager_stub)

    os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-testing-only-32chars")
    os.environ.setdefault("AZURE_AD_TENANT_ID", "test-tenant-id")
    os.environ.setdefault("AZURE_AD_CLIENT_ID", "test-client-id")
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)

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


_TUNED_HISTORY = {
    "disposition": "tuned",
    "final_body": 'DeviceProcessEvents | where AccountName != @"bob"',
}


_technique_counter = iter(range(1, 1000))


def _seed_analytic(hunt_id=None, tune_history=None, name="Suspicious Task"):
    technique_id = f"T1053.{next(_technique_counter):03d}"
    conn = db_module._connect_db()
    strategy = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, "Scheduled Task", "Detect it", []),
    ).fetchone()
    row = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, name, hunt_id, tune_history) "
        "VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
        (strategy["id"], "hash-" + technique_id, "DeviceProcessEvents | take 1", name, hunt_id,
         json.dumps(tune_history) if tune_history is not None else None),
    ).fetchone()
    conn.commit()
    conn.close()
    return row["id"]


def _seed_hunt():
    conn = db_module._connect_db()
    hunt_id = hunts_module.get_or_create_hunt(conn, "hash-1", title="A hunt")
    conn.close()
    return hunt_id


# --- auth gating -----------------------------------------------------------

def test_apply_requires_auth(api_client):
    client, _ = api_client
    response = client.post("/api/detections/tuning-suggestions/apply", json={"analytic_ids": [1]})
    assert response.status_code == 401


def test_apply_requires_admin_role(api_client):
    client, main_mod = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.post(
        "/api/detections/tuning-suggestions/apply", json={"analytic_ids": [1]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_dismiss_requires_admin_role(api_client):
    client, main_mod = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.post(
        "/api/detections/tuning-suggestions/dismiss", json={"analytic_ids": [1]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_apply_rejects_empty_analytic_ids(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.post(
        "/api/detections/tuning-suggestions/apply", json={"analytic_ids": []},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


# --- dismiss (single + batch) -----------------------------------------------

def test_dismiss_single_id_records_action(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    analytic_id = _seed_analytic(tune_history=_TUNED_HISTORY)
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.post(
        "/api/detections/tuning-suggestions/dismiss", json={"analytic_ids": [analytic_id]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["results"] == [{"analytic_id": analytic_id, "success": True, "reason": None}]

    conn = db_module._connect_db()
    row = conn.execute(
        "SELECT action, performed_by FROM tuning_suggestion_actions WHERE analytic_id = ?",
        (analytic_id,),
    ).fetchone()
    conn.close()
    assert row["action"] == "dismissed"
    # performed_by comes from the authenticated admin's token, never a
    # client-supplied field on the request body.
    assert row["performed_by"] == "Admin User"


def test_dismiss_batch_reports_independent_per_item_outcomes(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    good_id = _seed_analytic(tune_history=_TUNED_HISTORY)
    no_suggestion_id = _seed_analytic(tune_history=None, name="No suggestion")
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.post(
        "/api/detections/tuning-suggestions/dismiss",
        json={"analytic_ids": [good_id, no_suggestion_id, 999999]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    by_id = {r["analytic_id"]: r for r in response.json()["results"]}
    assert by_id[good_id]["success"] is True
    assert by_id[no_suggestion_id]["success"] is False
    assert by_id[999999]["success"] is False


# --- apply (single + batch + partial failure) -------------------------------

def test_apply_reports_failure_reason_when_sync_disabled(api_client):
    """Sentinel sync is off by default in a fresh test DB -- apply must
    report a clear per-item reason, never a silent/blank success."""
    client, main_mod = api_client
    _seed_admin_user()
    hunt_id = _seed_hunt()
    analytic_id = _seed_analytic(hunt_id=hunt_id, tune_history=_TUNED_HISTORY)
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.post(
        "/api/detections/tuning-suggestions/apply", json={"analytic_ids": [analytic_id]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["success"] is False
    assert "Sentinel sync is off" in result["reason"]


def test_apply_batch_partial_failure_never_blocks_the_whole_batch(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    hunt_id = _seed_hunt()
    eligible_but_disabled = _seed_analytic(hunt_id=hunt_id, tune_history=_TUNED_HISTORY, name="A")
    no_suggestion = _seed_analytic(hunt_id=hunt_id, tune_history=None, name="B")
    not_in_hunt = _seed_analytic(hunt_id=None, tune_history=_TUNED_HISTORY, name="C")
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.post(
        "/api/detections/tuning-suggestions/apply",
        json={"analytic_ids": [eligible_but_disabled, no_suggestion, not_in_hunt]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) == 3
    assert all(r["success"] is False for r in results)
    reasons = {r["analytic_id"]: r["reason"] for r in results}
    assert "Sentinel sync is off" in reasons[eligible_but_disabled]
    assert "no tuning suggestion" in reasons[no_suggestion]
    assert "does not belong to a hunt" in reasons[not_in_hunt]
