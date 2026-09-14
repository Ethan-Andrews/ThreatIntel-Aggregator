"""HTTP-level tests for /api/detections/alignment/* -- mirrors
test_auth_db.py's api_client fixture, the only established pattern in this
suite for hitting an authenticated route through TestClient."""

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

    # Unconditional (not "if 'feed_manager' not in sys.modules"): a real
    # feed_manager can already be sitting in sys.modules from an earlier
    # test file in the same pytest session (e.g. any test that triggers
    # alignment_check._sanitize_for_prompt's lazy `from feed_manager import
    # _sanitize_for_llm`). If that guard skips restubbing, main.py's
    # lifespan calls the REAL start_scheduler() on TestClient startup --
    # a live BackgroundScheduler polling real production feed URLs on a
    # loop, which hangs the test run. monkeypatch.setitem so the real
    # module (if any) is restored after this test, not left stubbed for
    # whatever runs next either.
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


def _seed_strategy_and_review(status="pending_review", verdict="diverges"):
    conn = db_module._connect_db()
    row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        ("T1053.005", "Scheduled Task", "Detect scheduled task creation", []),
    ).fetchone()
    strategy_id = row["id"]
    review_row = conn.execute(
        "INSERT INTO alignment_reviews (strategy_id, verdict, ai_reasoning, suggested_kql, status) "
        "VALUES (?, ?, 'test reasoning', ?, ?) RETURNING id",
        (strategy_id, verdict, "DeviceProcessEvents | take 1" if verdict == "diverges" else None, status),
    ).fetchone()
    conn.commit()
    conn.close()
    return strategy_id, review_row["id"]


def test_get_pending_requires_auth(api_client):
    client, _ = api_client
    response = client.get("/api/detections/alignment/pending")
    assert response.status_code == 401


def test_get_pending_returns_seeded_review(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    _seed_strategy_and_review(status="pending_review")
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.get("/api/detections/alignment/pending",
                          headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["technique_id"] == "T1053.005"


def test_get_pending_ready_only_filters_out_rows_with_no_suggested_kql(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    strategy_id, _ = _seed_strategy_and_review(status="pending_review", verdict="diverges")
    # A second review on the same strategy with no suggested_kql -- happens
    # in practice when _write_diverges()'s telemetry/static-gate checks
    # failed and final_kql stayed None.
    conn = db_module._connect_db()
    conn.execute(
        "INSERT INTO alignment_reviews (strategy_id, verdict, ai_reasoning, suggested_kql, status) "
        "VALUES (?, 'diverges', 'no telemetry', NULL, 'pending_review')",
        (strategy_id,),
    )
    conn.commit()
    conn.close()
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    all_response = client.get("/api/detections/alignment/pending",
                              headers={"Authorization": f"Bearer {token}"})
    assert all_response.json()["total"] == 2

    ready_response = client.get("/api/detections/alignment/pending?ready_only=true",
                                headers={"Authorization": f"Bearer {token}"})
    assert ready_response.status_code == 200
    assert ready_response.json()["total"] == 1


def _seed_hunt_with_analytic(strategy_id, hunt_title="BTR Reforged", review_state="approved",
                              name=None, description=None,
                              kql_body="DeviceProcessEvents | take 1"):
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent / "detection_pipeline"))
    import hunts as hunts_module

    conn = db_module._connect_db()
    hunt_id = hunts_module.get_or_create_hunt(conn, "hash-" + str(strategy_id), title=hunt_title)
    row = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, review_state, "
        " name, description, hunt_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
        (strategy_id, "hash-" + str(strategy_id), kql_body, review_state, name, description, hunt_id),
    ).fetchone()
    conn.commit()
    conn.close()
    return hunt_id, row["id"]


def test_get_hunts_requires_auth(api_client):
    client, _ = api_client
    response = client.get("/api/detections/hunts")
    assert response.status_code == 401


def test_get_hunts_returns_hunt_with_rollup(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    strategy_id, _ = _seed_strategy_and_review(status="accepted")
    _seed_hunt_with_analytic(
        strategy_id, hunt_title="BTR Reforged", review_state="approved",
        name="Suspicious Scheduled Task Creation",
        description="Flags schtasks.exe creating a new scheduled task.",
        kql_body="DeviceProcessEvents | where FileName == 'schtasks.exe'",
    )
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.get("/api/detections/hunts",
                          headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["title"] == "BTR Reforged"
    assert item["detection_count"] == 1
    assert item["review_state_counts"] == {"approved": 1}


def test_get_hunt_detail_requires_auth(api_client):
    client, _ = api_client
    response = client.get("/api/detections/hunts/1")
    assert response.status_code == 401


def test_get_hunt_detail_returns_child_detections(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    strategy_id, _ = _seed_strategy_and_review(status="accepted")
    hunt_id, _ = _seed_hunt_with_analytic(
        strategy_id, hunt_title="BTR Reforged",
        name="Suspicious Scheduled Task Creation",
        description="Flags schtasks.exe creating a new scheduled task.",
        kql_body="DeviceProcessEvents | where FileName == 'schtasks.exe'",
    )
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.get(f"/api/detections/hunts/{hunt_id}",
                          headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["title"] == "BTR Reforged"
    assert len(body["detections"]) == 1
    assert body["detections"][0]["name"] == "Suspicious Scheduled Task Creation"
    assert body["detections"][0]["kql_body"] == "DeviceProcessEvents | where FileName == 'schtasks.exe'"


def test_get_hunt_detail_returns_404_for_missing_hunt(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.get("/api/detections/hunts/999999",
                          headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 404


def test_accept_requires_admin_role(api_client):
    client, main_mod = api_client
    db_module.init_db()
    db_module.upsert_user("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")
    _, review_id = _seed_strategy_and_review()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.post(f"/api/detections/alignment/{review_id}/accept",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


def test_accept_registers_analytic(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    strategy_id, review_id = _seed_strategy_and_review()
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.post(f"/api/detections/alignment/{review_id}/accept",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "accepted"

    conn = db_module._connect_db()
    row = conn.execute(
        "SELECT status FROM alignment_reviews WHERE id = ?", (review_id,)
    ).fetchone()
    conn.close()
    assert row["status"] == "accepted"


def test_reject_marks_rejected(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    _, review_id = _seed_strategy_and_review()
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.post(f"/api/detections/alignment/{review_id}/reject",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
