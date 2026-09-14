"""HTTP-level tests for GET/PATCH /api/settings/orchestrator, plus the
orchestrator.run() early-exit guard that reads the same flag. Mirrors
test_alignment_endpoints.py's api_client fixture, the only established
pattern in this suite for hitting an authenticated route through
TestClient."""

import importlib
import os
import sys
import types

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db as db_module
from detection_pipeline import orchestrator, orchestrator_settings


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


def test_get_requires_auth(api_client):
    client, _ = api_client
    response = client.get("/api/settings/orchestrator")
    assert response.status_code == 401


def test_get_requires_admin_role(api_client):
    client, main_mod = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.get("/api/settings/orchestrator",
                          headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


def test_get_defaults_to_disabled_before_any_write(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.get("/api/settings/orchestrator",
                          headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is False
    assert body["updated_by"] is None


def test_patch_disables_and_records_who(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.patch("/api/settings/orchestrator",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"enabled": False})

    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is False
    assert body["updated_by"] == "Admin User"

    # A follow-up GET reflects the same state.
    response = client.get("/api/settings/orchestrator",
                          headers={"Authorization": f"Bearer {token}"})
    assert response.json()["enabled"] is False


def test_patch_requires_admin_role(api_client):
    client, main_mod = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.patch("/api/settings/orchestrator",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"enabled": False})

    assert response.status_code == 403


def test_patch_rejects_non_boolean(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.patch("/api/settings/orchestrator",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"enabled": "not-a-bool"})

    assert response.status_code == 422


def test_set_enabled_then_get_settings_round_trip(tmp_db):
    conn = db_module._connect_db()
    try:
        result = orchestrator_settings.set_enabled(conn, False, "tester")
        assert result["enabled"] is False
        assert result["updated_by"] == "tester"

        fetched = orchestrator_settings.get_settings(conn)
        assert fetched["enabled"] is False
        assert fetched["updated_by"] == "tester"
    finally:
        conn.close()


def test_get_settings_fails_closed_when_row_missing(tmp_db):
    conn = db_module._connect_db()
    try:
        conn.execute("DELETE FROM orchestrator_settings")
        conn.commit()
        settings = orchestrator_settings.get_settings(conn)
        assert settings["enabled"] is False
    finally:
        conn.close()


def test_run_exits_immediately_when_disabled(db_conn):
    """orchestrator.run() must not claim any candidates, build a Sentinel
    client, or call detections.ai when the switch is off -- it should not
    even reach the code that would need DETECTIONS_AI_API_KEY set."""
    orchestrator_settings.set_enabled(db_conn, False, "tester")

    result = orchestrator.run(batch_size=5)

    assert result.claimed == 0
    assert result.generated == 0
    assert result.failed == 0


# ------------------------------------------ PATCH .../orchestrator/schedule

def test_schedule_patch_requires_auth(api_client):
    client, _ = api_client
    response = client.patch("/api/settings/orchestrator/schedule", json={"interval_minutes": 60})
    assert response.status_code == 401


def test_schedule_patch_requires_admin_role(api_client):
    client, main_mod = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")
    response = client.patch(
        "/api/settings/orchestrator/schedule",
        headers={"Authorization": f"Bearer {token}"},
        json={"interval_minutes": 60},
    )
    assert response.status_code == 403


def test_schedule_patch_updates_interval_and_records_who(api_client):
    client, main_mod = api_client
    _seed_admin_user()
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")

    response = client.patch(
        "/api/settings/orchestrator/schedule",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "interval_minutes": 120,
            "window_start_minute": 540,
            "window_end_minute": 1020,
            "days_of_week": [1, 2, 3, 4, 5],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["interval_minutes"] == 120
    assert body["window_start_minute"] == 540
    assert body["window_end_minute"] == 1020
    assert sorted(body["days_of_week"]) == [1, 2, 3, 4, 5]
    assert body["updated_by"] == "Admin User"


@pytest.mark.parametrize("bad_body", [
    {"interval_minutes": 0},                                             # not > 0
    {"interval_minutes": 20000},                                         # exceeds one week
    {"interval_minutes": 60, "window_start_minute": 540},                # start without end
    {"interval_minutes": 60, "window_end_minute": 1020},                 # end without start
    {"interval_minutes": 60, "days_of_week": [7]},                       # out of 0-6 range
    {"interval_minutes": 60, "days_of_week": [-1]},                      # out of 0-6 range
    {"interval_minutes": 60, "window_start_minute": 1500, "window_end_minute": 1020},  # > 1439
])
def test_schedule_patch_rejects_invalid_input(api_client, bad_body):
    client, main_mod = api_client
    _seed_admin_user()
    token = main_mod.create_app_token("admin-oid-1", "admin@example.com", "Admin User", "admin")
    response = client.patch(
        "/api/settings/orchestrator/schedule",
        headers={"Authorization": f"Bearer {token}"},
        json=bad_body,
    )
    assert response.status_code == 422


# ---------------------------------------------------------------- is_due()

import datetime as _dt


def _dt_utc(*args, **kwargs):
    return _dt.datetime(*args, tzinfo=_dt.timezone.utc, **kwargs)


def test_is_due_default_settings_always_due():
    settings = {
        "interval_minutes": 30, "window_start_minute": None, "window_end_minute": None,
        "days_of_week": None, "last_run_at": None,
    }
    due, reason = orchestrator_settings.is_due(settings, _dt_utc(2026, 9, 3, 12, 0))
    assert due is True
    assert reason == ""


def test_is_due_false_when_interval_not_elapsed():
    settings = {
        "interval_minutes": 60, "window_start_minute": None, "window_end_minute": None,
        "days_of_week": None, "last_run_at": _dt_utc(2026, 9, 3, 12, 0),
    }
    due, reason = orchestrator_settings.is_due(settings, _dt_utc(2026, 9, 3, 12, 30))
    assert due is False
    assert "30 of 60 minutes" in reason


def test_is_due_true_once_interval_elapsed():
    settings = {
        "interval_minutes": 60, "window_start_minute": None, "window_end_minute": None,
        "days_of_week": None, "last_run_at": _dt_utc(2026, 9, 3, 12, 0),
    }
    due, reason = orchestrator_settings.is_due(settings, _dt_utc(2026, 9, 3, 13, 0))
    assert due is True


def test_is_due_true_when_last_run_at_is_none_regardless_of_interval():
    settings = {
        "interval_minutes": 1440, "window_start_minute": None, "window_end_minute": None,
        "days_of_week": None, "last_run_at": None,
    }
    due, _ = orchestrator_settings.is_due(settings, _dt_utc(2026, 9, 3, 0, 1))
    assert due is True


def test_is_due_false_outside_window():
    settings = {
        "interval_minutes": 30, "window_start_minute": 9 * 60, "window_end_minute": 17 * 60,
        "days_of_week": None, "last_run_at": None,
    }
    due, reason = orchestrator_settings.is_due(settings, _dt_utc(2026, 9, 3, 20, 0))
    assert due is False
    assert "09:00-17:00" in reason


def test_is_due_true_inside_window():
    settings = {
        "interval_minutes": 30, "window_start_minute": 9 * 60, "window_end_minute": 17 * 60,
        "days_of_week": None, "last_run_at": None,
    }
    due, _ = orchestrator_settings.is_due(settings, _dt_utc(2026, 9, 3, 12, 0))
    assert due is True


def test_is_due_window_spanning_midnight():
    settings = {
        "interval_minutes": 30, "window_start_minute": 22 * 60, "window_end_minute": 2 * 60,
        "days_of_week": None, "last_run_at": None,
    }
    # 23:00 and 01:00 are both inside a 22:00-02:00 window; noon is not.
    assert orchestrator_settings.is_due(settings, _dt_utc(2026, 9, 3, 23, 0))[0] is True
    assert orchestrator_settings.is_due(settings, _dt_utc(2026, 9, 4, 1, 0))[0] is True
    assert orchestrator_settings.is_due(settings, _dt_utc(2026, 9, 3, 12, 0))[0] is False


def test_is_due_false_on_unconfigured_day():
    # 2026-09-03 is a Thursday (pg dow 4); restrict to weekends (0, 6).
    settings = {
        "interval_minutes": 30, "window_start_minute": None, "window_end_minute": None,
        "days_of_week": [0, 6], "last_run_at": None,
    }
    due, reason = orchestrator_settings.is_due(settings, _dt_utc(2026, 9, 3, 12, 0))
    assert due is False
    assert "Thursday" in reason


def test_is_due_true_on_configured_day():
    settings = {
        "interval_minutes": 30, "window_start_minute": None, "window_end_minute": None,
        "days_of_week": [4], "last_run_at": None,  # Thursday
    }
    due, _ = orchestrator_settings.is_due(settings, _dt_utc(2026, 9, 3, 12, 0))
    assert due is True


def test_is_due_empty_days_of_week_means_every_day():
    settings = {
        "interval_minutes": 30, "window_start_minute": None, "window_end_minute": None,
        "days_of_week": [], "last_run_at": None,
    }
    due, _ = orchestrator_settings.is_due(settings, _dt_utc(2026, 9, 3, 12, 0))
    assert due is True


def test_set_interval_then_get_settings_round_trip(tmp_db):
    conn = db_module._connect_db()
    try:
        result = orchestrator_settings.set_interval(
            conn, interval_minutes=120, window_start_minute=540, window_end_minute=1020,
            days_of_week=[1, 2, 3, 4, 5], updated_by="tester",
        )
        assert result["interval_minutes"] == 120
        assert result["window_start_minute"] == 540
        assert result["window_end_minute"] == 1020
        assert sorted(result["days_of_week"]) == [1, 2, 3, 4, 5]

        fetched = orchestrator_settings.get_settings(conn)
        assert fetched["interval_minutes"] == 120
    finally:
        conn.close()


def test_mark_run_started_sets_last_run_at(tmp_db):
    conn = db_module._connect_db()
    try:
        assert orchestrator_settings.get_settings(conn)["last_run_at"] is None
        orchestrator_settings.mark_run_started(conn)
        assert orchestrator_settings.get_settings(conn)["last_run_at"] is not None
    finally:
        conn.close()


def test_run_exits_immediately_when_interval_not_yet_elapsed(db_conn):
    """Same no-candidates/no-Sentinel-client guarantee as the disabled
    switch, but gated on the interval instead."""
    orchestrator_settings.set_interval(
        db_conn, interval_minutes=60, window_start_minute=None,
        window_end_minute=None, days_of_week=None, updated_by="tester",
    )
    orchestrator_settings.mark_run_started(db_conn)  # last_run_at = now()

    result = orchestrator.run(batch_size=5)

    assert result.claimed == 0
    assert result.generated == 0
    assert result.failed == 0
