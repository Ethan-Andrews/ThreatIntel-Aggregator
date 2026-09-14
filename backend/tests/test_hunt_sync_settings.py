"""HTTP-level tests for GET/PATCH /api/settings/hunt-sync and the manual
POST /api/detections/hunts/{id}/deploy action, plus unit tests for the
settings module and hunts.get_sync_eligible_detections(). Mirrors
test_orchestrator_settings.py's api_client fixture."""

import importlib
import os
import sys
import types

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db as db_module
from detection_pipeline import hunt_sync_settings, hunts


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


def _make_hunt_with_detection(conn, *, static_gate_verdict="pass",
                              backtest_disposition="clean",
                              mitre_alignment_status="aligned"):
    hunt_id = hunts.get_or_create_hunt(
        conn, "entryhash1", title="Test Hunt", description="desc",
        source_title="Some Article", source_link="https://example.com/a",
        source_name="TheHackerNews", source_severity="High",
    )
    strategy_row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, "
        "chokepoint_tables, mitre_alignment_status) VALUES (?, ?, ?, ?, ?) RETURNING id",
        ("T1059", "Command and Scripting Interpreter", "obj", [], mitre_alignment_status),
    ).fetchone()
    strategy_id = strategy_row["id"]
    analytic_row = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, artifact_id, "
        "name, description, hunt_id, static_gate_verdict, backtest_disposition, review_state) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        (strategy_id, "entryhash1", "SecurityEvent | take 1", "art-1",
         "Suspicious Activity", "desc", hunt_id, static_gate_verdict,
         backtest_disposition, "pending"),
    ).fetchone()
    conn.commit()
    return hunt_id, analytic_row["id"]


def test_get_requires_auth(api_client):
    client, _ = api_client
    response = client.get("/api/settings/hunt-sync")
    assert response.status_code == 401


def test_get_requires_admin_role(api_client):
    client, main_mod = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.get("/api/settings/hunt-sync",
                          headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


def test_get_defaults_to_off_before_any_write(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)

    response = client.get("/api/settings/hunt-sync",
                          headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "off"
    assert body["require_alignment"] is True
    assert body["updated_by"] is None


def test_patch_sets_mode_and_records_who(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)

    response = client.patch("/api/settings/hunt-sync",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"mode": "auto", "require_alignment": False})

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "auto"
    assert body["require_alignment"] is False
    assert body["updated_by"] == "Admin User"

    response = client.get("/api/settings/hunt-sync",
                          headers={"Authorization": f"Bearer {token}"})
    assert response.json()["mode"] == "auto"


def test_patch_rejects_invalid_mode(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)

    response = client.patch("/api/settings/hunt-sync",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"mode": "sometimes", "require_alignment": True})

    assert response.status_code == 422


def test_patch_requires_admin_role(api_client):
    client, main_mod = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.patch("/api/settings/hunt-sync",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"mode": "auto", "require_alignment": True})

    assert response.status_code == 403


def test_schedule_patch_requires_admin_role(api_client):
    client, main_mod = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.patch("/api/settings/hunt-sync/schedule",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"interval_minutes": 60})

    assert response.status_code == 403


def test_schedule_patch_sets_severities_and_cadence(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)

    response = client.patch("/api/settings/hunt-sync/schedule",
                            headers={"Authorization": f"Bearer {token}"},
                            json={
                                "severities": ["critical", "high"],
                                "interval_minutes": 60,
                                "window_start_minute": 480,
                                "window_end_minute": 1020,
                                "days_of_week": [1, 2, 3, 4, 5],
                            })

    assert response.status_code == 200
    body = response.json()
    assert sorted(body["severities"]) == ["critical", "high"]
    assert body["interval_minutes"] == 60
    assert body["window_start_minute"] == 480
    assert body["days_of_week"] == [1, 2, 3, 4, 5]
    assert body["updated_by"] == "Admin User"

    fetched = client.get("/api/settings/hunt-sync", headers={"Authorization": f"Bearer {token}"})
    assert fetched.json()["interval_minutes"] == 60


def test_schedule_patch_rejects_unrecognized_severity(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)

    response = client.patch("/api/settings/hunt-sync/schedule",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"severities": ["extreme"], "interval_minutes": 30})

    assert response.status_code == 422


def test_schedule_patch_rejects_window_start_without_end(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)

    response = client.patch("/api/settings/hunt-sync/schedule",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"interval_minutes": 30, "window_start_minute": 480})

    assert response.status_code == 422


def test_schedule_patch_rejects_interval_out_of_bounds(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)

    response = client.patch("/api/settings/hunt-sync/schedule",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"interval_minutes": 0})

    assert response.status_code == 422


def test_auto_deploy_target_patch_requires_admin_role(api_client):
    client, main_mod = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.patch("/api/settings/hunt-sync/auto-deploy-target",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"target_sentinel_hunt_id": "some-guid"})

    assert response.status_code == 403


def test_auto_deploy_target_patch_sets_and_clears(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)

    response = client.patch("/api/settings/hunt-sync/auto-deploy-target",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"target_sentinel_hunt_id": "existing-hunt-guid"})
    assert response.status_code == 200
    body = response.json()
    assert body["auto_deploy_target_sentinel_hunt_id"] == "existing-hunt-guid"
    assert body["updated_by"] == "Admin User"

    fetched = client.get("/api/settings/hunt-sync", headers={"Authorization": f"Bearer {token}"})
    assert fetched.json()["auto_deploy_target_sentinel_hunt_id"] == "existing-hunt-guid"

    # null goes back to "create a new dedicated hunt per TI article".
    cleared = client.patch("/api/settings/hunt-sync/auto-deploy-target",
                           headers={"Authorization": f"Bearer {token}"},
                           json={"target_sentinel_hunt_id": None})
    assert cleared.status_code == 200
    assert cleared.json()["auto_deploy_target_sentinel_hunt_id"] is None


def test_deploy_requires_admin_role(api_client):
    client, main_mod = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.post("/api/detections/hunts/1/deploy",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


def test_deploy_returns_404_for_missing_hunt(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_sync_settings.set_settings(conn, "manual", True, "tester")
    conn.close()

    response = client.post("/api/detections/hunts/9999/deploy",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 404


def test_deploy_rejects_when_mode_is_off(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_id, _ = _make_hunt_with_detection(conn)
    conn.close()

    response = client.post(f"/api/detections/hunts/{hunt_id}/deploy",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 400
    assert "off" in response.json()["detail"].lower()


def test_deploy_rejects_when_no_eligible_detections(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_sync_settings.set_settings(conn, "manual", True, "tester")
    hunt_id, _ = _make_hunt_with_detection(conn, backtest_disposition="needs_tuning")
    conn.close()

    response = client.post(f"/api/detections/hunts/{hunt_id}/deploy",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 400
    assert "passed" in response.json()["detail"].lower()


def test_deploy_endpoint_does_not_500_with_the_real_unmocked_sync_hunt(api_client):
    """Regression test for a real prod incident (2026-08-31): sync_hunt()'s
    internal `import hunts as hunts_module` was a bare import that only
    resolved when detection_pipeline/ itself was on sys.path (true for
    orchestrator.py's own script process, never true for main.py's FastAPI
    process) -- every other deploy test here monkeypatches sync_hunt itself,
    which papers over the bug entirely. This test deliberately calls the
    real, unmocked sync_hunt() through the endpoint (SENTINEL_HUNTING_SYNC_
    ENABLED unset, so it's a no-op past the crashing import line) and
    asserts a clean 200, not the 500 a ModuleNotFoundError there produces."""
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_sync_settings.set_settings(conn, "manual", True, "tester")
    hunt_id, _ = _make_hunt_with_detection(conn)
    conn.close()

    response = client.post(f"/api/detections/hunts/{hunt_id}/deploy",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["sentinel_hunt_id"] is None


def test_deploy_calls_sync_hunt_with_eligible_detections_when_manual(api_client, monkeypatch):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_sync_settings.set_settings(conn, "manual", True, "tester")
    hunt_id, analytic_id = _make_hunt_with_detection(conn, mitre_alignment_status="partial")
    conn.close()

    calls = {}
    def _fake_sync_hunt(conn, hunt_id_arg, *, hunt_title, hunt_description, detections,
                       target_sentinel_hunt_id=None):
        calls["hunt_id"] = hunt_id_arg
        calls["detections"] = detections
    monkeypatch.setattr(main_mod.sentinel_hunting, "sync_hunt", _fake_sync_hunt)

    response = client.post(f"/api/detections/hunts/{hunt_id}/deploy",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert calls["hunt_id"] == hunt_id
    # require_alignment=False for manual deploy -- included even though
    # mitre_alignment_status is 'partial', not 'aligned'.
    assert [d["id"] for d in calls["detections"]] == [analytic_id]


def test_deploy_passes_the_hunts_stored_target_sentinel_hunt_id_through(api_client, monkeypatch):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_sync_settings.set_settings(conn, "manual", True, "tester")
    hunt_id, _ = _make_hunt_with_detection(conn)
    hunts.set_hunt_target(conn, hunt_id, "existing-hunt-guid")
    conn.close()

    calls = {}
    def _fake_sync_hunt(conn, hunt_id_arg, *, hunt_title, hunt_description, detections,
                       target_sentinel_hunt_id=None):
        calls["target_sentinel_hunt_id"] = target_sentinel_hunt_id
    monkeypatch.setattr(main_mod.sentinel_hunting, "sync_hunt", _fake_sync_hunt)

    response = client.post(f"/api/detections/hunts/{hunt_id}/deploy",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert calls["target_sentinel_hunt_id"] == "existing-hunt-guid"


def test_sentinel_targets_requires_admin_role(api_client):
    client, main_mod = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.get("/api/detections/hunts/sentinel-targets",
                          headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


def test_sentinel_targets_returns_list_existing_hunts_result(api_client, monkeypatch):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    monkeypatch.setattr(
        main_mod.sentinel_hunting, "list_existing_hunts",
        lambda: {"enabled": True, "hunts": [{"id": "guid-1", "display_name": "In the News V2"}], "error": None},
    )

    response = client.get("/api/detections/hunts/sentinel-targets",
                          headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json() == {
        "enabled": True,
        "hunts": [{"id": "guid-1", "display_name": "In the News V2"}],
        "error": None,
    }


def test_set_target_requires_admin_role(api_client):
    client, main_mod = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.patch("/api/detections/hunts/1/target",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"target_sentinel_hunt_id": "guid-1"})

    assert response.status_code == 403


def test_set_target_returns_404_for_missing_hunt(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)

    response = client.patch("/api/detections/hunts/9999/target",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"target_sentinel_hunt_id": "guid-1"})

    assert response.status_code == 404


def test_set_target_persists_and_is_reflected_in_the_response(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_id, _ = _make_hunt_with_detection(conn)
    conn.close()

    response = client.patch(f"/api/detections/hunts/{hunt_id}/target",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"target_sentinel_hunt_id": "existing-hunt-guid"})

    assert response.status_code == 200
    assert response.json()["target_sentinel_hunt_id"] == "existing-hunt-guid"

    detail = client.get(f"/api/detections/hunts/{hunt_id}",
                        headers={"Authorization": f"Bearer {token}"})
    assert detail.json()["target_sentinel_hunt_id"] == "existing-hunt-guid"


def test_set_target_null_clears_a_previously_set_target(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_id, _ = _make_hunt_with_detection(conn)
    hunts.set_hunt_target(conn, hunt_id, "existing-hunt-guid")
    conn.close()

    response = client.patch(f"/api/detections/hunts/{hunt_id}/target",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"target_sentinel_hunt_id": None})

    assert response.status_code == 200
    assert response.json()["target_sentinel_hunt_id"] is None


def test_deploy_all_requires_admin_role(api_client):
    client, main_mod = api_client
    _seed_viewer_user()
    token = main_mod.create_app_token("viewer-oid-1", "viewer@example.com", "Viewer User", "viewer")

    response = client.post("/api/detections/hunts/deploy-all",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


def test_deploy_all_rejects_when_mode_is_off(api_client):
    client, main_mod = api_client
    token = _admin_token(main_mod)

    response = client.post("/api/detections/hunts/deploy-all",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 400
    assert "off" in response.json()["detail"].lower()


def test_deploy_all_calls_deploy_all_hunts_when_manual(api_client, monkeypatch):
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_sync_settings.set_settings(conn, "manual", True, "tester")
    conn.close()

    called = {}
    def _fake_deploy_all_hunts(conn_arg):
        called["ran"] = True
        return {"enabled": True, "total": 2, "succeeded": 1,
                "failed": [{"hunt_id": 7, "reason": "500 Internal Server Error"}]}
    monkeypatch.setattr(main_mod.sentinel_hunting, "deploy_all_hunts", _fake_deploy_all_hunts)

    response = client.post("/api/detections/hunts/deploy-all",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert called["ran"]
    body = response.json()
    assert body["total"] == 2
    assert body["succeeded"] == 1
    assert body["failed"] == [{"hunt_id": 7, "reason": "500 Internal Server Error"}]


def test_deploy_all_endpoint_does_not_500_with_the_real_unmocked_deploy_all_hunts(api_client):
    """Same regression class as test_deploy_endpoint_does_not_500_with_the_
    real_unmocked_sync_hunt above -- calls the real, unmocked
    deploy_all_hunts() (SENTINEL_HUNTING_SYNC_ENABLED unset, so it's a
    no-op) and asserts a clean 200/enabled:false rather than a 500 from an
    import that only resolves under orchestrator.py's own process."""
    client, main_mod = api_client
    token = _admin_token(main_mod)
    conn = db_module._connect_db()
    hunt_sync_settings.set_settings(conn, "manual", True, "tester")
    _make_hunt_with_detection(conn)
    conn.close()

    response = client.post("/api/detections/hunts/deploy-all",
                           headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json() == {"enabled": False, "total": 0, "succeeded": 0, "failed": []}


def test_get_sync_eligible_detections_requires_gate_pass_and_clean_backtest(tmp_db):
    conn = db_module._connect_db()
    try:
        hunt_id, analytic_id = _make_hunt_with_detection(conn)
        eligible = hunts.get_sync_eligible_detections(conn, hunt_id, require_alignment=False)
        assert [d["id"] for d in eligible] == [analytic_id]
    finally:
        conn.close()


def test_get_sync_eligible_detections_excludes_failed_gate(tmp_db):
    conn = db_module._connect_db()
    try:
        hunt_id, _ = _make_hunt_with_detection(conn, static_gate_verdict="reject")
        eligible = hunts.get_sync_eligible_detections(conn, hunt_id, require_alignment=False)
        assert eligible == []
    finally:
        conn.close()


def test_get_sync_eligible_detections_excludes_dirty_backtest(tmp_db):
    conn = db_module._connect_db()
    try:
        hunt_id, _ = _make_hunt_with_detection(conn, backtest_disposition="tunable")
        eligible = hunts.get_sync_eligible_detections(conn, hunt_id, require_alignment=False)
        assert eligible == []
    finally:
        conn.close()


def test_get_sync_eligible_detections_require_alignment_excludes_unaligned(tmp_db):
    conn = db_module._connect_db()
    try:
        hunt_id, _ = _make_hunt_with_detection(conn, mitre_alignment_status="partial")
        eligible = hunts.get_sync_eligible_detections(conn, hunt_id, require_alignment=True)
        assert eligible == []
    finally:
        conn.close()


def test_get_sync_eligible_detections_require_alignment_includes_aligned(tmp_db):
    conn = db_module._connect_db()
    try:
        hunt_id, analytic_id = _make_hunt_with_detection(conn, mitre_alignment_status="aligned")
        eligible = hunts.get_sync_eligible_detections(conn, hunt_id, require_alignment=True)
        assert [d["id"] for d in eligible] == [analytic_id]
    finally:
        conn.close()


# --- Workstream A: dedup by artifact_id ------------------------------------
# docs/superpowers/specs/2026-09-04-live-feedback-round-6-design.md.
# Confirmed live 2026-09-04 against prod hunt_id=12: two artifact_ids, three
# analytics rows each (one per orchestrator run, ~24-30 min apart,
# 2026-08-21, predating register_analytic()'s artifact_id idempotency fix),
# all static_gate_verdict='pass'/backtest_disposition='clean' -- every one
# was eligible under the old query, so all three got synced to Sentinel as
# three separate ARM saved searches with the identical display_name.

def _seed_duplicate_analytics(conn, hunt_id, strategy_id, artifact_id, name, count=3):
    """Mirrors the real prod shape: `count` analytics rows sharing one
    artifact_id, distinct ids, otherwise-eligible.

    pg_analytics_artifact_id_unique.sql's own comment explains it was
    deliberately never applied against prod's existing duplicates -- this
    local test schema applies every tracked migration fresh, though, so
    the unique index IS present here even though prod's real, current
    state (confirmed live 2026-09-04, see the design doc) has none. Drop
    it for this test only, to faithfully reproduce the actual prod
    condition this fix targets rather than a schema state that doesn't
    match reality."""
    conn.execute("DROP INDEX IF EXISTS uq_analytics_artifact_id")
    ids = []
    for i in range(count):
        row = conn.execute(
            "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, artifact_id, "
            "name, description, hunt_id, static_gate_verdict, backtest_disposition, review_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'pass', 'clean', 'pending') RETURNING id",
            (strategy_id, f"entryhash-{artifact_id}-{i}", "SecurityEvent | take 1",
             artifact_id, name, "desc", hunt_id),
        ).fetchone()
        ids.append(row["id"])
    conn.commit()
    return ids


def _restore_artifact_id_unique_index(conn, *artifact_ids):
    """Undo _seed_duplicate_analytics'/a test's own DROP INDEX.

    pg_database applies pg_analytics_artifact_id_unique.sql exactly once
    per pytest session (it's a session-scoped fixture) against a Postgres
    test database that persists across separate `pytest` invocations --
    only the tracked tables get TRUNCATEd between tests, the database
    itself is reused if it already exists. A test that drops the index to
    seed duplicate artifact_ids (reproducing the real prod condition this
    fix targets) must put it back before returning, or the *next* `pytest`
    process's session-setup CREATE UNIQUE INDEX IF NOT EXISTS fails with
    the exact UniqueViolation this fix resolves, against leftover dirty
    data nothing ever cleaned up. Delete the duplicate rows first -- the
    CREATE fails the same way if any survive.
    """
    if artifact_ids:
        placeholders = ", ".join(["?"] * len(artifact_ids))
        conn.execute(f"DELETE FROM analytics WHERE artifact_id IN ({placeholders})", artifact_ids)
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_analytics_artifact_id "
        "ON analytics (artifact_id) WHERE artifact_id IS NOT NULL AND artifact_id != ''"
    )
    conn.commit()


def test_get_sync_eligible_detections_dedups_by_artifact_id_keeping_lowest_id(tmp_db):
    """The exact confirmed-live shape: three analytics rows sharing one
    artifact_id must collapse to just the earliest (lowest id)."""
    conn = db_module._connect_db()
    try:
        hunt_id, _ = _make_hunt_with_detection(conn)
        strategy_row = conn.execute(
            "SELECT strategy_id FROM analytics WHERE hunt_id = ?", (hunt_id,)
        ).fetchone()
        ids = _seed_duplicate_analytics(
            conn, hunt_id, strategy_row["strategy_id"], "dup-artifact-1",
            "RingCentral Email Spoofing Bypass via Whitelisting",
        )
        try:
            eligible = hunts.get_sync_eligible_detections(conn, hunt_id, require_alignment=False)
            matching = [d for d in eligible if d["id"] in ids]
            assert len(matching) == 1, "three rows sharing one artifact_id must collapse to one"
            assert matching[0]["id"] == min(ids), "must keep the lowest (earliest-registered) id"
        finally:
            _restore_artifact_id_unique_index(conn, "dup-artifact-1")
    finally:
        conn.close()


def test_get_sync_eligible_detections_dedups_null_named_duplicates_too(tmp_db):
    """The second confirmed-live group: name=NULL rows (the screenshot's
    'Email Collection' fallback-to-technique_name case) must dedup the
    same way name-having rows do."""
    conn = db_module._connect_db()
    try:
        hunt_id, _ = _make_hunt_with_detection(conn)
        strategy_row = conn.execute(
            "SELECT strategy_id FROM analytics WHERE hunt_id = ?", (hunt_id,)
        ).fetchone()
        ids = _seed_duplicate_analytics(
            conn, hunt_id, strategy_row["strategy_id"], "dup-artifact-2", None,
        )
        try:
            eligible = hunts.get_sync_eligible_detections(conn, hunt_id, require_alignment=False)
            matching = [d for d in eligible if d["id"] in ids]
            assert len(matching) == 1
            assert matching[0]["id"] == min(ids)
        finally:
            _restore_artifact_id_unique_index(conn, "dup-artifact-2")
    finally:
        conn.close()


def test_get_sync_eligible_detections_does_not_dedup_rows_with_no_artifact_id(tmp_db):
    """The regression this fix must NOT introduce: a naive `DISTINCT ON
    (a.artifact_id)` collapses every NULL-artifact_id row down to a single
    survivor in Postgres (NULL is treated as equal to NULL for grouping,
    unlike a `=` comparison or a unique index) -- confirmed directly
    against this schema before shipping. Legitimate detections that
    pre-date artifact_id tracking (or whose caller passed none) must all
    survive, not just the first one under a hunt."""
    conn = db_module._connect_db()
    try:
        hunt_id, first_id = _make_hunt_with_detection(conn)
        # _make_hunt_with_detection's own row already has artifact_id='art-1'
        # (not null) -- add three more with NULL artifact_id explicitly.
        strategy_row = conn.execute(
            "SELECT strategy_id FROM analytics WHERE hunt_id = ?", (hunt_id,)
        ).fetchone()
        null_ids = []
        for i in range(3):
            row = conn.execute(
                "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, artifact_id, "
                "name, description, hunt_id, static_gate_verdict, backtest_disposition, review_state) "
                "VALUES (?, ?, ?, NULL, ?, ?, ?, 'pass', 'clean', 'pending') RETURNING id",
                (strategy_row["strategy_id"], f"entryhash-null-{i}", "SecurityEvent | take 1",
                 f"Distinct Detection {i}", "desc", hunt_id),
            ).fetchone()
            null_ids.append(row["id"])
        conn.commit()

        eligible = hunts.get_sync_eligible_detections(conn, hunt_id, require_alignment=False)
        eligible_ids = {d["id"] for d in eligible}
        assert set(null_ids).issubset(eligible_ids), \
            "every NULL-artifact_id row must survive -- none may be deduped away"
        assert first_id in eligible_ids
        assert len(eligible) == 1 + len(null_ids)
    finally:
        conn.close()


def test_get_sync_eligible_detections_does_not_dedup_rows_with_empty_artifact_id(tmp_db):
    """Same guarantee for an empty-string artifact_id (a distinct historical
    caller convention from NULL, per pg_analytics_artifact_id_unique.sql's
    own WHERE clause) -- must not collapse against each other either."""
    conn = db_module._connect_db()
    try:
        hunt_id, first_id = _make_hunt_with_detection(conn)
        strategy_row = conn.execute(
            "SELECT strategy_id FROM analytics WHERE hunt_id = ?", (hunt_id,)
        ).fetchone()
        empty_ids = []
        for i in range(2):
            row = conn.execute(
                "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, artifact_id, "
                "name, description, hunt_id, static_gate_verdict, backtest_disposition, review_state) "
                "VALUES (?, ?, ?, '', ?, ?, ?, 'pass', 'clean', 'pending') RETURNING id",
                (strategy_row["strategy_id"], f"entryhash-empty-{i}", "SecurityEvent | take 1",
                 f"Empty Artifact Detection {i}", "desc", hunt_id),
            ).fetchone()
            empty_ids.append(row["id"])
        conn.commit()

        eligible = hunts.get_sync_eligible_detections(conn, hunt_id, require_alignment=False)
        eligible_ids = {d["id"] for d in eligible}
        assert set(empty_ids).issubset(eligible_ids)
        assert first_id in eligible_ids
    finally:
        conn.close()


def test_get_sync_eligible_detections_dedup_composes_with_eligibility_filters(tmp_db):
    """A duplicate whose OTHER copies are ineligible (failed gate/dirty
    backtest) must not suppress the one eligible copy, and vice versa --
    the dedup and the eligibility WHERE clause must compose correctly,
    not interact in either direction."""
    conn = db_module._connect_db()
    try:
        hunt_id, _ = _make_hunt_with_detection(conn)
        conn.execute("DROP INDEX IF EXISTS uq_analytics_artifact_id")
        strategy_row = conn.execute(
            "SELECT strategy_id FROM analytics WHERE hunt_id = ?", (hunt_id,)
        ).fetchone()
        # One eligible, one ineligible copy of the same artifact_id.
        eligible_row = conn.execute(
            "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, artifact_id, "
            "name, description, hunt_id, static_gate_verdict, backtest_disposition, review_state) "
            "VALUES (?, ?, ?, 'mixed-eligibility', ?, ?, ?, 'pass', 'clean', 'pending') RETURNING id",
            (strategy_row["strategy_id"], "entryhash-mixed-1", "SecurityEvent | take 1",
             "Mixed Eligibility Detection", "desc", hunt_id),
        ).fetchone()
        conn.execute(
            "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, artifact_id, "
            "name, description, hunt_id, static_gate_verdict, backtest_disposition, review_state) "
            "VALUES (?, ?, ?, 'mixed-eligibility', ?, ?, ?, 'reject', NULL, 'rejected')",
            (strategy_row["strategy_id"], "entryhash-mixed-2", "SecurityEvent | take 1",
             "Mixed Eligibility Detection", "desc", hunt_id),
        )
        conn.commit()

        try:
            eligible = hunts.get_sync_eligible_detections(conn, hunt_id, require_alignment=False)
            matching = [d for d in eligible if d["id"] == eligible_row["id"]]
            assert len(matching) == 1, "the one eligible copy must survive despite a duplicate reject"
        finally:
            _restore_artifact_id_unique_index(conn, "mixed-eligibility")
    finally:
        conn.close()


def test_set_settings_then_get_settings_round_trip(tmp_db):
    conn = db_module._connect_db()
    try:
        result = hunt_sync_settings.set_settings(conn, "auto", False, "tester")
        assert result["mode"] == "auto"
        assert result["require_alignment"] is False
        assert result["updated_by"] == "tester"

        fetched = hunt_sync_settings.get_settings(conn)
        assert fetched["mode"] == "auto"
        assert fetched["require_alignment"] is False
    finally:
        conn.close()


def test_set_settings_rejects_invalid_mode(tmp_db):
    conn = db_module._connect_db()
    try:
        with pytest.raises(ValueError):
            hunt_sync_settings.set_settings(conn, "sometimes", True, "tester")
    finally:
        conn.close()


def test_get_settings_fails_open_to_off_when_row_missing(tmp_db):
    conn = db_module._connect_db()
    try:
        conn.execute("DELETE FROM hunt_sync_settings")
        conn.commit()
        settings = hunt_sync_settings.get_settings(conn)
        assert settings["mode"] == "off"
        assert settings["require_alignment"] is True
        assert settings["severities"] is None
        assert settings["interval_minutes"] == 30
    finally:
        conn.close()


# --- set_schedule() / mark_run_started() (Workstream E) --------------------

def test_set_schedule_round_trip(tmp_db):
    conn = db_module._connect_db()
    try:
        result = hunt_sync_settings.set_schedule(
            conn, severities=["critical", "high"], interval_minutes=60,
            window_start_minute=480, window_end_minute=1020,
            days_of_week=[1, 2, 3, 4, 5], updated_by="tester",
        )
        assert sorted(result["severities"]) == ["critical", "high"]
        assert result["interval_minutes"] == 60
        assert result["window_start_minute"] == 480
        assert result["window_end_minute"] == 1020
        assert sorted(result["days_of_week"]) == [1, 2, 3, 4, 5]
        assert result["updated_by"] == "tester"

        fetched = hunt_sync_settings.get_settings(conn)
        assert fetched["interval_minutes"] == 60
    finally:
        conn.close()


def test_set_schedule_rejects_unrecognized_severity(tmp_db):
    conn = db_module._connect_db()
    try:
        with pytest.raises(ValueError, match="severities"):
            hunt_sync_settings.set_schedule(
                conn, severities=["extreme"], interval_minutes=30,
                window_start_minute=None, window_end_minute=None,
                days_of_week=None, updated_by="tester",
            )
    finally:
        conn.close()


def test_set_schedule_does_not_touch_mode_or_require_alignment(tmp_db):
    """set_schedule() and set_settings() write disjoint column sets --
    calling one must not silently reset the other's fields."""
    conn = db_module._connect_db()
    try:
        hunt_sync_settings.set_settings(conn, "auto", False, "tester")
        hunt_sync_settings.set_schedule(
            conn, severities=["low"], interval_minutes=45,
            window_start_minute=None, window_end_minute=None,
            days_of_week=None, updated_by="tester",
        )
        settings = hunt_sync_settings.get_settings(conn)
        assert settings["mode"] == "auto"
        assert settings["require_alignment"] is False
        assert settings["severities"] == ["low"]
    finally:
        conn.close()


def test_mark_run_started_sets_last_run_at(tmp_db):
    conn = db_module._connect_db()
    try:
        assert hunt_sync_settings.get_settings(conn)["last_run_at"] is None
        hunt_sync_settings.mark_run_started(conn)
        assert hunt_sync_settings.get_settings(conn)["last_run_at"] is not None
    finally:
        conn.close()


# --- set_auto_deploy_target() (2026-09-04, post-round-6 follow-up) --------

def test_get_settings_defaults_auto_deploy_target_to_none(tmp_db):
    conn = db_module._connect_db()
    try:
        assert hunt_sync_settings.get_settings(conn)["auto_deploy_target_sentinel_hunt_id"] is None
    finally:
        conn.close()


def test_set_auto_deploy_target_round_trip(tmp_db):
    conn = db_module._connect_db()
    try:
        result = hunt_sync_settings.set_auto_deploy_target(conn, "hunt-guid-1", "tester")
        assert result["auto_deploy_target_sentinel_hunt_id"] == "hunt-guid-1"
        assert result["updated_by"] == "tester"

        fetched = hunt_sync_settings.get_settings(conn)
        assert fetched["auto_deploy_target_sentinel_hunt_id"] == "hunt-guid-1"
    finally:
        conn.close()


def test_set_auto_deploy_target_none_clears_it(tmp_db):
    conn = db_module._connect_db()
    try:
        hunt_sync_settings.set_auto_deploy_target(conn, "hunt-guid-1", "tester")
        result = hunt_sync_settings.set_auto_deploy_target(conn, None, "tester")
        assert result["auto_deploy_target_sentinel_hunt_id"] is None
    finally:
        conn.close()


def test_set_auto_deploy_target_does_not_touch_mode_or_schedule(tmp_db):
    """Disjoint column set from set_settings()/set_schedule() -- same
    invariant test_set_schedule_does_not_touch_mode_or_require_alignment
    already establishes for that pair."""
    conn = db_module._connect_db()
    try:
        hunt_sync_settings.set_settings(conn, "auto", False, "tester")
        hunt_sync_settings.set_schedule(
            conn, severities=["low"], interval_minutes=45,
            window_start_minute=None, window_end_minute=None,
            days_of_week=None, updated_by="tester",
        )
        hunt_sync_settings.set_auto_deploy_target(conn, "hunt-guid-1", "tester")

        settings = hunt_sync_settings.get_settings(conn)
        assert settings["mode"] == "auto"
        assert settings["require_alignment"] is False
        assert settings["severities"] == ["low"]
        assert settings["interval_minutes"] == 45
        assert settings["auto_deploy_target_sentinel_hunt_id"] == "hunt-guid-1"
    finally:
        conn.close()
