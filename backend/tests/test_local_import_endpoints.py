"""HTTP-level tests for /api/detections/local-import* -- auth gating and
the endpoint contract. local_import.py's own parsing/import logic has its
own dedicated unit/integration tests (test_local_import.py); this focuses
on the routes themselves, same split as test_audit_log_endpoints.py."""

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
    # local_import.py's _build_ai_client() imports these two lazily at call
    # time (same pattern orchestrator.py's own _build_ai_client() uses) --
    # this stub needs them even though this test file never triggers an
    # actual AI call, since a real import job run through the endpoint
    # below reaches that import unconditionally per file.
    feed_manager_stub._ai_client = None
    feed_manager_stub._ai_configured = lambda: False
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


@pytest.mark.parametrize("method,path", [
    ("get", "/api/detections/local-import/status"),
    ("post", "/api/detections/local-import"),
    ("get", "/api/detections/local-import/jobs/does-not-exist"),
    ("get", "/api/detections/local-import/jobs"),
])
def test_requires_auth(api_client, method, path):
    client, _ = api_client
    if method == "post":
        response = client.post(path, json={})
    else:
        response = client.get(path)
    assert response.status_code == 401


def test_status_reports_not_configured_when_env_var_unset(api_client, monkeypatch):
    client, main_mod = api_client
    monkeypatch.delenv("LOCAL_IMPORT_DIR", raising=False)
    token = _viewer_token(main_mod)
    response = client.get(
        "/api/detections/local-import/status", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is False
    assert "LOCAL_IMPORT_DIR" in body["detail"]


def test_status_reports_configured_with_a_real_root(api_client, monkeypatch, tmp_path):
    client, main_mod = api_client
    monkeypatch.setenv("LOCAL_IMPORT_DIR", str(tmp_path))
    token = _viewer_token(main_mod)
    response = client.get(
        "/api/detections/local-import/status", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is True
    assert body["root"] == str(tmp_path.resolve())


def test_run_import_requires_admin_role(api_client, monkeypatch, tmp_path):
    client, main_mod = api_client
    monkeypatch.setenv("LOCAL_IMPORT_DIR", str(tmp_path))
    token = _viewer_token(main_mod)
    response = client.post(
        "/api/detections/local-import", json={"sub_path": ""},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_run_import_rejects_a_path_that_escapes_the_root(api_client, monkeypatch, tmp_path):
    client, main_mod = api_client
    monkeypatch.setenv("LOCAL_IMPORT_DIR", str(tmp_path))
    token = _admin_token(main_mod)
    response = client.post(
        "/api/detections/local-import", json={"sub_path": "../../etc"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


def test_run_import_starts_a_job_and_jobs_endpoint_reflects_it(api_client, monkeypatch, tmp_path):
    client, main_mod = api_client
    monkeypatch.setenv("LOCAL_IMPORT_DIR", str(tmp_path))
    (tmp_path / "rule.kql").write_text("DeviceProcessEvents | where 1 == 1")
    token = _admin_token(main_mod)

    response = client.post(
        "/api/detections/local-import", json={"sub_path": ""},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    job_id = response.json()["job_id"]
    assert job_id

    # BackgroundTasks runs after the response in a real ASGI server, but
    # TestClient executes it synchronously before returning here -- the
    # job should already be done.
    job_response = client.get(
        f"/api/detections/local-import/jobs/{job_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert job_response.status_code == 200
    job = job_response.json()
    assert job["job_id"] == job_id
    assert job["status"] == "completed"
    assert any(r["path"] == "rule.kql" and r["status"] == "imported" for r in job["results"])

    list_response = client.get(
        "/api/detections/local-import/jobs", headers={"Authorization": f"Bearer {token}"},
    )
    assert list_response.status_code == 200
    assert any(j["job_id"] == job_id for j in list_response.json()["jobs"])


def test_get_unknown_job_id_returns_404(api_client, monkeypatch, tmp_path):
    client, main_mod = api_client
    monkeypatch.setenv("LOCAL_IMPORT_DIR", str(tmp_path))
    token = _viewer_token(main_mod)
    response = client.get(
        "/api/detections/local-import/jobs/does-not-exist",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404
