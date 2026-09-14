import pytest
import sqlite3
import os
import sys
import importlib
import types

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db as db_module

# The local sqlite-era tmp_db fixture that used to live here (an unused
# tmp_path string, no real isolation) has been removed -- conftest.py's
# real tmp_db fixture (Postgres, truncates every table before each test)
# takes over automatically under the same name.


def test_create_users_table_creates_table(db_conn):
    db_module.init_db()
    cur = db_conn.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = current_schema() AND table_name = 'users'"
    )
    assert cur.fetchone() is not None


def test_upsert_user_creates_new_user(db_conn):
    db_module.init_db()
    db_module.upsert_user(
        entra_oid="oid-001",
        email="alice@example.com",
        display_name="Alice",
        role="admin",
    )
    row = db_conn.execute(
        "SELECT entra_oid, role, is_active FROM users WHERE entra_oid='oid-001'"
    ).fetchone()
    # PgRow is a dict subclass -- dict == tuple is always False, unlike
    # sqlite3.Row, which supports sequence-style equality. Compare fields
    # directly instead of relying on tuple equality.
    assert row["entra_oid"] == "oid-001"
    assert row["role"] == "admin"
    assert row["is_active"] == 1


def test_upsert_user_updates_existing_user(db_conn):
    db_module.init_db()
    db_module.upsert_user("oid-001", "a@example.com", "Alice", "viewer")
    db_module.upsert_user("oid-001", "a@example.com", "Alice Updated", "viewer")
    row = db_conn.execute("SELECT count(*) AS n FROM users WHERE entra_oid='oid-001'").fetchone()
    assert row["n"] == 1
    user = db_module.get_user_by_oid("oid-001")
    assert user["display_name"] == "Alice Updated"


def test_get_user_by_oid_returns_none_for_missing(tmp_db):
    db_module.init_db()
    assert db_module.get_user_by_oid("nonexistent") is None


def test_count_active_admins_returns_correct_count(tmp_db):
    db_module.init_db()
    db_module.upsert_user("oid-001", "a@example.com", "Alice", "admin")
    db_module.upsert_user("oid-002", "b@example.com", "Bob", "viewer")
    assert db_module.count_active_admins() == 1


def test_prepare_runtime_db_is_a_noop(tmp_db):
    """prepare_runtime_db() is a deliberate no-op post-Postgres-migration --
    there is no local runtime/persist sqlite file to snapshot or restore
    anymore (see its docstring in db.py). This replaces the old
    test_runtime_db_snapshot_round_trip, which tested the removed sqlite
    snapshot/restore behavior and could never pass against the real
    Postgres-backed db.py."""
    assert db_module.prepare_runtime_db("/tmp/runtime.db", "/tmp/persist.db") is False


def test_update_user_role_changes_role(tmp_db):
    db_module.init_db()
    db_module.upsert_user("oid-001", "a@example.com", "Alice", "viewer")
    db_module.update_user_role("oid-001", "admin")
    user = db_module.get_user_by_oid("oid-001")
    assert user["role"] == "admin"


def test_list_users_returns_all_users(tmp_db):
    db_module.init_db()
    db_module.upsert_user("oid-001", "a@example.com", "Alice", "admin")
    db_module.upsert_user("oid-002", "b@example.com", "Bob", "viewer")
    users = db_module.list_users()
    assert len(users) == 2


def test_upsert_does_not_change_role(tmp_db):
    db_module.init_db()
    # Create as admin
    db_module.upsert_user("oid-001", "a@example.com", "Alice", "admin")
    # Second upsert passes "viewer" — role must NOT change
    db_module.upsert_user("oid-001", "a@example.com", "Alice", "viewer")
    user = db_module.get_user_by_oid("oid-001")
    assert user["role"] == "admin"  # role preserved from first insert


@pytest.fixture
def api_client(tmp_db, monkeypatch):
    """TestClient with app imports isolated from optional runtime dependencies."""
    for mod in [
        "feedparser",
        "anthropic",
        "apscheduler",
        "apscheduler.schedulers",
        "apscheduler.schedulers.background",
    ]:
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
    # Ensure real modules are used, not stubs left by other test modules.
    # auth.py does `from db import DbReadinessError` at its own module level
    # -- if it was already imported earlier in this pytest session (by
    # another test file) while sys.modules["db"] was a stub, its
    # DbReadinessError stays bound to that stub's class object forever,
    # and `except DbReadinessError` in auth.py silently stops matching the
    # real db.DbReadinessError this test raises (a 500 instead of the
    # expected 503). Popping it here forces a fresh import against the
    # real db module set two lines below.
    sys.modules.pop("auth", None)
    sys.modules["db"] = db_module
    sys.modules.pop("enrichment", None)
    main_mod = importlib.import_module("main")

    with TestClient(main_mod.app, raise_server_exceptions=False) as client:
        yield client, main_mod


def test_auth_login_returns_503_when_storage_unavailable(api_client, monkeypatch):
    client, main_mod = api_client

    async def _valid_claims(_token):
        return {
            "oid": "entra-oid-1",
            "email": "user@example.com",
            "preferred_username": "user@example.com",
            "name": "Example User",
        }

    monkeypatch.setattr(main_mod, "validate_entra_token", _valid_claims)
    monkeypatch.setattr(main_mod, "get_user_by_oid", lambda _entra_oid: (_ for _ in ()).throw(db_module.DbReadinessError("storage offline")))

    response = client.post("/api/auth/login", json={"id_token": "valid-token"})

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication unavailable"}


def test_auth_login_returns_503_when_db_is_locked(api_client, monkeypatch):
    client, main_mod = api_client

    async def _valid_claims(_token):
        return {
            "oid": "entra-oid-1",
            "email": "user@example.com",
            "preferred_username": "user@example.com",
            "name": "Example User",
        }

    monkeypatch.setattr(main_mod, "validate_entra_token", _valid_claims)
    monkeypatch.setattr(main_mod, "get_user_by_oid", lambda _entra_oid: None)

    def _raise_locked(*_args, **_kwargs):
        raise Exception("database is locked")

    monkeypatch.setattr(main_mod, "upsert_user", _raise_locked)

    response = client.post("/api/auth/login", json={"id_token": "valid-token"})

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication unavailable"}


def test_require_auth_returns_503_when_storage_unavailable(api_client, monkeypatch):
    client, main_mod = api_client

    token = main_mod.create_app_token("entra-oid-1", "user@example.com", "Example User", "admin")

    def _db_unavailable(_entra_oid):
        raise db_module.DbReadinessError("storage offline")

    monkeypatch.setattr(sys.modules["auth"], "get_user_by_oid", _db_unavailable)

    response = client.get(
        "/api/users",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication unavailable"}


def test_dashboard_stats_uses_severity_for_triaged_and_attempted_unknown_for_failed(tmp_db):
    db_module.init_db()
    conn = db_module._connect_db()
    conn.execute(
        "INSERT INTO entries (hash, source, ingested, published, triaged, severity, ttps) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("hash-sev-triaged", "src", "2026-01-01", "2026-01-01", 0, "Critical", "T1190"),
    )
    conn.execute(
        "INSERT INTO entries (hash, source, ingested, published, triaged, severity, ttps) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("hash-failed", "src", "2026-01-02", "2026-01-02", 1, "Unknown", ""),
    )
    conn.execute(
        "INSERT INTO entries (hash, source, ingested, published, triaged, severity, ttps) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("hash-pending", "src", "2026-01-03", "2026-01-03", 0, "Unknown", ""),
    )
    conn.commit()
    conn.close()

    stats = db_module.get_dashboard_stats()

    assert stats["total"] == 3
    assert stats["triaged"] == 1
    assert stats["pending"] == 2
    assert stats["needs_retriage"] == 1
