"""Shared Postgres fixtures for the backend test suite.

The suite previously pointed db.DB_PATH at a throwaway SQLite file per test and
let init_db() build the schema. Postgres has no equivalent: the schema is owned
by pg_schema.sql and init_db() only verifies it. So instead of a file per test,
this module provisions one test database per session and truncates it between
tests, which is both faster and closer to how the application actually runs.

Point the suite at a server with:

    export TEST_PG_DSN='postgresql://postgres@127.0.0.1:5432/tiagg_test'

If TEST_PG_DSN is unset the whole suite skips rather than failing, so a checkout
without a local Postgres still reports cleanly.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import sys

import pytest

# conftest is loaded before pytest adds the tests directory to sys.path, so make
# the sibling helper module importable for both conftest and the test files.
sys.path.insert(0, str(Path(__file__).resolve().parent))


psycopg = pytest.importorskip("psycopg", reason="psycopg is required for the Postgres suite")

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "pg_schema.sql"

# Root-level migration files not covered by pg_schema.sql. Order matters:
# pg_coverage_ledger_v2.sql ALTERs a table pg_detection_strategies.sql
# creates, and pg_alignment_reviews.sql ALTERs the same table again.
DETECTION_PIPELINE_SCHEMA_PATHS = [
    SCHEMA_PATH.parent.parent / "pg_detection_strategies.sql",
    SCHEMA_PATH.parent.parent / "pg_coverage_ledger_v2.sql",
    SCHEMA_PATH.parent.parent / "pg_coverage_ledger_v3.sql",
    SCHEMA_PATH.parent.parent / "pg_hit_baseline.sql",
    SCHEMA_PATH.parent.parent / "pg_mitre_detection_strategies.sql",
    SCHEMA_PATH.parent.parent / "pg_alignment_reviews.sql",
    SCHEMA_PATH.parent.parent / "pg_analytics_validation_columns.sql",
    SCHEMA_PATH.parent.parent / "pg_disposition_checks.sql",
    SCHEMA_PATH.parent.parent / "pg_detection_pipeline_attempts.sql",
    SCHEMA_PATH.parent.parent / "pg_detection_pipeline_attempts_project_id.sql",
    SCHEMA_PATH.parent.parent / "pg_orchestrator_settings.sql",
    SCHEMA_PATH.parent.parent / "pg_orchestrator_settings_interval.sql",
    SCHEMA_PATH.parent.parent / "pg_sentinel_workspace_tables.sql",
    SCHEMA_PATH.parent.parent / "pg_analytics_name_description.sql",
    SCHEMA_PATH.parent.parent / "pg_hunts.sql",
    SCHEMA_PATH.parent.parent / "pg_hunts_target_sentinel_hunt.sql",
    SCHEMA_PATH.parent.parent / "pg_hunt_sync_settings.sql",
    SCHEMA_PATH.parent.parent / "pg_entries_emitted_at.sql",
    SCHEMA_PATH.parent.parent / "pg_tuning_suggestion_actions.sql",
    SCHEMA_PATH.parent.parent / "pg_sentinel_hunt_inventory.sql",
    SCHEMA_PATH.parent.parent / "pg_analytics_artifact_id_unique.sql",
    SCHEMA_PATH.parent.parent / "pg_sentinel_analytics_rules.sql",
    SCHEMA_PATH.parent.parent / "pg_sentinel_hunt_queries_tune_action.sql",
    SCHEMA_PATH.parent.parent / "pg_sentinel_analytics_rules_tune_action.sql",
    SCHEMA_PATH.parent.parent / "pg_audit_annotations.sql",
    SCHEMA_PATH.parent.parent / "pg_hunt_sync_settings_severity_cadence.sql",
    SCHEMA_PATH.parent.parent / "pg_hunt_sync_settings_auto_deploy_target.sql",
    SCHEMA_PATH.parent.parent / "pg_analytics_hunts_origin.sql",
    # Independent of every table above -- included here even though
    # master's own conftest.py still omits it (see docs/superpowers/
    # handoff-public-release-parity-2026-09-14.md).
    SCHEMA_PATH.parent / "pg_telemetry_baseline.sql",
]

DEFAULT_DSN = "postgresql://postgres@127.0.0.1:5433/tiagg_test"

# Order matters for TRUNCATE only in that all tables are listed; CASCADE is not
# used so an accidental dependency shows up as an error rather than silent data
# loss in a table nobody remembered.
ALL_TABLES = [
    "audit_annotations",
    "exposure_audit_log",
    "exposure_items",
    "feed_fetch_log",
    "runzero_sync_log",
    "runzero_matches",
    "runzero_vulns",
    "runzero_assets",
    "ioc_ledger",
    "users",
    "stack_items",
    "entries",
    "sources",
    "alignment_reviews",
    "mitre_analytics",
    "mitre_detection_strategies",
    "mitre_data_components",
    "hit_baseline",
    "disposition_checks",
    "orchestrator_settings",
    "hunt_sync_settings",
    "sentinel_workspace_tables",
    "detection_pipeline_attempts",
    "coverage_evidence",
    "tuning_suggestion_actions",
    "sentinel_hunt_queries",
    "sentinel_hunts",
    "sentinel_analytics_rules",
    "analytics",
    "hunts",
    "detection_strategies",
]


def _tables_to_truncate(conn) -> list[str]:
    """ALL_TABLES filtered down to tables that actually exist.

    Some ALL_TABLES entries (e.g. alignment_reviews, mitre_detection_strategies)
    come from pg_*.sql files that a later task in the detection-pipeline plan
    has not created yet. TRUNCATE fails outright if any named table is missing,
    so filter first rather than let an unrelated future-table gap break every
    test that uses tmp_db.
    """
    existing = {
        row[0]
        for row in conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
        ).fetchall()
    }
    return [t for t in ALL_TABLES if t in existing]


def _dsn() -> str:
    return os.environ.get("TEST_PG_DSN", DEFAULT_DSN)


def _admin_dsn(dsn: str) -> tuple[str, str]:
    """Split a DSN into (server DSN pointing at 'postgres', target db name)."""
    parts = urlsplit(dsn)
    dbname = parts.path.lstrip("/") or "postgres"
    admin = urlunsplit((parts.scheme, parts.netloc, "/postgres", parts.query, ""))
    return admin, dbname


@pytest.fixture(scope="session", autouse=True)
def pg_database():
    """Create the test database, apply pg_schema.sql, and export PG_DSN."""
    dsn = _dsn()
    admin, dbname = _admin_dsn(dsn)

    try:
        conn = psycopg.connect(admin, autocommit=True, connect_timeout=5)
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"no Postgres server reachable for tests: {exc}")

    with conn:
        exists = conn.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (dbname,)
        ).fetchone()
        if not exists:
            # Identifier cannot be parameterised; dbname comes from our own DSN.
            conn.execute(f'CREATE DATABASE "{dbname}"')

        # The detection-pipeline schema files GRANT to a 'tiapp' role that is
        # provisioned out-of-band on the real Postgres server (see
        # MIGRATION_RUNBOOK.md) and never created by any script in this repo.
        # A fresh local test container has no such role, so create a harmless
        # stand-in here purely so those GRANT statements have something to
        # target — mirrors the CREATE DATABASE fallback just above.
        role_exists = conn.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = 'tiapp'"
        ).fetchone()
        if not role_exists:
            conn.execute("CREATE ROLE tiapp")

    if not SCHEMA_PATH.exists():
        pytest.skip(f"pg_schema.sql not found at {SCHEMA_PATH}")

    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(schema_sql)
        for path in DETECTION_PIPELINE_SCHEMA_PATHS:
            if path.exists():
                conn.execute(path.read_text(encoding="utf-8"))

    # db.py reads PG_DSN at pool-open time, so set it before any import of db.
    os.environ["PG_DSN"] = dsn
    yield dsn

    if "pgcompat" in sys.modules:
        sys.modules["pgcompat"].close_pool()


@pytest.fixture
def tmp_db(pg_database):
    """Empty every table, then hand back the DSN.

    Named tmp_db so the existing tests that request it keep working. The value
    is now a DSN string rather than a filesystem path; tests that used it with
    sqlite3.connect() should call db._connect_db() instead.
    """
    with psycopg.connect(pg_database, autocommit=True) as conn:
        tables = _tables_to_truncate(conn)
        if tables:
            conn.execute("TRUNCATE " + ", ".join(tables) + " RESTART IDENTITY")
    return pg_database


@pytest.fixture
def db_conn(tmp_db):
    """A pooled application connection against a freshly emptied database."""
    import db as db_module

    conn = db_module._connect_db()
    try:
        yield conn
    finally:
        conn.close()
