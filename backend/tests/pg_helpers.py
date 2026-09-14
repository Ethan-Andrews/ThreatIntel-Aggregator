"""Postgres helpers for tests that previously built in-memory SQLite schemas.

conftest.py cannot be imported as a module by the test files themselves, so the
shared connection helper lives here and conftest re-exports the fixtures.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import psycopg

BACKEND = Path(__file__).resolve().parent.parent
SCHEMA_PATH = BACKEND / "pg_schema.sql"
DEFAULT_DSN = "postgresql://postgres@127.0.0.1:5433/tiagg_test"

ALL_TABLES = [
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
]


def dsn() -> str:
    return os.environ.get("TEST_PG_DSN") or os.environ.get("PG_DSN") or DEFAULT_DSN


def truncate_all() -> None:
    """Empty every table and reset identity sequences."""
    with psycopg.connect(dsn(), autocommit=True) as conn:
        conn.execute("TRUNCATE " + ", ".join(ALL_TABLES) + " RESTART IDENTITY")


def pg_test_conn():
    """A pooled application connection to a freshly emptied test database.

    Replaces sqlite3.connect(":memory:") plus hand-written partial DDL. Tests now
    run against the same schema pg_schema.sql creates in production, so a column
    the tests forgot to declare can no longer mask a real incompatibility.
    """
    os.environ["PG_DSN"] = dsn()
    truncate_all()
    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))
    import db as db_module

    return db_module._connect_db()


def table_columns(conn, table: str) -> set[str]:
    """Column names for a table. Replaces PRAGMA table_info()."""
    rows = conn.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = ?",
        (table,),
    ).fetchall()
    return {r["column_name"] for r in rows}
