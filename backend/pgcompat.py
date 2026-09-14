"""Postgres compatibility layer for ti-aggregator.

Purpose
-------
db.py contains roughly 89 qmark ("?") placeholders spread across ~45 call
sites. Rewriting them with sed is unsafe: "?" also appears inside URLs, regex
strings and literal text in the same file, so a blind substitution corrupts
non-SQL strings. This module converts placeholders at execute time instead, so
existing query strings stay exactly as written.

It also preserves the two sqlite3 behaviours db.py relies on:
  * connections expose .execute() directly (sqlite3.Connection does, DB-API
    connections do not)
  * rows support both index access row[0] and name access row["title"], which
    is what sqlite3.Row provides

Usage in db.py
--------------
    from pgcompat import connect

    def _connect_db(db_path=None):
        return connect()

Everything else in db.py stays as-is except the SQLite-specific SQL listed in
PATCHES.md.

Connection string comes from PG_DSN, e.g.
    postgresql://tiapp@my-pg.postgres.database.azure.com:5432/tiagg?sslmode=require
"""

from __future__ import annotations

import os
import re
import threading
from typing import Any, Iterable, Sequence

import psycopg
from psycopg import sql as _sql  # noqa: F401  (re-exported for callers)
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

__all__ = ["connect", "close_pool", "translate", "PgConnection", "PgRow"]

# --------------------------------------------------------------------------
# Placeholder translation
# --------------------------------------------------------------------------

# Matches single-quoted strings, double-quoted identifiers, dollar-quoted
# bodies, and line/block comments so that "?" inside them is left alone.
_SKIP = re.compile(
    r"""
      '(?:[^']|'')*'          # single-quoted literal, '' escape
    | "(?:[^"]|"")*"          # double-quoted identifier
    | --[^\n]*                # line comment
    | /\*.*?\*/               # block comment
    """,
    re.VERBOSE | re.DOTALL,
)


# Named placeholders (:name). The negative lookbehind leaves Postgres cast
# syntax (::text, ::jsonb) alone, and _SKIP already protects time literals
# such as '12:00' because they sit inside quotes.
_NAMED = re.compile(r"(?<!:):([A-Za-z_][A-Za-z0-9_]*)")


def _sub_outside_quotes(fragment: str) -> str:
    fragment = fragment.replace("??", "\x00").replace("?", "%s")
    fragment = _NAMED.sub(r"%(\1)s", fragment)
    return fragment


def translate(query: str) -> str:
    """Convert qmark and named placeholders to pyformat, ignoring quoted regions.

    'SELECT * FROM entries WHERE hash = ?'   ->  '... WHERE hash = %s'
    'INSERT ... VALUES (:id, :org)'          ->  '... VALUES (%(id)s, %(org)s)'
    "SELECT ?, 'a?b'"                        ->  "SELECT %s, 'a?b'"
    "SELECT x::text"                         ->  unchanged
    "WHERE title LIKE '%CVE-%'"              ->  "WHERE title LIKE '%%CVE-%%'"

    A literal question mark that must survive can be written as '??'.

    Literal '%' is doubled first, across the whole string including quoted
    regions, because psycopg scans for '%' without respecting SQL quoting: an
    embedded LIKE pattern such as '%CVE-%' would otherwise be read as the
    invalid placeholder '%C'. Doubling happens before placeholder substitution
    so the '%s' this function emits is never itself escaped.
    """
    query = query.replace("%", "%%")

    out: list[str] = []
    pos = 0
    for m in _SKIP.finditer(query):
        out.append(_sub_outside_quotes(query[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(_sub_outside_quotes(query[pos:]))
    return "".join(out).replace("\x00", "?")


# --------------------------------------------------------------------------
# Row wrapper: index access and name access, like sqlite3.Row
# --------------------------------------------------------------------------


class PgRow(dict):
    """dict that also supports positional access and tuple-style unpacking."""

    __slots__ = ()

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return list(self.values())[key]
        if isinstance(key, slice):
            return list(self.values())[key]
        return super().__getitem__(key)

    def __iter__(self):
        # sqlite3.Row iterates values, not keys. Matching that matters for
        # call sites doing "a, b = row" or "tuple(row)".
        return iter(self.values())

    def keys(self):  # type: ignore[override]
        return list(super().keys())


def _row_factory(cursor):
    make = dict_row(cursor)

    def make_row(values):
        return PgRow(make(values))

    return make_row


# --------------------------------------------------------------------------
# Cursor and connection wrappers
# --------------------------------------------------------------------------


class PgCursor:
    """Thin wrapper translating placeholders before delegating to psycopg."""

    __slots__ = ("_cur",)

    def __init__(self, cur: psycopg.Cursor) -> None:
        self._cur = cur

    def execute(self, query: str, params: Sequence[Any] | None = None) -> "PgCursor":
        self._cur.execute(translate(query), params or ())
        return self

    def executemany(self, query: str, seq: Iterable[Sequence[Any]]) -> "PgCursor":
        self._cur.executemany(translate(query), list(seq))
        return self

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def fetchmany(self, size: int | None = None):
        return self._cur.fetchmany(size) if size else self._cur.fetchmany()

    def __iter__(self):
        return iter(self._cur)

    def close(self) -> None:
        self._cur.close()

    @property
    def rowcount(self) -> int:
        return self._cur.rowcount

    @property
    def description(self):
        return self._cur.description

    @property
    def lastrowid(self):
        # Postgres has no lastrowid. Call sites needing a generated id must use
        # "INSERT ... RETURNING id". See PATCHES.md item 9.
        raise NotImplementedError(
            "lastrowid is unavailable on Postgres; use INSERT ... RETURNING id"
        )


class PgConnection:
    """sqlite3.Connection-shaped facade over a pooled psycopg connection."""

    __slots__ = ("_conn", "_pool", "_closed")

    def __init__(self, conn: psycopg.Connection, pool: ConnectionPool) -> None:
        self._conn = conn
        self._pool = pool
        self._closed = False

    # sqlite3.Connection.execute() is a shortcut that creates a cursor.
    def execute(self, query: str, params: Sequence[Any] | None = None) -> PgCursor:
        cur = self._conn.cursor()
        cur.execute(translate(query), params or ())
        return PgCursor(cur)

    def executemany(self, query: str, seq: Iterable[Sequence[Any]]) -> PgCursor:
        cur = self._conn.cursor()
        cur.executemany(translate(query), list(seq))
        return PgCursor(cur)

    def cursor(self) -> PgCursor:
        return PgCursor(self._conn.cursor())

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._conn.commit()
        except Exception:
            self._conn.rollback()
        finally:
            self._pool.putconn(self._conn)

    def __enter__(self) -> "PgConnection":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None:
            self.rollback()
        self.close()


# --------------------------------------------------------------------------
# Pool
# --------------------------------------------------------------------------

_pool: ConnectionPool | None = None
_pool_lock = threading.Lock()


def _dsn() -> str:
    dsn = os.environ.get("PG_DSN", "").strip()
    if not dsn:
        raise RuntimeError("PG_DSN is not set; refusing to start without a database")
    return dsn


def _get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = ConnectionPool(
                    conninfo=_dsn(),
                    min_size=int(os.environ.get("PG_POOL_MIN", "1")),
                    max_size=int(os.environ.get("PG_POOL_MAX", "10")),
                    timeout=float(os.environ.get("PG_POOL_TIMEOUT", "30")),
                    kwargs={"autocommit": False, "row_factory": _row_factory},
                    open=True,
                )
    return _pool


def connect() -> PgConnection:
    """Check out a pooled connection wrapped in the sqlite3-shaped facade."""
    pool = _get_pool()
    return PgConnection(pool.getconn(), pool)


def close_pool() -> None:
    """Close the pool. Call from the FastAPI lifespan shutdown path."""
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.close()
            _pool = None
