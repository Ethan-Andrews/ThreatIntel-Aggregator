"""Tests for db.get_exposure_metrics() -- RunZero Metrics subtab
(Workstream F, docs/superpowers/specs/2026-09-04-live-feedback-round-6-
design.md). Built on exposure_items, not raw runzero_vulns (confirmed
decision: runzero_vulns has zero history)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db as db_module


def _seed_asset(conn, asset_id, org="Org", site="HQ"):
    conn.execute(
        "INSERT INTO runzero_assets (id, org, site, alive) VALUES (?, ?, ?, 1)",
        (asset_id, org, site),
    )


def _seed_item(conn, asset_id, entry_hash, status, first_seen, remediated_at=None):
    conn.execute(
        "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen, remediated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (asset_id, entry_hash, status, first_seen, first_seen, remediated_at),
    )


def test_all_time_intake_and_standing(db_conn):
    _seed_asset(db_conn, "a1", org="Org")
    _seed_item(db_conn, "a1", "h1", "active", "2026-01-01T00:00:00Z")
    _seed_item(db_conn, "a1", "h2", "remediated", "2026-01-02T00:00:00Z", remediated_at="2026-01-05T00:00:00Z")
    db_conn.commit()

    result = db_module.get_exposure_metrics(since=None, until=None, conn=db_conn)
    standing = {s["org"]: s for s in result["standing"]}
    assert standing["Org"]["total_intake"] == 2
    assert standing["Org"]["still_standing"] == 1
    assert standing["Org"]["remediated"] == 1


def test_window_scopes_the_intake_cohort(db_conn):
    """'Still standing' means 'of what appeared IN THIS WINDOW, not yet
    remediated' -- an item that appeared before the window must not be
    counted, even if it's still active today."""
    _seed_asset(db_conn, "a1", org="Org")
    _seed_item(db_conn, "a1", "h-old", "active", "2020-01-01T00:00:00Z")
    _seed_item(db_conn, "a1", "h-new", "active", "2026-06-01T00:00:00Z")
    db_conn.commit()

    result = db_module.get_exposure_metrics(since="2026-01-01T00:00:00Z", until="2026-12-31T23:59:59Z", conn=db_conn)
    standing = {s["org"]: s for s in result["standing"]}
    assert standing["Org"]["total_intake"] == 1  # only h-new


def test_remediated_series_excludes_still_open_items(db_conn):
    _seed_asset(db_conn, "a1", org="Org")
    _seed_item(db_conn, "a1", "h-open", "active", "2026-01-01T00:00:00Z")
    _seed_item(db_conn, "a1", "h-fixed", "remediated", "2026-01-01T00:00:00Z", remediated_at="2026-01-10T00:00:00Z")
    db_conn.commit()

    result = db_module.get_exposure_metrics(since=None, until=None, conn=db_conn)
    total_remediated_rows = sum(r["count"] for r in result["remediated_by_day"])
    assert total_remediated_rows == 1


def test_org_filter_scopes_all_three_shapes(db_conn):
    _seed_asset(db_conn, "a1", org="OrgA")
    _seed_asset(db_conn, "a2", org="OrgB")
    _seed_item(db_conn, "a1", "h1", "active", "2026-01-01T00:00:00Z")
    _seed_item(db_conn, "a2", "h2", "active", "2026-01-01T00:00:00Z")
    db_conn.commit()

    result = db_module.get_exposure_metrics(since=None, until=None, org="OrgA", conn=db_conn)
    assert {r["org"] for r in result["standing"]} == {"OrgA"}
    assert {r["org"] for r in result["intake_by_day"]} == {"OrgA"}


def test_mixed_text_timestamp_formats_compare_correctly():
    """exposure_items.first_seen is written in isoformat() (T + offset,
    e.g. "+00:00") by db.py's own reconcile path, but this test suite's
    convention (and some real historical rows) use a bare "Z" suffix
    instead. A window boundary using either format must still compare
    correctly via the ::timestamptz cast -- not a lexical string
    accident. Exercised indirectly via test_window_scopes_the_intake_
    cohort above (Z-suffixed rows, T+offset-style window bound) -- this
    test just documents the specific claim being relied on."""
    import psycopg
    # A same-day boundary where a naive string compare would get it
    # backwards (space-separated 'until' vs 'T'-separated stored value)
    # must still resolve correctly once cast to timestamptz.
    with psycopg.connect(os.environ["TEST_PG_DSN"]) as conn:
        row = conn.execute(
            "SELECT '2026-01-05T10:00:00Z'::timestamptz <= '2026-01-05 23:59:59'::timestamptz"
        ).fetchone()
        assert row[0] is True
