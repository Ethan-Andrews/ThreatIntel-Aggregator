"""Tests for db.get_runzero_matches() -- the read query backing
GET /api/integrations/runzero/matches. No prior direct coverage existed
for this function; test_runzero_sync.py only covers the write/correlation
side (run_correlation_pass()).

get_runzero_matches() opens and closes its own connection internally
(doesn't take a conn param), so seed data via the pg_test_conn() helper
and commit before calling it -- same real-Postgres-DSN convention every
other test in this suite uses."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pg_helpers import pg_test_conn
import db


def _seed(conn, hash, title, severity, published, org="FSC", hostname="HOST-001"):
    conn.execute(
        "INSERT INTO runzero_assets (id, org, hostname, alive) VALUES (?, ?, ?, 1)",
        (f"a-{hash}", org, hostname),
    )
    conn.execute(
        "INSERT INTO entries (hash, title, source, severity, published, iocs) "
        "VALUES (?, ?, 'S', ?, ?, '{}')",
        (hash, title, severity, published),
    )
    conn.execute(
        "INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence, match_detail) "
        "VALUES (?, ?, 'cve', 'confirmed', 'detail')",
        (hash, f"a-{hash}"),
    )
    conn.commit()


def test_search_matches_threat_intel_title_not_just_asset_identity():
    conn = pg_test_conn()
    _seed(conn, "h1", "Critical RCE in Widgetsoft VPN", "High", "2026-08-01T00:00:00Z",
          org="Org A", hostname="unrelated-host")
    _seed(conn, "h2", "Unrelated phishing campaign", "Low", "2026-08-01T00:00:00Z",
          org="Org B", hostname="other-host")

    total, matches = db.get_runzero_matches(asset_search="widgetsoft")

    assert total == 1
    assert matches[0]["hash"] == "h1"


def test_search_still_matches_asset_hostname_and_org():
    conn = pg_test_conn()
    _seed(conn, "h1", "Some CVE", "High", "2026-08-01T00:00:00Z", org="Acme Corp")
    _seed(conn, "h2", "Some other CVE", "High", "2026-08-01T00:00:00Z", org="Other Inc")

    total, matches = db.get_runzero_matches(asset_search="acme")
    assert total == 1
    assert matches[0]["hash"] == "h1"


def test_filters_by_severity():
    conn = pg_test_conn()
    _seed(conn, "h1", "Critical one", "Critical", "2026-08-01T00:00:00Z")
    _seed(conn, "h2", "High one", "High", "2026-08-01T00:00:00Z")
    _seed(conn, "h3", "Low one", "Low", "2026-08-01T00:00:00Z")

    total, matches = db.get_runzero_matches(severity=["Critical", "High"])
    assert total == 2
    assert {m["hash"] for m in matches} == {"h1", "h2"}


def test_filters_by_date_range():
    conn = pg_test_conn()
    _seed(conn, "h1", "Old one", "High", "2026-01-01T00:00:00Z")
    _seed(conn, "h2", "Mid one", "High", "2026-06-01T00:00:00Z")
    _seed(conn, "h3", "New one", "High", "2026-12-01T00:00:00Z")

    total, matches = db.get_runzero_matches(date_from="2026-03-01", date_to="2026-09-01")
    assert total == 1
    assert matches[0]["hash"] == "h2"


def test_severity_and_date_filters_combine_with_existing_confidence_filter():
    conn = pg_test_conn()
    _seed(conn, "h1", "Confirmed critical, in range", "Critical", "2026-06-01T00:00:00Z")
    conn.execute(
        "INSERT INTO runzero_assets (id, org, hostname, alive) VALUES ('a-h2', 'FSC', 'HOST-002', 1)"
    )
    conn.execute(
        "INSERT INTO entries (hash, title, source, severity, published, iocs) "
        "VALUES ('h2', 'Possible critical, in range', 'S', 'Critical', '2026-06-01T00:00:00Z', '{}')"
    )
    conn.execute(
        "INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence, match_detail) "
        "VALUES ('h2', 'a-h2', 'software', 'possible', 'detail')"
    )
    conn.commit()

    total, matches = db.get_runzero_matches(
        confidence="confirmed", severity=["Critical"],
        date_from="2026-01-01", date_to="2026-12-31",
    )
    assert total == 1
    assert matches[0]["hash"] == "h1"


# --- kev_only (Workstream G) ------------------------------------------------

def test_kev_only_filters_to_entries_with_kev_flag_set():
    conn = pg_test_conn()
    _seed(conn, "h-kev", "Exploited CVE", "Critical", "2026-08-01T00:00:00Z")
    _seed(conn, "h-not-kev", "Non-KEV CVE", "Critical", "2026-08-01T00:00:00Z")
    conn.execute("UPDATE entries SET kev_flag = 1 WHERE hash = 'h-kev'")
    conn.commit()

    total, matches = db.get_runzero_matches(kev_only=True)
    assert total == 1
    assert matches[0]["hash"] == "h-kev"


def test_kev_only_false_is_the_default_and_unfiltered():
    conn = pg_test_conn()
    _seed(conn, "h-kev", "Exploited CVE", "Critical", "2026-08-01T00:00:00Z")
    _seed(conn, "h-not-kev", "Non-KEV CVE", "Critical", "2026-08-01T00:00:00Z")
    conn.execute("UPDATE entries SET kev_flag = 1 WHERE hash = 'h-kev'")
    conn.commit()

    total, matches = db.get_runzero_matches()
    assert total == 2
