"""Tests for db.get_enrichment_stats(), which backs Settings' "System Info"
panel. Before this file existed, this function had zero test coverage --
which is exactly how a real bug survived: the frontend
(SettingsPanel.js) reads ips_extracted/hashes_extracted/cves_extracted/
last_poll from this endpoint's response, but the function only ever
returned enriched_count/kev_count/pending_count/avg_epss/max_epss/
avg_priority. The panel always rendered "--" for all four fields
regardless of how much real data existed, since the keys it read were
simply never present. Fixed by pulling the per-type counts from
ioc_ledger (which upsert_ioc_ledger() already populates with the exact
ipv4-addr/file/vulnerability type breakdown) and reusing the same
MAX(ingested) query get_dashboard_stats() uses for last_poll."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import db as db_module


def _insert_entry(conn, entry_hash, ingested):
    conn.execute(
        "INSERT INTO entries (hash, source, title, ingested) VALUES (?, ?, ?, ?)",
        (entry_hash, "TestFeed", "Test", ingested),
    )


def _insert_ioc(conn, ioc_type, value, subtype=""):
    conn.execute(
        "INSERT INTO ioc_ledger (type, subtype, value, first_seen, last_seen, entry_hashes) "
        "VALUES (?, ?, ?, '2026-01-01 00:00:00', '2026-01-01 00:00:00', '[]')",
        (ioc_type, subtype, value),
    )


def test_enrichment_stats_reports_zero_extraction_counts_when_ledger_empty(db_conn):
    stats = db_module.get_enrichment_stats()
    assert stats["ips_extracted"] == 0
    assert stats["hashes_extracted"] == 0
    assert stats["cves_extracted"] == 0
    assert stats["last_poll"] is None


def test_enrichment_stats_counts_each_ioc_type_from_the_ledger(db_conn):
    _insert_ioc(db_conn, "ipv4-addr", "203.0.113.9")
    _insert_ioc(db_conn, "ipv4-addr", "203.0.113.10")
    _insert_ioc(db_conn, "file", "a" * 64, subtype="SHA-256")
    _insert_ioc(db_conn, "vulnerability", "CVE-2026-12345")
    # A type System Info doesn't report on must not leak into any of the
    # three counts it does.
    _insert_ioc(db_conn, "domain-name", "evil.example.com")
    db_conn.commit()

    stats = db_module.get_enrichment_stats()
    assert stats["ips_extracted"] == 2
    assert stats["hashes_extracted"] == 1
    assert stats["cves_extracted"] == 1


def test_enrichment_stats_last_poll_is_the_most_recent_ingested_timestamp(db_conn):
    _insert_entry(db_conn, "a" * 64, "2026-01-01 00:00:00")
    _insert_entry(db_conn, "b" * 64, "2026-06-15 12:30:00")
    db_conn.commit()

    stats = db_module.get_enrichment_stats()
    assert stats["last_poll"] == "2026-06-15 12:30:00"
