"""Tests for get_dashboard_stats()/get_mitre_coverage()'s optional
since/until window (Workstream D, docs/superpowers/specs/2026-09-04-
live-feedback-round-6-design.md)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db as db_module


def _seed_entry(conn, hash_, ingested, severity="Critical", ttps="T1190",
                tags=None, iocs=None):
    conn.execute(
        "INSERT INTO entries (hash, source, ingested, published, triaged, severity, ttps, tags, iocs) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (hash_, "src", ingested, ingested, 1, severity, ttps,
         tags or '{}', iocs or '{}'),
    )


def test_default_no_window_matches_pre_task_behavior(db_conn):
    _seed_entry(db_conn, "hash-old", "2020-01-01 00:00:00")
    _seed_entry(db_conn, "hash-new", "2026-01-01 00:00:00")
    db_conn.commit()

    stats = db_module.get_dashboard_stats()
    assert stats["total"] == 2
    explicit_none = db_module.get_dashboard_stats(since=None, until=None)
    assert stats == explicit_none


def test_window_excluding_all_entries_returns_zero_not_error(db_conn):
    _seed_entry(db_conn, "hash-old", "2020-01-01 00:00:00")
    db_conn.commit()

    stats = db_module.get_dashboard_stats(since="2099-01-01 00:00:00")
    assert stats["total"] == 0
    assert stats["severity"] == []
    assert stats["ttps"] == []


def test_since_and_until_both_scope_the_window(db_conn):
    _seed_entry(db_conn, "hash-jan", "2026-01-15 00:00:00")
    _seed_entry(db_conn, "hash-feb", "2026-02-15 00:00:00")
    _seed_entry(db_conn, "hash-mar", "2026-03-15 00:00:00")
    db_conn.commit()

    stats = db_module.get_dashboard_stats(since="2026-02-01 00:00:00", until="2026-02-28 23:59:59")
    assert stats["total"] == 1


def test_severity_ttp_tag_ioc_breakdowns_all_respect_the_window(db_conn):
    """Not just the top-level totals -- every one of the four breakdown
    dicts must exclude entries outside the window."""
    import json
    _seed_entry(
        db_conn, "hash-outside", "2020-01-01 00:00:00", severity="Critical", ttps="T9999",
        tags=json.dumps({"malware_types": ["OutsideMalware"]}),
        iocs=json.dumps({"cves": ["CVE-2020-0000"]}),
    )
    _seed_entry(
        db_conn, "hash-inside", "2026-01-01 00:00:00", severity="High", ttps="T1234",
        tags=json.dumps({"malware_types": ["InsideMalware"]}),
        iocs=json.dumps({"cves": ["CVE-2026-1111"]}),
    )
    db_conn.commit()

    stats = db_module.get_dashboard_stats(since="2025-01-01 00:00:00")

    assert [s["label"] for s in stats["severity"]] == ["High"]
    assert [t["technique"] for t in stats["ttps"]] == ["T1234"]
    malware_values = [v["value"] for v in stats["tag_distribution"]["malware_types"]]
    assert malware_values == ["InsideMalware"]
    cve_values = [v["value"] for v in stats["ioc_distribution"]["cves"]]
    assert cve_values == ["CVE-2026-1111"]


def test_mitre_coverage_default_matches_pre_task_behavior(db_conn):
    _seed_entry(db_conn, "hash-a", "2026-01-01 00:00:00", ttps="T1053.005")
    db_conn.commit()

    coverage = db_module.get_mitre_coverage()
    assert coverage == db_module.get_mitre_coverage(since=None, until=None)
    assert coverage["T1053.005"] == 1
    assert coverage["T1053"] == 1


def test_mitre_coverage_respects_window(db_conn):
    _seed_entry(db_conn, "hash-old", "2020-01-01 00:00:00", ttps="T1053.005")
    _seed_entry(db_conn, "hash-new", "2026-01-01 00:00:00", ttps="T1059")
    db_conn.commit()

    coverage = db_module.get_mitre_coverage(since="2025-01-01 00:00:00")
    assert "T1053.005" not in coverage
    assert coverage["T1059"] == 1
