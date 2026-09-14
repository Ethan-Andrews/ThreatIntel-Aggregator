import os
import sys
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import db as db_module


@pytest.fixture
def fresh_db(db_conn):
    """Alias for conftest's db_conn (which truncates via tmp_db) — see
    test_ioc_admin.py for why. Returns the real pooled connection, not a
    path, since two tests below need to seed the entries table directly."""
    return db_conn


def test_upsert_creates_ip_row(fresh_db):
    iocs = {"ips": ["1.2.3.4"], "domains": [], "urls": [], "hashes": [], "cves": [], "threat_actors": []}
    db_module.upsert_ioc_ledger(iocs, "hash1", "2026-06-09T10:00:00Z")
    rows = db_module.get_iocs()
    assert len(rows) == 1
    assert rows[0]["type"] == "ipv4-addr"
    assert rows[0]["value"] == "1.2.3.4"
    assert rows[0]["occurrence_count"] == 1
    assert rows[0]["subtype"] == ""


def test_upsert_deduplicates(fresh_db):
    iocs = {"ips": ["1.2.3.4"], "domains": [], "urls": [], "hashes": [], "cves": [], "threat_actors": []}
    db_module.upsert_ioc_ledger(iocs, "hash1", "2026-06-09T10:00:00Z")
    db_module.upsert_ioc_ledger(iocs, "hash2", "2026-06-09T11:00:00Z")
    rows = db_module.get_iocs()
    assert len(rows) == 1
    assert rows[0]["occurrence_count"] == 2
    assert rows[0]["entry_count"] == 2


def test_upsert_hash_sets_subtype(fresh_db):
    sha256 = "a" * 64
    iocs = {"ips": [], "domains": [], "urls": [], "hashes": [sha256], "cves": [], "threat_actors": []}
    db_module.upsert_ioc_ledger(iocs, "hash1", "2026-06-09T10:00:00Z")
    rows = db_module.get_iocs()
    assert len(rows) == 1
    assert rows[0]["type"] == "file"
    assert rows[0]["subtype"] == "SHA-256"


def test_upsert_all_types(fresh_db):
    iocs = {
        "ips": ["1.2.3.4"],
        "domains": ["evil.com"],
        "urls": ["http://evil.com/p"],
        "hashes": ["b" * 64],
        "cves": ["CVE-2024-1234"],
        "threat_actors": ["APT28"],
    }
    db_module.upsert_ioc_ledger(iocs, "hash1", "2026-06-09T10:00:00Z")
    rows = db_module.get_iocs()
    types = {r["type"] for r in rows}
    assert types == {"ipv4-addr", "domain-name", "url", "file", "vulnerability", "threat-actor"}


def test_get_iocs_type_filter(fresh_db):
    iocs = {"ips": ["1.2.3.4"], "domains": ["evil.com"], "urls": [], "hashes": [], "cves": [], "threat_actors": []}
    db_module.upsert_ioc_ledger(iocs, "hash1", "2026-06-09T10:00:00Z")
    rows = db_module.get_iocs(type_filter="ipv4-addr")
    assert len(rows) == 1
    assert rows[0]["type"] == "ipv4-addr"


def test_get_iocs_search(fresh_db):
    iocs = {"ips": ["1.2.3.4", "5.6.7.8"], "domains": [], "urls": [], "hashes": [], "cves": [], "threat_actors": []}
    db_module.upsert_ioc_ledger(iocs, "hash1", "2026-06-09T10:00:00Z")
    rows = db_module.get_iocs(search="1.2.3")
    assert len(rows) == 1
    assert rows[0]["value"] == "1.2.3.4"


def test_get_ioc_entries_returns_correlated(fresh_db):
    fresh_db.execute(
        "INSERT INTO entries (hash, source, title, link, published, summary, iocs, triaged) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
        ("hash1", "TestSource", "Test Title", "", "2026-06-09T10:00:00Z", "summary", '{"ips":["1.2.3.4"]}'),
    )
    fresh_db.commit()
    iocs = {"ips": ["1.2.3.4"], "domains": [], "urls": [], "hashes": [], "cves": [], "threat_actors": []}
    db_module.upsert_ioc_ledger(iocs, "hash1", "2026-06-09T10:00:00Z")
    rows = db_module.get_iocs()
    ioc_id = rows[0]["id"]
    entries = db_module.get_ioc_entries(ioc_id)
    assert len(entries) == 1
    assert entries[0]["hash"] == "hash1"


def test_upsert_idempotent_same_hash(fresh_db):
    iocs = {"ips": ["9.9.9.9"], "domains": [], "urls": [], "hashes": [], "cves": [], "threat_actors": []}
    db_module.upsert_ioc_ledger(iocs, "same_hash", "2026-06-10T10:00:00Z")
    db_module.upsert_ioc_ledger(iocs, "same_hash", "2026-06-10T11:00:00Z")
    rows = db_module.get_iocs()
    assert len(rows) == 1
    assert rows[0]["occurrence_count"] == 1
    assert rows[0]["entry_count"] == 1


def test_run_ioc_backfill_populates_ledger(fresh_db):
    fresh_db.execute(
        "INSERT INTO entries (hash, source, title, link, published, summary, iocs, triaged) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
        ("hash1", "S", "T", "", "2026-06-09T10:00:00Z", "s",
         '{"ips":["9.8.7.6"],"domains":[],"urls":[],"hashes":[],"cves":[],"threat_actors":[]}'),
    )
    fresh_db.commit()
    db_module.run_ioc_backfill()
    rows = db_module.get_iocs()
    assert len(rows) == 1
    assert rows[0]["value"] == "9.8.7.6"
