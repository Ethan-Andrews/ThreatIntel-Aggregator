import os
import sys
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import db as db_module


@pytest.fixture
def fresh_db(tmp_db):
    """Alias for conftest's tmp_db — every db_module call in this file uses
    the pooled connection directly (no conn param), so truncating via tmp_db
    is what actually isolates tests; the previous local fixture built an
    unused sqlite file and never touched the real Postgres test DB, letting
    data leak between tests in this file."""
    return tmp_db


def _seed_two(fresh_db):
    """Insert an IOC with 2 entry associations."""
    iocs = {"ips": ["1.2.3.4"], "domains": [], "urls": [], "hashes": [], "cves": [], "threat_actors": []}
    db_module.upsert_ioc_ledger(iocs, "aaa", "2026-06-10T10:00:00Z")
    db_module.upsert_ioc_ledger(iocs, "bbb", "2026-06-10T11:00:00Z")
    return db_module.get_iocs()[0]


def test_delete_ioc_removes_row(fresh_db):
    _seed_two(fresh_db)
    ioc_id = db_module.get_iocs()[0]["id"]
    result = db_module.delete_ioc(ioc_id)
    assert result is True
    assert db_module.get_iocs() == []


def test_delete_ioc_returns_false_for_missing(fresh_db):
    result = db_module.delete_ioc(9999)
    assert result is False


def test_remove_ioc_entry_decrements_count(fresh_db):
    _seed_two(fresh_db)
    ioc_id = db_module.get_iocs()[0]["id"]
    result = db_module.remove_ioc_entry(ioc_id, "aaa")
    assert result == {"deleted": False}
    row = db_module.get_iocs()[0]
    assert row["occurrence_count"] == 1
    assert row["entry_count"] == 1


def test_remove_ioc_entry_deletes_when_zero(fresh_db):
    iocs = {"ips": ["5.6.7.8"], "domains": [], "urls": [], "hashes": [], "cves": [], "threat_actors": []}
    db_module.upsert_ioc_ledger(iocs, "only_hash", "2026-06-10T10:00:00Z")
    ioc_id = db_module.get_iocs()[0]["id"]
    result = db_module.remove_ioc_entry(ioc_id, "only_hash")
    assert result == {"deleted": True}
    assert db_module.get_iocs() == []


def test_remove_ioc_entry_missing_ioc_returns_false(fresh_db):
    result = db_module.remove_ioc_entry(9999, "some_hash")
    assert result == {"deleted": False}


def test_remove_ioc_entry_missing_hash_returns_false(fresh_db):
    _seed_two(fresh_db)
    ioc_id = db_module.get_iocs()[0]["id"]
    result = db_module.remove_ioc_entry(ioc_id, "nonexistent_hash")
    assert result == {"deleted": False}
    assert db_module.get_iocs()[0]["occurrence_count"] == 2
