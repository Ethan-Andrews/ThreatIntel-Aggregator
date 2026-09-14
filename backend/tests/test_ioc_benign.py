import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import db as db_module


@pytest.fixture
def fresh_db(tmp_db):
    """Alias for conftest's tmp_db — see test_ioc_admin.py for why."""
    return tmp_db


def _insert_ioc(fresh_db):
    """Insert one IP IOC and return its ledger id."""
    iocs = {"ips": ["1.2.3.4"], "domains": [], "urls": [], "hashes": [], "cves": [], "threat_actors": []}
    db_module.upsert_ioc_ledger(iocs, "hash1", "2026-06-10T10:00:00Z")
    rows = db_module.get_iocs(include_benign=True)
    return rows[0]["id"]


def test_set_ioc_benign_marks_row(fresh_db):
    ioc_id = _insert_ioc(fresh_db)
    result = db_module.set_ioc_benign(ioc_id, True, "source domain")
    assert result is True
    rows = db_module.get_iocs(include_benign=True)
    assert rows[0]["benign"] == 1
    assert rows[0]["benign_reason"] == "source domain"


def test_set_ioc_benign_unmarks_row(fresh_db):
    ioc_id = _insert_ioc(fresh_db)
    db_module.set_ioc_benign(ioc_id, True, "reason")
    db_module.set_ioc_benign(ioc_id, False, "")
    rows = db_module.get_iocs(include_benign=True)
    assert rows[0]["benign"] == 0
    assert rows[0]["benign_reason"] is None


def test_set_ioc_benign_returns_false_for_missing_id(fresh_db):
    result = db_module.set_ioc_benign(999, True, "")
    assert result is False


def test_get_iocs_excludes_benign_by_default(fresh_db):
    ioc_id = _insert_ioc(fresh_db)
    db_module.set_ioc_benign(ioc_id, True, "spam domain")
    rows = db_module.get_iocs()
    assert rows == []


def test_get_iocs_includes_benign_when_flagged(fresh_db):
    ioc_id = _insert_ioc(fresh_db)
    db_module.set_ioc_benign(ioc_id, True, "spam domain")
    rows = db_module.get_iocs(include_benign=True)
    assert len(rows) == 1
    assert rows[0]["benign"] == 1


def test_count_iocs_excludes_benign_by_default(fresh_db):
    ioc_id = _insert_ioc(fresh_db)
    db_module.set_ioc_benign(ioc_id, True, "spam")
    count = db_module.count_iocs()
    assert count == 0


def test_count_iocs_includes_benign_when_flagged(fresh_db):
    ioc_id = _insert_ioc(fresh_db)
    db_module.set_ioc_benign(ioc_id, True, "spam")
    count = db_module.count_iocs(include_benign=True)
    assert count == 1


def test_upsert_does_not_update_benign_row(fresh_db):
    """A benign IOC must not be updated when the same value appears in a new entry."""
    iocs = {"ips": ["9.9.9.9"], "domains": [], "urls": [], "hashes": [], "cves": [], "threat_actors": []}
    db_module.upsert_ioc_ledger(iocs, "hash1", "2026-06-10T10:00:00Z")
    rows = db_module.get_iocs(include_benign=True)
    ioc_id = rows[0]["id"]
    db_module.set_ioc_benign(ioc_id, True, "spam")

    # Re-upsert with a new entry hash — benign guard should block the update
    db_module.upsert_ioc_ledger(iocs, "hash2", "2026-06-10T11:00:00Z")
    rows = db_module.get_iocs(include_benign=True)
    assert rows[0]["occurrence_count"] == 1   # unchanged
    assert rows[0]["benign"] == 1             # still benign


def test_get_iocs_returns_benign_fields(fresh_db):
    _insert_ioc(fresh_db)
    rows = db_module.get_iocs(include_benign=True)
    assert "benign" in rows[0]
    assert "benign_reason" in rows[0]
    assert rows[0]["benign"] == 0
    assert rows[0]["benign_reason"] is None
