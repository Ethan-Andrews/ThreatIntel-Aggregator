"""Tests for sentinel_hunt_queries.py -- the app-facing read/write layer
over sentinel_hunts/sentinel_hunt_queries (populated by sentinel_hunt_sync.py).
Real Postgres throughout (db_conn), no mocking needed -- pure DB logic."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import sentinel_hunt_queries


def _seed_hunt(conn, sentinel_hunt_id="hunt-1", display_name="Test Hunt", query_count=0):
    row = conn.execute(
        "INSERT INTO sentinel_hunts (sentinel_hunt_id, display_name, description, status) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (sentinel_hunt_id, display_name, "a hunt", "Active"),
    ).fetchone()
    conn.execute(
        "UPDATE sentinel_hunts SET query_count = ? WHERE id = ?", (query_count, row["id"])
    )
    conn.commit()
    return row["id"]


def _seed_query(conn, hunt_id, sentinel_saved_search_id="q-1", display_name="Query 1",
                kql_body="T | take 1", review_state="pending", backtest_disposition=None):
    row = conn.execute(
        "INSERT INTO sentinel_hunt_queries "
        "(hunt_id, sentinel_saved_search_id, display_name, kql_body, review_state, "
        " backtest_disposition) "
        "VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
        (hunt_id, sentinel_saved_search_id, display_name, kql_body, review_state,
         backtest_disposition),
    ).fetchone()
    conn.commit()
    return row["id"]


# --- list_sentinel_hunts() ---------------------------------------------------

def test_list_sentinel_hunts_empty(db_conn):
    result = sentinel_hunt_queries.list_sentinel_hunts(db_conn)
    assert result == {"total": 0, "items": []}


def test_list_sentinel_hunts_includes_review_state_rollup(db_conn):
    hunt_id = _seed_hunt(db_conn, query_count=2)
    _seed_query(db_conn, hunt_id, "q-1", review_state="pending")
    _seed_query(db_conn, hunt_id, "q-2", review_state="approved")

    result = sentinel_hunt_queries.list_sentinel_hunts(db_conn)
    assert result["total"] == 1
    item = result["items"][0]
    assert item["query_count"] == 2
    assert item["review_state_counts"] == {"pending": 1, "approved": 1}


def test_list_sentinel_hunts_includes_tunable_count(db_conn):
    hunt_id = _seed_hunt(db_conn, query_count=3)
    _seed_query(db_conn, hunt_id, "q-1", backtest_disposition="needs_tuning")
    _seed_query(db_conn, hunt_id, "q-2", backtest_disposition="needs_tuning")
    _seed_query(db_conn, hunt_id, "q-3", backtest_disposition="clean")

    result = sentinel_hunt_queries.list_sentinel_hunts(db_conn)
    assert result["items"][0]["tunable_count"] == 2


def test_list_sentinel_hunts_tunable_count_is_zero_for_no_tunable_queries(db_conn):
    hunt_id = _seed_hunt(db_conn, query_count=1)
    _seed_query(db_conn, hunt_id, "q-1", backtest_disposition="clean")

    result = sentinel_hunt_queries.list_sentinel_hunts(db_conn)
    assert result["items"][0]["tunable_count"] == 0


def test_list_sentinel_hunts_searches_by_display_name_case_insensitively(db_conn):
    _seed_hunt(db_conn, sentinel_hunt_id="hunt-1", display_name="Suspicious PowerShell Activity")
    _seed_hunt(db_conn, sentinel_hunt_id="hunt-2", display_name="Scheduled Task Creation")

    result = sentinel_hunt_queries.list_sentinel_hunts(db_conn, search="powershell")
    assert result["total"] == 1
    assert result["items"][0]["sentinel_hunt_id"] == "hunt-1"


def test_list_sentinel_hunts_pagination(db_conn):
    for i in range(5):
        _seed_hunt(db_conn, sentinel_hunt_id=f"hunt-{i}", display_name=f"Hunt {i}")

    page1 = sentinel_hunt_queries.list_sentinel_hunts(db_conn, limit=2, offset=0)
    page2 = sentinel_hunt_queries.list_sentinel_hunts(db_conn, limit=2, offset=2)
    assert page1["total"] == 5
    assert len(page1["items"]) == 2
    assert len(page2["items"]) == 2
    ids_page1 = {i["id"] for i in page1["items"]}
    ids_page2 = {i["id"] for i in page2["items"]}
    assert ids_page1.isdisjoint(ids_page2)


# --- get_sentinel_hunt() -----------------------------------------------------

def test_get_sentinel_hunt_not_found(db_conn):
    assert sentinel_hunt_queries.get_sentinel_hunt(db_conn, 999999) is None


def test_get_sentinel_hunt_does_not_include_queries(db_conn):
    """The whole point of this endpoint being separate from
    list_hunt_queries() -- a hunt with 800+ queries must not have them all
    embedded in the metadata response."""
    hunt_id = _seed_hunt(db_conn)
    _seed_query(db_conn, hunt_id)
    detail = sentinel_hunt_queries.get_sentinel_hunt(db_conn, hunt_id)
    assert "queries" not in detail
    assert "detections" not in detail


# --- list_hunt_queries() -----------------------------------------------------

def test_list_hunt_queries_pagination(db_conn):
    hunt_id = _seed_hunt(db_conn)
    for i in range(30):
        _seed_query(db_conn, hunt_id, sentinel_saved_search_id=f"q-{i}", display_name=f"Query {i:02d}")

    page1 = sentinel_hunt_queries.list_hunt_queries(db_conn, hunt_id, limit=10, offset=0)
    page2 = sentinel_hunt_queries.list_hunt_queries(db_conn, hunt_id, limit=10, offset=10)
    page3 = sentinel_hunt_queries.list_hunt_queries(db_conn, hunt_id, limit=10, offset=20)
    assert page1["total"] == 30
    assert len(page1["items"]) == 10
    assert len(page2["items"]) == 10
    assert len(page3["items"]) == 10
    all_ids = (
        {i["id"] for i in page1["items"]}
        | {i["id"] for i in page2["items"]}
        | {i["id"] for i in page3["items"]}
    )
    assert len(all_ids) == 30


def test_list_hunt_queries_excludes_kql_body_from_list_rows(db_conn):
    """List rows deliberately omit kql_body/control_probe_result/tune_history
    -- a page of 50 shouldn't drag along every query's full body until
    something actually expands one row."""
    hunt_id = _seed_hunt(db_conn)
    _seed_query(db_conn, hunt_id, kql_body="SECRET_LOOKING_BODY | take 1")
    result = sentinel_hunt_queries.list_hunt_queries(db_conn, hunt_id)
    assert "kql_body" not in result["items"][0]


def test_list_hunt_queries_filters_by_review_state(db_conn):
    hunt_id = _seed_hunt(db_conn)
    _seed_query(db_conn, hunt_id, "q-1", review_state="pending")
    _seed_query(db_conn, hunt_id, "q-2", review_state="approved")

    result = sentinel_hunt_queries.list_hunt_queries(db_conn, hunt_id, review_state="approved")
    assert result["total"] == 1
    assert result["items"][0]["sentinel_saved_search_id"] == "q-2"


def test_list_hunt_queries_filters_by_disposition(db_conn):
    hunt_id = _seed_hunt(db_conn)
    _seed_query(db_conn, hunt_id, "q-1", backtest_disposition="needs_tuning")
    _seed_query(db_conn, hunt_id, "q-2", backtest_disposition="clean")
    _seed_query(db_conn, hunt_id, "q-3")  # never tested

    result = sentinel_hunt_queries.list_hunt_queries(db_conn, hunt_id, disposition="needs_tuning")
    assert result["total"] == 1
    assert result["items"][0]["sentinel_saved_search_id"] == "q-1"


def test_list_hunt_queries_searches_by_display_name_case_insensitively(db_conn):
    hunt_id = _seed_hunt(db_conn)
    _seed_query(db_conn, hunt_id, "q-1", display_name="Suspicious PowerShell Download")
    _seed_query(db_conn, hunt_id, "q-2", display_name="Scheduled Task Creation")

    result = sentinel_hunt_queries.list_hunt_queries(db_conn, hunt_id, search="powershell")
    assert result["total"] == 1
    assert result["items"][0]["sentinel_saved_search_id"] == "q-1"


def test_list_hunt_queries_scoped_to_one_hunt(db_conn):
    hunt_a = _seed_hunt(db_conn, sentinel_hunt_id="hunt-a")
    hunt_b = _seed_hunt(db_conn, sentinel_hunt_id="hunt-b")
    _seed_query(db_conn, hunt_a, "q-a")
    _seed_query(db_conn, hunt_b, "q-b")

    result = sentinel_hunt_queries.list_hunt_queries(db_conn, hunt_a)
    assert result["total"] == 1
    assert result["items"][0]["sentinel_saved_search_id"] == "q-a"


# --- get_query_detail() ------------------------------------------------------

def test_get_query_detail_not_found(db_conn):
    assert sentinel_hunt_queries.get_query_detail(db_conn, 999999) is None


def test_get_query_detail_includes_full_kql_body(db_conn):
    hunt_id = _seed_hunt(db_conn)
    query_id = _seed_query(db_conn, hunt_id, kql_body="DeviceProcessEvents | take 5")
    detail = sentinel_hunt_queries.get_query_detail(db_conn, query_id)
    assert detail["kql_body"] == "DeviceProcessEvents | take 5"
    assert detail["review_state"] == "pending"
    assert detail["control_probe_result"] is None
    assert detail["tune_history"] is None


# --- set_query_review_state() ------------------------------------------------

def test_set_query_review_state_updates(db_conn):
    hunt_id = _seed_hunt(db_conn)
    query_id = _seed_query(db_conn, hunt_id)
    ok = sentinel_hunt_queries.set_query_review_state(db_conn, query_id, "approved")
    assert ok is True
    assert sentinel_hunt_queries.get_query_detail(db_conn, query_id)["review_state"] == "approved"


def test_set_query_review_state_rejects_invalid_state(db_conn):
    hunt_id = _seed_hunt(db_conn)
    query_id = _seed_query(db_conn, hunt_id)
    ok = sentinel_hunt_queries.set_query_review_state(db_conn, query_id, "not-a-real-state")
    assert ok is False
    assert sentinel_hunt_queries.get_query_detail(db_conn, query_id)["review_state"] == "pending"


def test_set_query_review_state_missing_query_returns_false(db_conn):
    assert sentinel_hunt_queries.set_query_review_state(db_conn, 999999, "approved") is False


# --- record_query_test_result() / record_query_tune_result() ----------------

def test_record_query_test_result_persists_and_sets_last_tested_at(db_conn):
    hunt_id = _seed_hunt(db_conn)
    query_id = _seed_query(db_conn, hunt_id)
    sentinel_hunt_queries.record_query_test_result(
        db_conn, query_id, {"disposition": "ok", "tables": []}, "clean",
    )
    detail = sentinel_hunt_queries.get_query_detail(db_conn, query_id)
    assert detail["control_probe_result"] == {"disposition": "ok", "tables": []}
    assert detail["backtest_disposition"] == "clean"
    assert detail["last_tested_at"] is not None


def test_record_query_tune_result_persists(db_conn):
    hunt_id = _seed_hunt(db_conn)
    query_id = _seed_query(db_conn, hunt_id)
    sentinel_hunt_queries.record_query_tune_result(
        db_conn, query_id, {"disposition": "tuned", "final_body": "T | take 1 | where X == 1"},
    )
    detail = sentinel_hunt_queries.get_query_detail(db_conn, query_id)
    assert detail["tune_history"]["disposition"] == "tuned"
