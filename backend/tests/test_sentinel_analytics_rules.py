"""Tests for sentinel_analytics_rules.py -- the app-facing read/write layer
over sentinel_analytics_rules (populated by sentinel_analytics_rules_sync.py).
Real Postgres throughout, no mocking needed -- pure DB logic. Mirrors
test_sentinel_hunt_queries.py's structure for the flat (non-hunt-scoped)
shape this table actually has."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import sentinel_analytics_rules as rules_mod


def _seed_rule(conn, sentinel_rule_id="rule-1", display_name="Rule 1",
              kql_body="T | take 1", review_state="pending", severity="High",
              backtest_disposition=None):
    row = conn.execute(
        "INSERT INTO sentinel_analytics_rules "
        "(sentinel_rule_id, display_name, kql_body, review_state, severity, "
        " backtest_disposition) "
        "VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
        (sentinel_rule_id, display_name, kql_body, review_state, severity,
         backtest_disposition),
    ).fetchone()
    conn.commit()
    return row["id"]


def test_list_analytics_rules_empty(db_conn):
    assert rules_mod.list_analytics_rules(db_conn) == {"total": 0, "items": []}


def test_list_analytics_rules_excludes_kql_body(db_conn):
    _seed_rule(db_conn)
    result = rules_mod.list_analytics_rules(db_conn)
    assert result["total"] == 1
    assert "kql_body" not in result["items"][0]


def test_list_analytics_rules_filters_by_review_state(db_conn):
    _seed_rule(db_conn, sentinel_rule_id="r1", review_state="pending")
    _seed_rule(db_conn, sentinel_rule_id="r2", review_state="approved")

    result = rules_mod.list_analytics_rules(db_conn, review_state="approved")
    assert result["total"] == 1
    assert result["items"][0]["sentinel_rule_id"] == "r2"


def test_list_analytics_rules_filters_by_disposition(db_conn):
    _seed_rule(db_conn, sentinel_rule_id="r1", backtest_disposition="needs_tuning")
    _seed_rule(db_conn, sentinel_rule_id="r2", backtest_disposition="clean")
    _seed_rule(db_conn, sentinel_rule_id="r3")  # never tested -- no disposition at all

    result = rules_mod.list_analytics_rules(db_conn, disposition="needs_tuning")
    assert result["total"] == 1
    assert result["items"][0]["sentinel_rule_id"] == "r1"


def test_list_analytics_rules_searches_by_display_name_case_insensitively(db_conn):
    _seed_rule(db_conn, sentinel_rule_id="r1", display_name="Suspicious PowerShell Download")
    _seed_rule(db_conn, sentinel_rule_id="r2", display_name="Scheduled Task Creation")

    result = rules_mod.list_analytics_rules(db_conn, search="powershell")
    assert result["total"] == 1
    assert result["items"][0]["sentinel_rule_id"] == "r1"


def test_list_analytics_rules_orders_by_display_name(db_conn):
    _seed_rule(db_conn, sentinel_rule_id="r1", display_name="Zebra Rule")
    _seed_rule(db_conn, sentinel_rule_id="r2", display_name="Alpha Rule")

    result = rules_mod.list_analytics_rules(db_conn)
    assert [i["display_name"] for i in result["items"]] == ["Alpha Rule", "Zebra Rule"]


def test_get_rule_detail_includes_kql_body(db_conn):
    rule_id = _seed_rule(db_conn, kql_body="DeviceProcessEvents | take 1")
    detail = rules_mod.get_rule_detail(db_conn, rule_id)
    assert detail["kql_body"] == "DeviceProcessEvents | take 1"


def test_get_rule_detail_404_shape_for_missing_rule(db_conn):
    assert rules_mod.get_rule_detail(db_conn, 999) is None


def test_set_rule_review_state_updates_and_returns_true(db_conn):
    rule_id = _seed_rule(db_conn)
    ok = rules_mod.set_rule_review_state(db_conn, rule_id, "approved")
    assert ok is True
    assert rules_mod.get_rule_detail(db_conn, rule_id)["review_state"] == "approved"


def test_set_rule_review_state_rejects_invalid_state(db_conn):
    rule_id = _seed_rule(db_conn)
    ok = rules_mod.set_rule_review_state(db_conn, rule_id, "bogus")
    assert ok is False
    assert rules_mod.get_rule_detail(db_conn, rule_id)["review_state"] == "pending"


def test_set_rule_review_state_returns_false_for_missing_rule(db_conn):
    assert rules_mod.set_rule_review_state(db_conn, 999, "approved") is False


def test_record_rule_test_result_persists_control_probe_and_backtest(db_conn):
    rule_id = _seed_rule(db_conn)
    rules_mod.record_rule_test_result(
        db_conn, rule_id, {"gate_verdict": "pass", "disposition": "ok"}, "clean",
    )
    detail = rules_mod.get_rule_detail(db_conn, rule_id)
    assert detail["control_probe_result"] == {"gate_verdict": "pass", "disposition": "ok"}
    assert detail["backtest_disposition"] == "clean"
    assert detail["last_tested_at"] is not None


def test_record_rule_tune_result_persists_tune_history(db_conn):
    rule_id = _seed_rule(db_conn)
    rules_mod.record_rule_tune_result(db_conn, rule_id, {"disposition": "tuned"})
    detail = rules_mod.get_rule_detail(db_conn, rule_id)
    assert detail["tune_history"] == {"disposition": "tuned"}
