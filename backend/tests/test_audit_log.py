"""Tests for audit_log.py -- the admin-only cross-pipeline audit view
combining detection static_gate/control_probe outcomes, hunt Sentinel-sync
outcomes, and Sentinel-native query gate/control_probe outcomes into one
paginated, failing/passing-filterable list."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import audit_log
import coverage_ledger
import hunts


def _seed_strategy(conn, technique_id="T1053.005"):
    row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, "Scheduled Task", "Detect scheduled task creation", []),
    ).fetchone()
    conn.commit()
    return row["id"]


def _seed_detection(conn, strategy_id, name, static_gate_verdict, control_probe_result=None):
    row = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, name, "
        "static_gate_verdict, control_probe_result) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
        (strategy_id, f"hash-{name}", "T | take 1", name, static_gate_verdict,
         json.dumps(control_probe_result) if control_probe_result is not None else None),
    ).fetchone()
    conn.commit()
    return row["id"]


def _seed_hunt(conn, title, sentinel_hunt_id=None, error=None):
    hunt_id = hunts.get_or_create_hunt(conn, f"hash-{title}", title=title)
    hunts.mark_hunt_synced(conn, hunt_id, sentinel_hunt_id=sentinel_hunt_id, error=error)
    return hunt_id


def _seed_sentinel_hunt(conn, sentinel_hunt_id="s-hunt-1"):
    row = conn.execute(
        "INSERT INTO sentinel_hunts (sentinel_hunt_id, display_name, description, status) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (sentinel_hunt_id, "Test Hunt", "a hunt", "Active"),
    ).fetchone()
    conn.commit()
    return row["id"]


def _seed_sentinel_query(conn, hunt_id, display_name, control_probe_result, saved_search_id):
    row = conn.execute(
        "INSERT INTO sentinel_hunt_queries "
        "(hunt_id, sentinel_saved_search_id, display_name, kql_body, control_probe_result, last_tested_at) "
        "VALUES (?, ?, ?, ?, ?, now()) RETURNING id",
        (hunt_id, saved_search_id, display_name, "T | take 1", json.dumps(control_probe_result)),
    ).fetchone()
    conn.commit()
    return row["id"]


def test_empty_when_nothing_has_been_checked(db_conn):
    strategy_id = _seed_strategy(db_conn)
    # A detection that hasn't run static_gate yet -- must not appear.
    coverage_ledger.register_analytic(
        db_conn, strategy_id, source_entry_hash="hash-untested", kql_body="T | take 1",
    )
    result = audit_log.list_audit_entries(db_conn)
    assert result == {"total": 0, "items": []}
    assert audit_log.get_audit_summary(db_conn) == {"failing": 0, "passing": 0}


def test_detection_static_gate_rejection_is_failing(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection(db_conn, strategy_id, "Bad Detection", static_gate_verdict="reject")

    result = audit_log.list_audit_entries(db_conn)
    assert result["total"] == 1
    item = result["items"][0]
    assert item["source"] == "detection"
    assert item["is_failing"] is True
    assert item["title"] == "Bad Detection"
    assert "rejected" in item["detail"].lower()


def test_detection_control_probe_error_is_failing_even_if_gate_passed(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection(
        db_conn, strategy_id, "No Sentinel Client", static_gate_verdict="pass",
        control_probe_result={"error": "no Sentinel client configured"},
    )
    result = audit_log.list_audit_entries(db_conn, outcome="failing")
    assert result["total"] == 1
    assert result["items"][0]["detail"] == "no Sentinel client configured"


def test_detection_clean_pass_is_passing(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection(
        db_conn, strategy_id, "Good Detection", static_gate_verdict="pass",
        control_probe_result={"gate_verdict": "pass", "disposition": "ok"},
    )
    result = audit_log.list_audit_entries(db_conn, outcome="passing")
    assert result["total"] == 1
    assert result["items"][0]["is_failing"] is False


def test_hunt_sync_failure_is_failing(db_conn):
    _seed_hunt(db_conn, "Failed Hunt", sentinel_hunt_id=None, error="ARM 403 Forbidden")
    result = audit_log.list_audit_entries(db_conn, outcome="failing")
    assert result["total"] == 1
    item = result["items"][0]
    assert item["source"] == "hunt_sync"
    assert item["detail"] == "ARM 403 Forbidden"


def test_hunt_sync_success_is_passing(db_conn):
    _seed_hunt(db_conn, "Synced Hunt", sentinel_hunt_id="s-hunt-abc", error=None)
    result = audit_log.list_audit_entries(db_conn, outcome="passing")
    assert result["total"] == 1
    assert result["items"][0]["source"] == "hunt_sync"


def test_hunt_never_attempted_sync_is_excluded(db_conn):
    hunts.get_or_create_hunt(db_conn, "hash-never-synced", title="Never Synced")
    result = audit_log.list_audit_entries(db_conn)
    assert result["total"] == 0


def test_sentinel_query_gate_reject_is_failing(db_conn):
    hunt_id = _seed_sentinel_hunt(db_conn)
    _seed_sentinel_query(
        db_conn, hunt_id, "Rejected Query",
        {"gate_verdict": "reject", "gate_findings": ["contains DROP TABLE"]},
        "q-reject-1",
    )
    result = audit_log.list_audit_entries(db_conn, outcome="failing")
    assert result["total"] == 1
    item = result["items"][0]
    assert item["source"] == "sentinel_query"
    assert item["title"] == "Rejected Query"
    # Regression: findings used to be dropped entirely for this source --
    # only the AI-detection source showed why the gate actually rejected.
    assert "DROP TABLE" in item["detail"]


def test_sentinel_query_clean_pass_is_passing(db_conn):
    hunt_id = _seed_sentinel_hunt(db_conn)
    _seed_sentinel_query(
        db_conn, hunt_id, "Clean Query",
        {"gate_verdict": "pass", "disposition": "ok"},
        "q-pass-1",
    )
    result = audit_log.list_audit_entries(db_conn, outcome="passing")
    assert result["total"] == 1
    assert result["items"][0]["source"] == "sentinel_query"


def test_untested_sentinel_query_is_excluded(db_conn):
    hunt_id = _seed_sentinel_hunt(db_conn)
    db_conn.execute(
        "INSERT INTO sentinel_hunt_queries (hunt_id, sentinel_saved_search_id, display_name, kql_body) "
        "VALUES (?, ?, ?, ?)",
        (hunt_id, "q-untested", "Untested Query", "T | take 1"),
    )
    db_conn.commit()
    result = audit_log.list_audit_entries(db_conn)
    assert result["total"] == 0


def _seed_analytics_rule(conn, display_name, control_probe_result, sentinel_rule_id):
    row = conn.execute(
        "INSERT INTO sentinel_analytics_rules "
        "(sentinel_rule_id, display_name, kql_body, control_probe_result, last_tested_at) "
        "VALUES (?, ?, ?, ?, now()) RETURNING id",
        (sentinel_rule_id, display_name, "T | take 1", json.dumps(control_probe_result)),
    ).fetchone()
    conn.commit()
    return row["id"]


def test_analytics_rule_gate_reject_is_failing(db_conn):
    _seed_analytics_rule(
        db_conn, "Rejected Rule",
        {"gate_verdict": "reject", "gate_findings": [{"code": "filename_literal", "detail": "node.exe"}]},
        "rule-reject-1",
    )
    result = audit_log.list_audit_entries(db_conn, outcome="failing")
    assert result["total"] == 1
    item = result["items"][0]
    assert item["source"] == "analytics_rule"
    assert "node.exe" in item["detail"]


def test_analytics_rule_clean_pass_is_passing(db_conn):
    _seed_analytics_rule(
        db_conn, "Clean Rule", {"gate_verdict": "pass"}, "rule-pass-1",
    )
    result = audit_log.list_audit_entries(db_conn, outcome="passing")
    assert result["total"] == 1
    assert result["items"][0]["source"] == "analytics_rule"


def test_untested_analytics_rule_is_excluded(db_conn):
    db_conn.execute(
        "INSERT INTO sentinel_analytics_rules (sentinel_rule_id, display_name, kql_body) "
        "VALUES (?, ?, ?)",
        ("rule-untested", "Untested Rule", "T | take 1"),
    )
    db_conn.commit()
    result = audit_log.list_audit_entries(db_conn)
    assert result["total"] == 0


def test_combines_all_four_sources_and_summary_counts_match(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection(db_conn, strategy_id, "Failing Detection", static_gate_verdict="reject")
    _seed_detection(
        db_conn, strategy_id, "Passing Detection", static_gate_verdict="pass",
        control_probe_result={"gate_verdict": "pass"},
    )
    _seed_hunt(db_conn, "Failing Hunt", error="boom")
    hunt_id = _seed_sentinel_hunt(db_conn)
    _seed_sentinel_query(
        db_conn, hunt_id, "Passing Query", {"gate_verdict": "pass"}, "q-1",
    )
    _seed_analytics_rule(db_conn, "Failing Rule", {"gate_verdict": "reject"}, "rule-1")

    result = audit_log.list_audit_entries(db_conn)
    assert result["total"] == 5
    sources = {item["source"] for item in result["items"]}
    assert sources == {"detection", "hunt_sync", "sentinel_query", "analytics_rule"}

    summary = audit_log.get_audit_summary(db_conn)
    assert summary == {"failing": 3, "passing": 2}


def test_pagination_respects_limit_and_offset(db_conn):
    strategy_id = _seed_strategy(db_conn)
    for i in range(5):
        _seed_detection(db_conn, strategy_id, f"Detection {i}", static_gate_verdict="reject")

    page1 = audit_log.list_audit_entries(db_conn, limit=2, offset=0)
    page2 = audit_log.list_audit_entries(db_conn, limit=2, offset=2)
    assert page1["total"] == 5
    assert len(page1["items"]) == 2
    assert len(page2["items"]) == 2
    ids_page1 = {i["source_id"] for i in page1["items"]}
    ids_page2 = {i["source_id"] for i in page2["items"]}
    assert ids_page1.isdisjoint(ids_page2)


def test_null_technique_name_falls_back_when_detection_name_missing(db_conn):
    strategy_id = _seed_strategy(db_conn, technique_id="T1087.004")
    db_conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, static_gate_verdict) "
        "VALUES (?, ?, ?, ?)",
        (strategy_id, "hash-noname", "T | take 1", "reject"),
    )
    db_conn.commit()
    result = audit_log.list_audit_entries(db_conn)
    assert result["items"][0]["title"] == "Unnamed — T1087.004"


# --- get_audit_failure_breakdown() -------------------------------------

def _seed_detection_with_findings(conn, strategy_id, name, findings):
    row = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, name, "
        "static_gate_verdict, static_gate_findings) VALUES (?, ?, ?, ?, 'reject', ?) RETURNING id",
        (strategy_id, f"hash-{name}", "T | take 1", name, json.dumps(findings)),
    ).fetchone()
    conn.commit()
    return row["id"]


def test_breakdown_empty_when_nothing_failing(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection(db_conn, strategy_id, "Clean Detection", static_gate_verdict="pass")
    assert audit_log.get_audit_failure_breakdown(db_conn) == []


def test_breakdown_groups_static_gate_rejections_by_finding_code(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection_with_findings(
        db_conn, strategy_id, "Detection A",
        [{"code": "no_table", "detail": "no recognised table"}],
    )
    _seed_detection_with_findings(
        db_conn, strategy_id, "Detection B",
        [{"code": "no_table", "detail": "no recognised table"}],
    )
    _seed_detection_with_findings(
        db_conn, strategy_id, "Detection C",
        [{"code": "enumerated_literals", "detail": "7 items"}],
    )

    breakdown = audit_log.get_audit_failure_breakdown(db_conn)
    by_category = {b["category"]: b["count"] for b in breakdown}
    assert by_category["Static gate: no_table"] == 2
    assert by_category["Static gate: enumerated_literals"] == 1


def test_breakdown_one_row_with_multiple_findings_counts_each_code(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection_with_findings(
        db_conn, strategy_id, "Detection A",
        [{"code": "enumerated_literals", "detail": "7 items"}, {"code": "memory_risk", "detail": "make_set"}],
    )

    breakdown = audit_log.get_audit_failure_breakdown(db_conn)
    by_category = {b["category"]: b["count"] for b in breakdown}
    assert by_category["Static gate: enumerated_literals"] == 1
    assert by_category["Static gate: memory_risk"] == 1


def test_breakdown_groups_non_gate_errors_by_exact_message(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection(
        db_conn, strategy_id, "Detection A", static_gate_verdict="pass",
        control_probe_result={"error": "no Sentinel client configured"},
    )
    _seed_detection(
        db_conn, strategy_id, "Detection B", static_gate_verdict="pass",
        control_probe_result={"error": "no Sentinel client configured"},
    )
    _seed_hunt(db_conn, "Failed Hunt", sentinel_hunt_id=None, error="403 Forbidden")

    breakdown = audit_log.get_audit_failure_breakdown(db_conn)
    by_category = {b["category"]: b["count"] for b in breakdown}
    assert by_category["no Sentinel client configured"] == 2
    assert by_category["403 Forbidden"] == 1


def test_list_entries_filters_by_gate_category(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection_with_findings(
        db_conn, strategy_id, "Detection A",
        [{"code": "no_table", "detail": "no recognised table"}],
    )
    _seed_detection_with_findings(
        db_conn, strategy_id, "Detection B",
        [{"code": "enumerated_literals", "detail": "7 items"}],
    )

    result = audit_log.list_audit_entries(db_conn, category="Static gate: no_table")
    assert result["total"] == 1
    assert result["items"][0]["title"] == "Detection A"


def test_list_entries_category_filter_matches_breakdown_counts(db_conn):
    # The bubbles and the filtered list must never disagree -- both derive
    # from the same _categorize() helper.
    strategy_id = _seed_strategy(db_conn)
    for name in ("A", "B", "C"):
        _seed_detection_with_findings(
            db_conn, strategy_id, name,
            [{"code": "memory_risk", "detail": "make_set"}],
        )
    breakdown = audit_log.get_audit_failure_breakdown(db_conn)
    by_category = {b["category"]: b["count"] for b in breakdown}

    result = audit_log.list_audit_entries(db_conn, category="Static gate: memory_risk")
    assert result["total"] == by_category["Static gate: memory_risk"] == 3


def test_list_entries_category_filter_paginates_the_filtered_set(db_conn):
    strategy_id = _seed_strategy(db_conn)
    for name in ("A", "B", "C"):
        _seed_detection_with_findings(
            db_conn, strategy_id, name,
            [{"code": "no_table", "detail": "x"}],
        )
    _seed_detection_with_findings(
        db_conn, strategy_id, "D", [{"code": "memory_risk", "detail": "x"}],
    )

    page = audit_log.list_audit_entries(db_conn, category="Static gate: no_table", limit=2, offset=0)
    assert page["total"] == 3
    assert len(page["items"]) == 2

    page2 = audit_log.list_audit_entries(db_conn, category="Static gate: no_table", limit=2, offset=2)
    assert len(page2["items"]) == 1


def test_list_entries_category_filter_ignores_passing_rows(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection(db_conn, strategy_id, "Clean Detection", static_gate_verdict="pass")
    result = audit_log.list_audit_entries(db_conn, category="Static gate: no_table")
    assert result == {"total": 0, "items": []}


def test_list_entries_unknown_category_returns_empty(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection_with_findings(
        db_conn, strategy_id, "Detection A",
        [{"code": "no_table", "detail": "x"}],
    )
    result = audit_log.list_audit_entries(db_conn, category="not a real category")
    assert result == {"total": 0, "items": []}


def test_breakdown_sorted_by_count_descending(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection_with_findings(
        db_conn, strategy_id, "A", [{"code": "no_table", "detail": "x"}],
    )
    _seed_detection_with_findings(
        db_conn, strategy_id, "B", [{"code": "no_table", "detail": "x"}],
    )
    _seed_detection_with_findings(
        db_conn, strategy_id, "C", [{"code": "memory_risk", "detail": "x"}],
    )

    breakdown = audit_log.get_audit_failure_breakdown(db_conn)
    assert breakdown[0]["category"] == "Static gate: no_table"
    assert breakdown[0]["count"] == 2


# --- annotations (Workstream C) ---------------------------------------------

def test_record_annotation_rejects_unrecognized_source(db_conn):
    import pytest
    with pytest.raises(ValueError, match="source"):
        audit_log.record_annotation(db_conn, "not_a_real_source", 1, "fixed", "", "admin")


def test_record_annotation_rejects_unrecognized_status(db_conn):
    import pytest
    with pytest.raises(ValueError, match="status"):
        audit_log.record_annotation(db_conn, "detection", 1, "not_a_real_status", "", "admin")


def test_record_annotation_is_upsert_not_insert_only(db_conn):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_detection(db_conn, strategy_id, "A", static_gate_verdict="reject")

    audit_log.record_annotation(db_conn, "detection", analytic_id, "acknowledged", "first note", "alice")
    audit_log.record_annotation(db_conn, "detection", analytic_id, "fixed", "second note", "bob")

    row = db_conn.execute(
        "SELECT status, notes, updated_by FROM audit_annotations WHERE source = ? AND source_id = ?",
        ("detection", analytic_id),
    ).fetchone()
    assert row["status"] == "fixed"
    assert row["notes"] == "second note"
    assert row["updated_by"] == "bob"
    count = db_conn.execute("SELECT COUNT(*) FROM audit_annotations").fetchone()[0]
    assert count == 1, "a second annotation on the same row must update in place, not insert a second row"


def test_each_annotation_status_removes_the_row_from_failing(db_conn):
    for status in ("acknowledged", "not_applicable", "fixed"):
        strategy_id = _seed_strategy(db_conn, technique_id=f"T-{status}")
        analytic_id = _seed_detection(db_conn, strategy_id, status, static_gate_verdict="reject")
        audit_log.record_annotation(db_conn, "detection", analytic_id, status, "", "admin")

    summary = audit_log.get_audit_summary(db_conn)
    assert summary == {"failing": 0, "passing": 3}


def test_status_filter_unannotated_is_the_default(db_conn):
    strategy_id = _seed_strategy(db_conn)
    plain_id = _seed_detection(db_conn, strategy_id, "Plain", static_gate_verdict="reject")
    annotated_id = _seed_detection(db_conn, strategy_id, "Annotated", static_gate_verdict="reject")
    audit_log.record_annotation(db_conn, "detection", annotated_id, "fixed", "", "admin")

    default = audit_log.list_audit_entries(db_conn, outcome="failing")
    assert default["total"] == 1
    assert default["items"][0]["source_id"] == plain_id

    explicit = audit_log.list_audit_entries(db_conn, outcome="failing", status="unannotated")
    assert explicit == default


def test_status_filter_all_ignores_annotation_state(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection(db_conn, strategy_id, "Plain", static_gate_verdict="reject")
    annotated_id = _seed_detection(db_conn, strategy_id, "Annotated", static_gate_verdict="reject")
    audit_log.record_annotation(db_conn, "detection", annotated_id, "fixed", "", "admin")

    result = audit_log.list_audit_entries(db_conn, status="all")
    assert result["total"] == 2


def test_status_filter_one_specific_status(db_conn):
    strategy_id = _seed_strategy(db_conn)
    ack_id = _seed_detection(db_conn, strategy_id, "Ack", static_gate_verdict="reject")
    fixed_id = _seed_detection(db_conn, strategy_id, "Fixed", static_gate_verdict="reject")
    audit_log.record_annotation(db_conn, "detection", ack_id, "acknowledged", "", "admin")
    audit_log.record_annotation(db_conn, "detection", fixed_id, "fixed", "", "admin")

    result = audit_log.list_audit_entries(db_conn, status="fixed")
    assert result["total"] == 1
    assert result["items"][0]["source_id"] == fixed_id


def test_clear_annotation_restores_failing_status(db_conn):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_detection(db_conn, strategy_id, "A", static_gate_verdict="reject")
    audit_log.record_annotation(db_conn, "detection", analytic_id, "acknowledged", "", "admin")
    assert audit_log.get_audit_summary(db_conn) == {"failing": 0, "passing": 1}

    audit_log.clear_annotation(db_conn, "detection", analytic_id)
    assert audit_log.get_audit_summary(db_conn) == {"failing": 1, "passing": 0}


def test_clear_annotation_on_nonexistent_row_is_a_noop(db_conn):
    audit_log.clear_annotation(db_conn, "detection", 999999)  # must not raise


def test_since_until_default_none_matches_pre_window_behavior(db_conn):
    """The default call (no window args) must return byte-identical
    results to before this feature existed -- catches an accidental
    behavior change in the default path."""
    strategy_id = _seed_strategy(db_conn)
    _seed_detection(db_conn, strategy_id, "A", static_gate_verdict="reject")
    with_defaults = audit_log.list_audit_entries(db_conn)
    explicit_none = audit_log.list_audit_entries(db_conn, since=None, until=None)
    assert with_defaults == explicit_none
    assert with_defaults["total"] == 1


def test_since_excludes_rows_checked_before_it(db_conn):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_detection(db_conn, strategy_id, "Old", static_gate_verdict="reject")
    db_conn.execute(
        "UPDATE analytics SET created_at = now() - interval '10 days' WHERE id = ?",
        (analytic_id,),
    )
    db_conn.commit()
    _seed_detection(db_conn, strategy_id, "New", static_gate_verdict="reject")

    result = audit_log.list_audit_entries(db_conn)
    assert result["total"] == 2

    import datetime as dt
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    windowed = audit_log.list_audit_entries(db_conn, since=since)
    assert windowed["total"] == 1
    assert windowed["items"][0]["title"] == "New"


def test_summary_and_breakdown_respect_the_window_too(db_conn):
    strategy_id = _seed_strategy(db_conn)
    old_id = _seed_detection_with_findings(
        db_conn, strategy_id, "Old", [{"code": "no_table", "detail": "x"}],
    )
    db_conn.execute(
        "UPDATE analytics SET created_at = now() - interval '10 days' WHERE id = ?", (old_id,),
    )
    db_conn.commit()

    import datetime as dt
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")

    assert audit_log.get_audit_summary(db_conn, since=since) == {"failing": 0, "passing": 0}
    assert audit_log.get_audit_failure_breakdown(db_conn, since=since) == []
    assert audit_log.get_audit_summary(db_conn) == {"failing": 1, "passing": 0}


def test_trend_buckets_by_day_within_the_threshold(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection(db_conn, strategy_id, "A", static_gate_verdict="reject")
    _seed_detection(db_conn, strategy_id, "B", static_gate_verdict="pass")

    trend = audit_log.get_audit_trend(db_conn, since=None, until=None, bucket="day")
    assert len(trend) == 1
    assert trend[0]["failing"] == 1
    assert trend[0]["passing"] == 1


def test_trend_auto_picks_week_bucket_for_all_time(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_detection(db_conn, strategy_id, "A", static_gate_verdict="reject")
    # No assertion on the exact bucket value -- just confirming it runs
    # without error and returns a sensible single-row result for one item,
    # auto-choosing 'week' since since/until are both None (unbounded span).
    trend = audit_log.get_audit_trend(db_conn, since=None, until=None)
    assert len(trend) == 1
    assert trend[0]["failing"] == 1


def test_trend_excludes_annotated_rows_from_failing_bucket(db_conn):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_detection(db_conn, strategy_id, "A", static_gate_verdict="reject")
    audit_log.record_annotation(db_conn, "detection", analytic_id, "fixed", "", "admin")

    trend = audit_log.get_audit_trend(db_conn, since=None, until=None, bucket="day")
    assert trend[0]["failing"] == 0
    assert trend[0]["passing"] == 1


def test_trend_rejects_unrecognized_bucket(db_conn):
    import pytest
    with pytest.raises(ValueError, match="bucket"):
        audit_log.get_audit_trend(db_conn, since=None, until=None, bucket="month")


def test_annotation_category_filter_composes_with_status(db_conn):
    """An annotated row must not appear in category-filtered results
    either -- category filtering builds on the same is_failing/status
    clauses, not a separate code path that could disagree."""
    strategy_id = _seed_strategy(db_conn)
    annotated_id = _seed_detection_with_findings(
        db_conn, strategy_id, "Annotated", [{"code": "no_table", "detail": "x"}],
    )
    audit_log.record_annotation(db_conn, "detection", annotated_id, "fixed", "", "admin")

    result = audit_log.list_audit_entries(db_conn, category="Static gate: no_table")
    assert result == {"total": 0, "items": []}
