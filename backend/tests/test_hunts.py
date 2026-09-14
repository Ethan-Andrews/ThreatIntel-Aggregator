"""Tests for hunts.py -- the grouping layer over `analytics` that gives
Sentinel's own "Hunts" container concept a real backing table. See
pg_hunts.sql and hunts.py's module docstring for the architecture."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import hunts


def _seed_strategy(conn, technique_id="T1053.005", technique_name="Scheduled Task"):
    row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, technique_name, "Detect it", []),
    ).fetchone()
    conn.commit()
    return row["id"]


def _seed_analytic(conn, strategy_id, hunt_id, name=None, description=None,
                   kql_body="X | take 1", review_state="pending",
                   static_gate_verdict=None, backtest_disposition=None):
    row = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, name, "
        " description, review_state, hunt_id, static_gate_verdict, backtest_disposition) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        (strategy_id, "hash-" + str(strategy_id), kql_body, name, description,
         review_state, hunt_id, static_gate_verdict, backtest_disposition),
    ).fetchone()
    conn.commit()
    return row["id"]


def test_get_or_create_hunt_creates_new_row(db_conn):
    hunt_id = hunts.get_or_create_hunt(
        db_conn, "entry-hash-1", title="[High] BTR Reforged",
        description="APT campaign writeup", source_title="BTR Reforged",
        source_link="https://example.com/article", source_name="Some Feed",
        source_severity="High",
    )
    row = db_conn.execute("SELECT * FROM hunts WHERE id = ?", (hunt_id,)).fetchone()
    assert row["source_entry_hash"] == "entry-hash-1"
    assert row["title"] == "[High] BTR Reforged"
    assert row["source_name"] == "Some Feed"
    assert row["sentinel_hunt_id"] is None


def test_get_or_create_hunt_is_idempotent_by_source_entry_hash(db_conn):
    first = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="First title")
    second = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="Different title, same article")

    assert first == second
    count = db_conn.execute(
        "SELECT COUNT(*) FROM hunts WHERE source_entry_hash = 'entry-hash-1'"
    ).fetchone()[0]
    assert count == 1


def test_mark_hunt_synced_records_sentinel_id(db_conn):
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="T")
    hunts.mark_hunt_synced(db_conn, hunt_id, sentinel_hunt_id="abc-123-guid")

    row = db_conn.execute("SELECT sentinel_hunt_id, sentinel_synced_at, sentinel_sync_error "
                          "FROM hunts WHERE id = ?", (hunt_id,)).fetchone()
    assert row["sentinel_hunt_id"] == "abc-123-guid"
    assert row["sentinel_synced_at"] is not None
    assert row["sentinel_sync_error"] is None


def test_mark_hunt_synced_records_error_without_sentinel_id(db_conn):
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="T")
    hunts.mark_hunt_synced(db_conn, hunt_id, sentinel_hunt_id=None, error="403 Forbidden")

    row = db_conn.execute("SELECT sentinel_hunt_id, sentinel_sync_error "
                          "FROM hunts WHERE id = ?", (hunt_id,)).fetchone()
    assert row["sentinel_hunt_id"] is None
    assert row["sentinel_sync_error"] == "403 Forbidden"


def test_list_hunts_returns_rollup_counts_and_techniques(db_conn):
    strategy_a = _seed_strategy(db_conn, "T1053.005", "Scheduled Task")
    strategy_b = _seed_strategy(db_conn, "T1059.001", "PowerShell")
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="BTR Reforged")
    _seed_analytic(db_conn, strategy_a, hunt_id, name="Detection A", review_state="approved")
    _seed_analytic(db_conn, strategy_b, hunt_id, name="Detection B", review_state="pending")

    result = hunts.list_hunts(db_conn)
    assert result["total"] == 1
    item = result["items"][0]
    assert item["title"] == "BTR Reforged"
    assert item["detection_count"] == 2
    assert item["review_state_counts"] == {"approved": 1, "pending": 1}
    technique_ids = {t["technique_id"] for t in item["techniques"]}
    assert technique_ids == {"T1053.005", "T1059.001"}


def test_list_hunts_with_no_detections_shows_zero_count(db_conn):
    hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="Empty hunt")
    result = hunts.list_hunts(db_conn)
    assert result["items"][0]["detection_count"] == 0
    assert result["items"][0]["techniques"] == []


def test_list_hunts_filters_by_technique_id(db_conn):
    strategy_a = _seed_strategy(db_conn, "T1053.005")
    strategy_b = _seed_strategy(db_conn, "T1059.001")
    hunt_1 = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="Hunt 1")
    hunt_2 = hunts.get_or_create_hunt(db_conn, "entry-hash-2", title="Hunt 2")
    _seed_analytic(db_conn, strategy_a, hunt_1)
    _seed_analytic(db_conn, strategy_b, hunt_2)

    result = hunts.list_hunts(db_conn, technique_id="T1059.001")
    assert result["total"] == 1
    assert result["items"][0]["title"] == "Hunt 2"


def test_list_hunts_search_matches_title_substring_case_insensitively(db_conn):
    hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="BTR Reforged")
    hunts.get_or_create_hunt(db_conn, "entry-hash-2", title="SnakeBiteAgent Campaign")

    result = hunts.list_hunts(db_conn, search="reforged")
    assert result["total"] == 1
    assert result["items"][0]["title"] == "BTR Reforged"


def test_list_hunts_search_finds_no_match_for_an_unrelated_substring(db_conn):
    hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="BTR Reforged")
    result = hunts.list_hunts(db_conn, search="does-not-exist")
    assert result["total"] == 0


def test_new_hunt_has_no_target_sentinel_hunt_by_default(db_conn):
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="BTR Reforged")
    detail = hunts.get_hunt_detail(db_conn, hunt_id)
    assert detail["target_sentinel_hunt_id"] is None


def test_set_hunt_target_persists_and_is_returned_by_get_hunt_detail(db_conn):
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="BTR Reforged")
    hunts.set_hunt_target(db_conn, hunt_id, "existing-hunt-guid-123")
    detail = hunts.get_hunt_detail(db_conn, hunt_id)
    assert detail["target_sentinel_hunt_id"] == "existing-hunt-guid-123"


def test_set_hunt_target_none_clears_a_previously_set_target(db_conn):
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="BTR Reforged")
    hunts.set_hunt_target(db_conn, hunt_id, "existing-hunt-guid-123")
    hunts.set_hunt_target(db_conn, hunt_id, None)
    detail = hunts.get_hunt_detail(db_conn, hunt_id)
    assert detail["target_sentinel_hunt_id"] is None


def test_list_hunts_needing_deploy_surfaces_the_stored_target(db_conn):
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="BTR Reforged")
    hunts.set_hunt_target(db_conn, hunt_id, "existing-hunt-guid-123")
    _seed_analytic(db_conn, strategy_id, hunt_id,
                   static_gate_verdict="pass", backtest_disposition="clean")

    candidates = hunts.list_hunts_needing_deploy(db_conn)
    assert len(candidates) == 1
    assert candidates[0]["target_sentinel_hunt_id"] == "existing-hunt-guid-123"


def test_list_hunts_reports_eligible_count_regardless_of_ready_only(db_conn):
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="Mixed hunt")
    _seed_analytic(db_conn, strategy_id, hunt_id,
                   static_gate_verdict="pass", backtest_disposition="clean")
    _seed_analytic(db_conn, strategy_id, hunt_id,
                   static_gate_verdict="pass", backtest_disposition="needs_tuning")
    _seed_analytic(db_conn, strategy_id, hunt_id,
                   static_gate_verdict="reject", backtest_disposition=None)

    result = hunts.list_hunts(db_conn)
    assert result["items"][0]["detection_count"] == 3
    assert result["items"][0]["eligible_count"] == 1


def test_list_hunts_ready_only_excludes_hunts_with_no_eligible_detection(db_conn):
    strategy_id = _seed_strategy(db_conn)
    ready_hunt = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="Ready hunt")
    not_ready_hunt = hunts.get_or_create_hunt(db_conn, "entry-hash-2", title="Not ready hunt")
    _seed_analytic(db_conn, strategy_id, ready_hunt,
                   static_gate_verdict="pass", backtest_disposition="clean")
    _seed_analytic(db_conn, strategy_id, not_ready_hunt,
                   static_gate_verdict="reject", backtest_disposition=None)

    result = hunts.list_hunts(db_conn, ready_only=True)

    assert result["total"] == 1
    assert result["items"][0]["title"] == "Ready hunt"


def test_list_hunts_needing_deploy_includes_never_synced_hunt(db_conn):
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="Never Synced")
    result = hunts.list_hunts_needing_deploy(db_conn)
    assert {h["id"] for h in result} == {hunt_id}


def test_list_hunts_needing_deploy_includes_hunt_with_failed_sync(db_conn):
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="Failed Sync")
    hunts.mark_hunt_synced(db_conn, hunt_id, sentinel_hunt_id=None, error="403 Forbidden")
    result = hunts.list_hunts_needing_deploy(db_conn)
    assert {h["id"] for h in result} == {hunt_id}


def test_list_hunts_needing_deploy_excludes_hunt_synced_clean_with_no_new_detections(db_conn):
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="Up To Date")
    hunts.mark_hunt_synced(db_conn, hunt_id, sentinel_hunt_id="sentinel-guid-1")
    result = hunts.list_hunts_needing_deploy(db_conn)
    assert result == []


def test_list_hunts_needing_deploy_includes_hunt_with_detection_added_since_last_sync(db_conn):
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="Stale Sync")
    hunts.mark_hunt_synced(db_conn, hunt_id, sentinel_hunt_id="sentinel-guid-1")
    # A detection registered after the hunt was last synced -- Sentinel
    # doesn't have it yet, so this hunt needs a resync even though its
    # last sync attempt succeeded.
    _seed_analytic(db_conn, strategy_id, hunt_id, name="New Detection")
    result = hunts.list_hunts_needing_deploy(db_conn)
    assert {h["id"] for h in result} == {hunt_id}


def test_get_hunt_detail_returns_full_child_detections(db_conn):
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts.get_or_create_hunt(
        db_conn, "entry-hash-1", title="BTR Reforged",
        description="APT campaign", source_link="https://example.com/a",
    )
    _seed_analytic(
        db_conn, strategy_id, hunt_id,
        name="Suspicious Scheduled Task Creation",
        description="Flags schtasks.exe creating a new scheduled task.",
        kql_body="DeviceProcessEvents | where FileName == 'schtasks.exe'",
        review_state="approved",
    )

    detail = hunts.get_hunt_detail(db_conn, hunt_id)
    assert detail["title"] == "BTR Reforged"
    assert detail["source_link"] == "https://example.com/a"
    assert len(detail["detections"]) == 1
    det = detail["detections"][0]
    assert det["name"] == "Suspicious Scheduled Task Creation"
    assert det["description"] == "Flags schtasks.exe creating a new scheduled task."
    assert det["kql_body"] == "DeviceProcessEvents | where FileName == 'schtasks.exe'"
    assert det["technique_id"] == "T1053.005"
    assert det["review_state"] == "approved"


def test_get_hunt_detail_returns_none_for_missing_id(db_conn):
    assert hunts.get_hunt_detail(db_conn, 999999) is None


def test_get_hunt_detail_handles_hunt_with_no_detections_yet(db_conn):
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="Fresh hunt")
    detail = hunts.get_hunt_detail(db_conn, hunt_id)
    assert detail["detections"] == []


# --- tuning_suggestion surfacing on hunt detail's child detections -------

def test_get_hunt_detail_tuning_suggestion_is_none_when_never_tuned(db_conn):
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="Hunt")
    _seed_analytic(db_conn, strategy_id, hunt_id)

    detail = hunts.get_hunt_detail(db_conn, hunt_id)
    assert detail["detections"][0]["tuning_suggestion"] is None


def test_get_hunt_detail_tuning_suggestion_pending_when_final_body_present(db_conn):
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="Hunt")
    analytic_id = _seed_analytic(db_conn, strategy_id, hunt_id)
    import json
    db_conn.execute(
        "UPDATE analytics SET tune_history = ? WHERE id = ?",
        (json.dumps({"disposition": "clean_after_tuning", "final_body": "X | where Y != @\"z\""}),
         analytic_id),
    )
    db_conn.commit()

    detail = hunts.get_hunt_detail(db_conn, hunt_id)
    suggestion = detail["detections"][0]["tuning_suggestion"]
    assert suggestion["pending"] is True
    assert suggestion["final_body"] == "X | where Y != @\"z\""


def test_get_hunt_detail_tuning_suggestion_not_pending_once_applied(db_conn):
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts.get_or_create_hunt(db_conn, "entry-hash-1", title="Hunt")
    analytic_id = _seed_analytic(db_conn, strategy_id, hunt_id)
    import json
    final_body = "X | where Y != @\"z\""
    db_conn.execute(
        "UPDATE analytics SET tune_history = ? WHERE id = ?",
        (json.dumps({"disposition": "tuned", "final_body": final_body}), analytic_id),
    )
    db_conn.execute(
        "INSERT INTO tuning_suggestion_actions "
        "(analytic_id, suggested_kql_body, action, applied_kql_body, performed_by) "
        "VALUES (?, ?, 'applied', ?, 'admin@example.com')",
        (analytic_id, final_body, final_body),
    )
    db_conn.commit()

    detail = hunts.get_hunt_detail(db_conn, hunt_id)
    suggestion = detail["detections"][0]["tuning_suggestion"]
    assert suggestion["pending"] is False
    assert suggestion["action"] == "applied"
    assert suggestion["performed_by"] == "admin@example.com"
