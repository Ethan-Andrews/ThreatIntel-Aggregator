"""Tests for tuning_actions.py -- the audit trail for admin apply/dismiss
decisions on stage-7 tuning suggestions (tune.py's TuneResult.final_body,
persisted in analytics.tune_history). See pg_tuning_suggestion_actions.sql.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import tuning_actions


def _seed_analytic(conn, technique_id="T1053.005", tune_history=None):
    strategy = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, "Some Technique", "Detect it", []),
    ).fetchone()
    import json
    analytic = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, tune_history) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (strategy["id"], "hash-" + technique_id, "SomeTable | take 1",
         json.dumps(tune_history) if tune_history is not None else None),
    ).fetchone()
    conn.commit()
    return analytic["id"]


# --- record_tuning_action() ----------------------------------------------

def test_record_tuning_action_rejects_invalid_action(db_conn):
    analytic_id = _seed_analytic(db_conn)
    with pytest.raises(ValueError, match="action must be one of"):
        tuning_actions.record_tuning_action(
            db_conn, analytic_id, "SomeTable | take 1", action="bogus",
        )


def test_record_tuning_action_persists_applied_row(db_conn):
    analytic_id = _seed_analytic(db_conn)
    action_id = tuning_actions.record_tuning_action(
        db_conn, analytic_id, "SomeTable | where X != @\"bob\"", action="applied",
        applied_kql_body="SomeTable | where X != @\"bob\"",
        sentinel_push_result={"status": "success"}, performed_by="admin@example.com",
    )
    row = db_conn.execute(
        "SELECT * FROM tuning_suggestion_actions WHERE id = ?", (action_id,)
    ).fetchone()
    assert row["analytic_id"] == analytic_id
    assert row["action"] == "applied"
    assert row["applied_kql_body"] == "SomeTable | where X != @\"bob\""
    assert row["sentinel_push_result"] == {"status": "success"}
    assert row["performed_by"] == "admin@example.com"
    assert row["performed_at"] is not None


def test_record_tuning_action_persists_dismissed_row_with_no_applied_body(db_conn):
    analytic_id = _seed_analytic(db_conn)
    action_id = tuning_actions.record_tuning_action(
        db_conn, analytic_id, "SomeTable | where X != @\"bob\"", action="dismissed",
        performed_by="admin@example.com",
    )
    row = db_conn.execute(
        "SELECT * FROM tuning_suggestion_actions WHERE id = ?", (action_id,)
    ).fetchone()
    assert row["action"] == "dismissed"
    assert row["applied_kql_body"] is None
    assert row["sentinel_push_result"] is None


def test_record_tuning_action_multiple_rows_survive_independently(db_conn):
    """A later action on the same analytic is a NEW row, not a correction of
    the old one -- the point-in-time history is the product."""
    analytic_id = _seed_analytic(db_conn)
    tuning_actions.record_tuning_action(
        db_conn, analytic_id, "body-v1", action="dismissed", performed_by="alice",
    )
    tuning_actions.record_tuning_action(
        db_conn, analytic_id, "body-v1", action="applied",
        applied_kql_body="body-v1", sentinel_push_result={"status": "success"},
        performed_by="bob",
    )
    count = db_conn.execute(
        "SELECT COUNT(*) FROM tuning_suggestion_actions WHERE analytic_id = ?", (analytic_id,)
    ).fetchone()[0]
    assert count == 2


# --- get_tuning_action_status() -------------------------------------------

def test_get_tuning_action_status_empty_ids_returns_empty_dict(db_conn):
    assert tuning_actions.get_tuning_action_status(db_conn, []) == {}


def test_get_tuning_action_status_absent_for_ids_with_no_action(db_conn):
    analytic_id = _seed_analytic(db_conn)
    assert tuning_actions.get_tuning_action_status(db_conn, [analytic_id]) == {}


def test_get_tuning_action_status_returns_most_recent_action(db_conn):
    analytic_id = _seed_analytic(db_conn)
    tuning_actions.record_tuning_action(
        db_conn, analytic_id, "body-v1", action="dismissed", performed_by="alice",
    )
    tuning_actions.record_tuning_action(
        db_conn, analytic_id, "body-v1", action="applied",
        applied_kql_body="body-v1", sentinel_push_result={"status": "success"},
        performed_by="bob",
    )
    status = tuning_actions.get_tuning_action_status(db_conn, [analytic_id])
    assert status[analytic_id]["action"] == "applied"
    assert status[analytic_id]["performed_by"] == "bob"


def test_get_tuning_action_status_scopes_by_requested_ids(db_conn):
    id_a = _seed_analytic(db_conn, "T1053.001")
    id_b = _seed_analytic(db_conn, "T1053.002")
    tuning_actions.record_tuning_action(db_conn, id_a, "body-a", action="dismissed")
    tuning_actions.record_tuning_action(db_conn, id_b, "body-b", action="dismissed")

    status = tuning_actions.get_tuning_action_status(db_conn, [id_a])
    assert list(status.keys()) == [id_a]


# --- suggestion_view() -----------------------------------------------------

def test_suggestion_view_none_when_no_tune_history():
    assert tuning_actions.suggestion_view(None, None) is None


def test_suggestion_view_not_pending_when_no_final_body():
    view = tuning_actions.suggestion_view(
        {"disposition": "needs_human_tuning", "final_body": None}, None,
    )
    assert view["pending"] is False
    assert view["final_body"] is None
    assert view["disposition"] == "needs_human_tuning"


def test_suggestion_view_pending_when_final_body_present_and_no_action():
    view = tuning_actions.suggestion_view(
        {"disposition": "tuned", "final_body": "SomeTable | where X != @\"bob\""}, None,
    )
    assert view["pending"] is True
    assert view["final_body"] == "SomeTable | where X != @\"bob\""
    assert view["action"] is None


def test_suggestion_view_not_pending_once_actioned():
    view = tuning_actions.suggestion_view(
        {"disposition": "tuned", "final_body": "SomeTable | where X != @\"bob\""},
        {"action": "dismissed", "performed_by": "alice", "performed_at": "2026-09-01T00:00:00Z"},
    )
    assert view["pending"] is False
    assert view["action"] == "dismissed"
    assert view["performed_by"] == "alice"


def test_suggestion_view_apply_failed_reports_still_pending_with_error():
    """A recorded 'applied' action whose push actually failed must not
    render identically to a real success -- found via a mass-data stress
    test (2026-09-01). Must stay retryable (pending=True)."""
    view = tuning_actions.suggestion_view(
        {"disposition": "tuned", "final_body": "SomeTable | where X != @\"bob\""},
        {
            "action": "applied", "performed_by": "admin@example.com",
            "performed_at": "2026-09-01T00:00:00Z",
            "sentinel_push_result": {"status": "error", "detail": "403 Forbidden"},
        },
    )
    assert view["pending"] is True
    assert view["action"] == "apply_failed"
    assert view["error"] == "403 Forbidden"


def test_suggestion_view_successful_apply_is_not_apply_failed(db_conn=None):
    view = tuning_actions.suggestion_view(
        {"disposition": "tuned", "final_body": "SomeTable | where X != @\"bob\""},
        {
            "action": "applied", "performed_by": "admin@example.com",
            "performed_at": "2026-09-01T00:00:00Z",
            "sentinel_push_result": {"status": "success"},
        },
    )
    assert view["pending"] is False
    assert view["action"] == "applied"
    assert view["error"] is None


def test_suggestion_view_dismissed_is_unaffected_by_push_result_shape():
    view = tuning_actions.suggestion_view(
        {"disposition": "tuned", "final_body": "SomeTable | where X != @\"bob\""},
        {"action": "dismissed", "performed_by": "alice", "sentinel_push_result": None},
    )
    assert view["pending"] is False
    assert view["action"] == "dismissed"
    assert view["error"] is None
