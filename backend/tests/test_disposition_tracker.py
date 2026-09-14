"""Tests for disposition_tracker.py (stage 9). Pure-logic classification
tests need no DB; due_for_recheck()/sweep() use db_conn (real Postgres)."""

import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import disposition_tracker


class _FakeControlProbeResult:
    def __init__(self, telemetry_ok, disposition="ok"):
        self.telemetry_ok = telemetry_ok
        self.disposition = disposition

    def to_row(self):
        return {"disposition": self.disposition}


class _FakeBacktestOutcome:
    def __init__(self, hits=0, error="", disposition="clean", window_hours=2160.0):
        self.hits = hits
        self.error = error
        self.disposition = disposition
        self.window_hours = window_hours


def test_check_one_still_clean(monkeypatch):
    monkeypatch.setattr(disposition_tracker, "run_control_probe",
                        lambda client, body, artifact_id="": _FakeControlProbeResult(True))
    monkeypatch.setattr(disposition_tracker, "run_backtest",
                        lambda client, body, artifact_id="", with_evidence=True: _FakeBacktestOutcome(hits=0))

    outcome = disposition_tracker.check_one(object(), 1, "DeviceProcessEvents | take 1")
    assert outcome.outcome == "still_clean"
    assert outcome.hits == 0


def test_check_one_now_firing(monkeypatch):
    monkeypatch.setattr(disposition_tracker, "run_control_probe",
                        lambda client, body, artifact_id="": _FakeControlProbeResult(True))
    monkeypatch.setattr(disposition_tracker, "run_backtest",
                        lambda client, body, artifact_id="", with_evidence=True: _FakeBacktestOutcome(hits=12, disposition="needs_tuning"))

    outcome = disposition_tracker.check_one(object(), 1, "DeviceProcessEvents | take 1")
    assert outcome.outcome == "now_firing"
    assert outcome.hits == 12


def test_check_one_telemetry_decayed(monkeypatch):
    monkeypatch.setattr(disposition_tracker, "run_control_probe",
                        lambda client, body, artifact_id="": _FakeControlProbeResult(False, disposition="no_telemetry"))

    def _should_not_run(*a, **k):
        raise AssertionError("backtest must not run when telemetry isn't confirmed")
    monkeypatch.setattr(disposition_tracker, "run_backtest", _should_not_run)

    outcome = disposition_tracker.check_one(object(), 1, "DeviceProcessEvents | take 1")
    assert outcome.outcome == "telemetry_decayed"
    assert outcome.control_probe_disposition == "no_telemetry"


def test_check_one_check_error(monkeypatch):
    monkeypatch.setattr(disposition_tracker, "run_control_probe",
                        lambda client, body, artifact_id="": _FakeControlProbeResult(True))
    monkeypatch.setattr(disposition_tracker, "run_backtest",
                        lambda client, body, artifact_id="", with_evidence=True: _FakeBacktestOutcome(error="query failed"))

    outcome = disposition_tracker.check_one(object(), 1, "DeviceProcessEvents | take 1")
    assert outcome.outcome == "check_error"


_technique_counter = {"n": 0}


def _seed_strategy_and_analytic(conn, backtest_disposition="clean", review_state="pending"):
    _technique_counter["n"] += 1
    technique_id = f"T1053.{_technique_counter['n']:03d}"
    strategy = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, "Scheduled Task", "Detect scheduled task creation", []),
    ).fetchone()
    analytic = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, "
        " backtest_disposition, review_state) "
        "VALUES (?, ?, ?, ?, ?) RETURNING id",
        (strategy["id"], "test-hash", "DeviceProcessEvents | take 1",
         backtest_disposition, review_state),
    ).fetchone()
    conn.commit()
    return analytic["id"]


def test_due_for_recheck_returns_never_checked(db_conn):
    analytic_id = _seed_strategy_and_analytic(db_conn)
    due = disposition_tracker.due_for_recheck(db_conn)
    assert [d["id"] for d in due] == [analytic_id]


def test_due_for_recheck_excludes_recently_checked(db_conn):
    analytic_id = _seed_strategy_and_analytic(db_conn)
    db_conn.execute(
        "INSERT INTO disposition_checks (analytic_id, control_probe_disposition, outcome) "
        "VALUES (?, 'ok', 'still_clean')",
        (analytic_id,),
    )
    db_conn.commit()
    due = disposition_tracker.due_for_recheck(db_conn)
    assert due == []


def test_due_for_recheck_includes_stale_check(db_conn):
    analytic_id = _seed_strategy_and_analytic(db_conn)
    stale = datetime.now(timezone.utc) - timedelta(hours=48)
    db_conn.execute(
        "INSERT INTO disposition_checks (analytic_id, checked_at, control_probe_disposition, outcome) "
        "VALUES (?, ?, 'ok', 'still_clean')",
        (analytic_id, stale),
    )
    db_conn.commit()
    due = disposition_tracker.due_for_recheck(db_conn)
    assert [d["id"] for d in due] == [analytic_id]


def test_due_for_recheck_excludes_non_clean_and_rejected(db_conn):
    _seed_strategy_and_analytic(db_conn, backtest_disposition="needs_tuning")
    _seed_strategy_and_analytic(db_conn, backtest_disposition="clean", review_state="rejected")
    due = disposition_tracker.due_for_recheck(db_conn)
    assert due == []


def test_sweep_records_outcomes(db_conn, monkeypatch):
    analytic_id = _seed_strategy_and_analytic(db_conn)
    monkeypatch.setattr(disposition_tracker, "run_control_probe",
                        lambda client, body, artifact_id="": _FakeControlProbeResult(True))
    monkeypatch.setattr(disposition_tracker, "run_backtest",
                        lambda client, body, artifact_id="", with_evidence=True: _FakeBacktestOutcome(hits=0))

    outcomes = disposition_tracker.sweep(object(), db_conn, limit=10)
    assert len(outcomes) == 1
    assert outcomes[0].outcome == "still_clean"

    row = db_conn.execute(
        "SELECT outcome FROM disposition_checks WHERE analytic_id = ?", (analytic_id,)
    ).fetchone()
    assert row["outcome"] == "still_clean"
