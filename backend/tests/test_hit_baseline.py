"""due_for_baseline()/sweep_baseline(): the automated-path wiring for
hit_baseline.py, which previously only ever ran manually per analytic via
its CLI. assess_hit()/assess_and_record() themselves are exercised
indirectly here through the monkeypatched sweep path -- their own scoring
logic is documented in the module docstring and not re-tested here."""

import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import hit_baseline


def _seed_strategy(conn, technique_id="T1053.005"):
    row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, "Scheduled Task", "Detect scheduled task creation", []),
    ).fetchone()
    conn.commit()
    return row["id"]


def _seed_analytic(conn, strategy_id, review_state="approved",
                   kql_body="DeviceProcessEvents | take 1"):
    row = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, review_state) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (strategy_id, "test-hash", kql_body, review_state),
    ).fetchone()
    conn.commit()
    return row["id"]


def _record(conn, analytic_id, when, dimension="InitiatingProcessAccountName",
           entity_value="svc_test", hit_count=1):
    conn.execute(
        "INSERT INTO hit_baseline (analytic_id, dimension, entity_value, "
        "window_start, hit_count, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
        (analytic_id, dimension, entity_value, when.date(), hit_count, when),
    )
    conn.commit()


def test_due_for_baseline_includes_never_baselined_approved_analytic(db_conn):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id)

    due = hit_baseline.due_for_baseline(db_conn)

    assert [row["id"] for row in due] == [analytic_id]


def test_due_for_baseline_excludes_pending_or_rejected_analytics(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_analytic(db_conn, strategy_id, review_state="pending")
    _seed_analytic(db_conn, strategy_id, review_state="rejected")

    assert hit_baseline.due_for_baseline(db_conn) == []


def test_due_for_baseline_excludes_recently_recorded(db_conn):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id)
    _record(db_conn, analytic_id, datetime.datetime.now(datetime.timezone.utc))

    due = hit_baseline.due_for_baseline(db_conn)

    assert analytic_id not in [row["id"] for row in due]


def test_due_for_baseline_includes_stale_recording(db_conn):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id)
    stale = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=12)
    _record(db_conn, analytic_id, stale)

    due = hit_baseline.due_for_baseline(db_conn)

    assert analytic_id in [row["id"] for row in due]


def test_sweep_baseline_covers_every_due_analytic(db_conn, monkeypatch):
    strategy_id = _seed_strategy(db_conn)
    a1 = _seed_analytic(db_conn, strategy_id, kql_body="DeviceProcessEvents | take 1")
    a2 = _seed_analytic(db_conn, strategy_id, kql_body="DeviceNetworkEvents | take 1")

    calls = []

    def _fake_assess_and_record(client, conn, analytic_id, body, as_of=None):
        calls.append(analytic_id)
        return []

    monkeypatch.setattr(hit_baseline, "assess_and_record", _fake_assess_and_record)

    results = hit_baseline.sweep_baseline(object(), db_conn)

    assert sorted(calls) == sorted([a1, a2])
    assert {analytic_id for analytic_id, _ in results} == {a1, a2}


def test_sweep_baseline_continues_after_one_analytic_errors(db_conn, monkeypatch):
    strategy_id = _seed_strategy(db_conn)
    a1 = _seed_analytic(db_conn, strategy_id, kql_body="DeviceProcessEvents | take 1")
    a2 = _seed_analytic(db_conn, strategy_id, kql_body="DeviceNetworkEvents | take 1")

    def _flaky_assess(client, conn, analytic_id, body, as_of=None):
        if analytic_id == a1:
            raise RuntimeError("simulated Sentinel error")
        return []

    monkeypatch.setattr(hit_baseline, "assess_and_record", _flaky_assess)

    results = hit_baseline.sweep_baseline(object(), db_conn)

    assert [analytic_id for analytic_id, _ in results] == [a2]
