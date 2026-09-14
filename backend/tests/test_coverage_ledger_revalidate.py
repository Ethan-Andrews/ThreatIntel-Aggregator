"""revalidate_strategy() gains a second axis (alignment) alongside its
existing telemetry-probe check. Both feed the same one-way downgrade:
a bad result on either axis moves the strategy to needs_review."""

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import coverage_ledger


def _seed_strategy(conn, technique_id="T1053.005"):
    row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, "Scheduled Task", "Detect scheduled task creation", []),
    ).fetchone()
    conn.commit()
    return row["id"]


def _seed_analytic(conn, strategy_id, kql_body="DeviceProcessEvents | take 1"):
    conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body) VALUES (?, ?, ?)",
        (strategy_id, "test-hash", kql_body),
    )
    conn.commit()


def test_revalidate_strategy_downgrades_on_diverges_alignment(db_conn, monkeypatch):
    strategy_id = _seed_strategy(db_conn)
    _seed_analytic(db_conn, strategy_id)

    # No probes -- keep the existing telemetry axis at its 'degraded'-free
    # default by short-circuiting build_plan to report no probes at all,
    # isolating this test to the new alignment axis.
    monkeypatch.setattr(
        coverage_ledger, "check_alignment",
        lambda ai_client, sentinel_client, conn, sid, analytic_id=None:
            types.SimpleNamespace(verdict="diverges"),
    )

    class _NoProbePlan:
        probes = []
        def queries(self):
            return []

    # revalidate_strategy() now imports build_plan via the package-qualified
    # detection_pipeline.control_query path (see coverage_ledger.py's fix
    # for the run_probe exception-identity bug) so both this call and the
    # bare "control_query" alias need patching -- whichever this test
    # process resolves depends on which sys.modules entry already exists,
    # and package-qualified takes precedence when both are importable.
    monkeypatch.setattr("detection_pipeline.control_query.build_plan", lambda kql: _NoProbePlan())
    monkeypatch.setattr("control_query.build_plan", lambda kql: _NoProbePlan())

    worst = coverage_ledger.revalidate_strategy(None, db_conn, strategy_id, ai_client=object())

    assert worst in ("degraded", "error", "alignment_diverges")
    row = db_conn.execute(
        "SELECT status FROM detection_strategies WHERE id = ?", (strategy_id,)
    ).fetchone()
    assert row["status"] == "needs_review"


def test_revalidate_strategy_skips_alignment_when_no_ai_client(db_conn, monkeypatch):
    strategy_id = _seed_strategy(db_conn)
    _seed_analytic(db_conn, strategy_id)

    def _should_not_be_called(*args, **kwargs):
        raise AssertionError("check_alignment must not run without ai_client")

    monkeypatch.setattr(coverage_ledger, "check_alignment", _should_not_be_called)

    class _NoProbePlan:
        probes = []
        def queries(self):
            return []

    # revalidate_strategy() now imports build_plan via the package-qualified
    # detection_pipeline.control_query path (see coverage_ledger.py's fix
    # for the run_probe exception-identity bug) so both this call and the
    # bare "control_query" alias need patching -- whichever this test
    # process resolves depends on which sys.modules entry already exists,
    # and package-qualified takes precedence when both are importable.
    monkeypatch.setattr("detection_pipeline.control_query.build_plan", lambda kql: _NoProbePlan())
    monkeypatch.setattr("control_query.build_plan", lambda kql: _NoProbePlan())

    # ai_client defaults to None -- must not raise, must not call check_alignment.
    coverage_ledger.revalidate_strategy(None, db_conn, strategy_id)


def _set_last_validated(conn, strategy_id, when):
    conn.execute(
        "UPDATE detection_strategies SET last_validated_at = ? WHERE id = ?",
        (when, strategy_id),
    )
    conn.commit()


def test_due_for_revalidation_includes_never_validated_active_strategy(db_conn):
    strategy_id = _seed_strategy(db_conn)
    assert strategy_id in coverage_ledger.due_for_revalidation(db_conn)


def test_due_for_revalidation_excludes_recently_validated(db_conn):
    import datetime
    strategy_id = _seed_strategy(db_conn)
    _set_last_validated(db_conn, strategy_id, datetime.datetime.now(datetime.timezone.utc))
    assert strategy_id not in coverage_ledger.due_for_revalidation(db_conn)


def test_due_for_revalidation_includes_stale_validation(db_conn):
    import datetime
    strategy_id = _seed_strategy(db_conn)
    stale = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=48)
    _set_last_validated(db_conn, strategy_id, stale)
    assert strategy_id in coverage_ledger.due_for_revalidation(db_conn)


def test_due_for_revalidation_excludes_non_active_status(db_conn):
    strategy_id = _seed_strategy(db_conn)
    db_conn.execute(
        "UPDATE detection_strategies SET status = 'needs_review' WHERE id = ?",
        (strategy_id,),
    )
    db_conn.commit()
    assert strategy_id not in coverage_ledger.due_for_revalidation(db_conn)


def test_sweep_revalidation_covers_every_due_strategy(db_conn, monkeypatch):
    s1 = _seed_strategy(db_conn, technique_id="T1053.005")
    s2 = _seed_strategy(db_conn, technique_id="T1059")

    calls = []

    def _fake_revalidate(client, conn, strategy_id, ai_client=None, sentinel_client=None):
        calls.append(strategy_id)
        return "ok"

    monkeypatch.setattr(coverage_ledger, "revalidate_strategy", _fake_revalidate)

    results = coverage_ledger.sweep_revalidation(object(), db_conn)

    assert sorted(calls) == sorted([s1, s2])
    assert set(results) == {(s1, "ok"), (s2, "ok")}


def test_sweep_revalidation_continues_after_one_strategy_errors(db_conn, monkeypatch):
    s1 = _seed_strategy(db_conn, technique_id="T1053.005")
    s2 = _seed_strategy(db_conn, technique_id="T1059")

    def _flaky_revalidate(client, conn, strategy_id, ai_client=None, sentinel_client=None):
        if strategy_id == s1:
            raise RuntimeError("simulated Sentinel error")
        return "degraded"

    monkeypatch.setattr(coverage_ledger, "revalidate_strategy", _flaky_revalidate)

    results = coverage_ledger.sweep_revalidation(object(), db_conn)

    assert results == [(s2, "degraded")]
