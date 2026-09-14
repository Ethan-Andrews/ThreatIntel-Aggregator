"""Stage 9: periodic re-confirmation that a shipped 'clean'-disposition
analytic hasn't silently rotted.

A clean rule (backtest_disposition == 'clean', hits == 0 over 90 days) can
rot two different ways: it starts genuinely firing, or the telemetry it
depends on dies underneath it -- which *also* reports zero hits, and looks
identical to "still clean" unless something re-checks the telemetry itself.
That second failure mode is exactly the "invisible failure visibility"
problem explain.md names for behavioral detections: a rule that drifted
still shows green. So this module re-runs both the control probe (is the
telemetry even still there) and a fresh backtest (has it started firing),
not backtest alone.

Deterministic, no AI -- same discipline as static_gate/control_query/
backtest/tune. Runs as a bounded per-batch sweep, not continuously and not
against every clean analytic every run: orchestrator.py's job is a one-shot
batch that runs to completion every 30 minutes, not a persistent process,
so "rot" gets checked on a schedule that fits inside that model instead of
assuming a different one.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from control_probe import run_control_probe
from backtest import run_backtest

DEFAULT_SWEEP_LIMIT = 10
MIN_RECHECK_INTERVAL_HOURS = 24


@dataclass
class DispositionOutcome:
    analytic_id: int
    outcome: str
    # still_clean | now_firing | telemetry_decayed | check_error
    hits: int | None = None
    window_hours: float | None = None
    control_probe_disposition: str = "no_plan"
    backtest_disposition: str | None = None
    detail: dict = field(default_factory=dict)


def check_one(client, analytic_id: int, kql_body: str) -> DispositionOutcome:
    """Re-run the control probe, then (only if telemetry is confirmed) a
    fresh backtest, for one previously-clean analytic."""
    probe = run_control_probe(client, kql_body, artifact_id=f"disposition-{analytic_id}")

    if not probe.telemetry_ok:
        return DispositionOutcome(
            analytic_id=analytic_id,
            outcome="telemetry_decayed",
            control_probe_disposition=probe.disposition,
            detail=probe.to_row(),
        )

    bt = run_backtest(client, kql_body, artifact_id=f"disposition-{analytic_id}",
                      with_evidence=False)

    if bt.error:
        return DispositionOutcome(
            analytic_id=analytic_id,
            outcome="check_error",
            control_probe_disposition=probe.disposition,
            backtest_disposition=bt.disposition,
            detail={"error": bt.error},
        )

    outcome = "still_clean" if bt.hits == 0 else "now_firing"
    return DispositionOutcome(
        analytic_id=analytic_id,
        outcome=outcome,
        hits=bt.hits,
        window_hours=bt.window_hours,
        control_probe_disposition=probe.disposition,
        backtest_disposition=bt.disposition,
    )


def record(conn, outcome: DispositionOutcome) -> int:
    import json
    row = conn.execute(
        "INSERT INTO disposition_checks "
        "(analytic_id, hits, window_hours, control_probe_disposition, "
        " backtest_disposition, outcome, detail) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
        (outcome.analytic_id, outcome.hits, outcome.window_hours,
         outcome.control_probe_disposition, outcome.backtest_disposition,
         outcome.outcome, json.dumps(outcome.detail)),
    ).fetchone()
    conn.commit()
    return row["id"]


def due_for_recheck(conn, limit: int = DEFAULT_SWEEP_LIMIT,
                    min_interval_hours: int = MIN_RECHECK_INTERVAL_HOURS) -> list[dict]:
    """Clean, non-rejected analytics never checked, or last checked before
    the cutoff -- oldest-checked-first (never-checked sorts first)."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=min_interval_hours)
    rows = conn.execute(
        "SELECT a.id, a.kql_body, MAX(dc.checked_at) AS last_checked "
        "FROM analytics a "
        "LEFT JOIN disposition_checks dc ON dc.analytic_id = a.id "
        "WHERE a.backtest_disposition = 'clean' AND a.review_state != 'rejected' "
        "GROUP BY a.id, a.kql_body "
        "HAVING MAX(dc.checked_at) IS NULL OR MAX(dc.checked_at) < ? "
        "ORDER BY MAX(dc.checked_at) ASC NULLS FIRST "
        "LIMIT ?",
        (cutoff, limit),
    ).fetchall()
    return [{"id": r["id"], "kql_body": r["kql_body"]} for r in rows]


def sweep(client, conn, limit: int = DEFAULT_SWEEP_LIMIT) -> list[DispositionOutcome]:
    """due_for_recheck() -> check_one() -> record(), once per orchestrator
    run (after the candidate batch, not per candidate) -- rot is a function
    of time passing, not of new TI arriving."""
    outcomes = []
    for row in due_for_recheck(conn, limit=limit):
        outcome = check_one(client, row["id"], row["kql_body"])
        record(conn, outcome)
        outcomes.append(outcome)
    return outcomes
