"""Runs one Sentinel-native hunt query (sentinel_hunt_queries.kql_body)
through the same review/test/tune pipeline stages orchestrator.py already
runs for AI-generated detections -- see orchestrator.py's stage 6-9
sequencing (static gate -> control probe -> backtest -> bounded tuning).

Deliberately a thin wrapper, not a reimplementation: static_gate.evaluate(),
control_probe.run_control_probe(), and backtest.run_backtest() all already
take a raw KQL string and a client with zero dependency on the `analytics`
table, so they're directly reusable here. Only tune.run_tune_loop() needs
its three closures wired, exactly the way orchestrator.py's own stage 9
already does.

Called on demand (one query at a time, admin-triggered from the UI), not
as part of a batch sweep -- an analyst chooses which of a hunt's 800+
queries to actually spend Sentinel query budget validating, rather than
this pipeline testing all of them unprompted on every sync.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from detection_pipeline.static_gate import evaluate as gate_evaluate
from detection_pipeline.control_probe import run_control_probe
from detection_pipeline.backtest import (
    run_backtest,
    rule_body,
    DEFAULT_LOOKBACK_DAYS as BACKTEST_LOOKBACK_DAYS,
)
from detection_pipeline.tune import (
    run_tune_loop,
    collect_distributions,
    make_count_fn,
    make_field_population_fn,
    make_distribution_fn,
)


logger = logging.getLogger(__name__)


def build_sentinel_client():
    """Same construction pattern as orchestrator.py's own
    _build_sentinel_client() (data-plane SentinelClient, distinct from
    sentinel_hunting's/sentinel_hunt_sync's ARM control-plane clients) --
    never raises, returns None on any config/credential problem so an
    admin-triggered test/tune call fails with a clear per-query error
    instead of a 500."""
    from detection_pipeline.sentinel import SentinelClient
    try:
        return SentinelClient()
    except Exception as exc:
        logger.warning("SentinelClient unavailable for hunt query test/tune: %s", exc)
        return None


@dataclass
class QueryCheckResult:
    gate_verdict: str                   # pass | reject
    gate_findings: list
    control_probe_result: dict | None = None   # ControlProbeResult.to_row(), or None if gated out
    backtest_disposition: str | None = None
    backtest_hits: int | None = None
    error: str | None = None            # set when the gate itself rejected, or no sentinel_client


def run_query_check(
    sentinel_client, kql_body: str, artifact_id: str, title: str,
    available_tables: set[str] | None = None,
) -> QueryCheckResult:
    """Stages 6-8: static gate, then (if it passes and a live client is
    available) the real telemetry control probe, then a backtest. Mirrors
    orchestrator.py's process_one() sequencing exactly, minus the
    stage-9 tune loop -- see run_query_tune() for that, called separately
    once a backtest reports needs_tuning.

    available_tables is the same cached Sentinel table catalog
    orchestrator.py passes into gate_evaluate() (sentinel_table_sync.
    get_cached_tables()) -- callers here fetch it once per request and
    pass it in; None falls back to static_gate's own DEFAULT_MDE_TABLES,
    same as an empty/never-synced cache does everywhere else."""
    gate = gate_evaluate(
        kql_body, artifact_id=artifact_id, title=title, available_tables=available_tables,
    )
    result = QueryCheckResult(
        gate_verdict=gate.verdict,
        gate_findings=[{"code": f.code, "detail": f.detail} for f in gate.findings],
    )
    if gate.verdict != "pass":
        result.error = "static gate rejected this query -- see gate_findings"
        return result
    if sentinel_client is None:
        result.error = "no Sentinel client configured -- cannot probe telemetry or backtest"
        return result

    control_result = run_control_probe(sentinel_client, kql_body, artifact_id=artifact_id, title=title)
    result.control_probe_result = control_result.to_row()
    if not control_result.telemetry_ok:
        return result

    backtest_result = run_backtest(sentinel_client, kql_body, artifact_id=artifact_id, title=title)
    result.backtest_disposition = backtest_result.disposition
    result.backtest_hits = backtest_result.hits
    if backtest_result.error:
        result.error = backtest_result.error
    return result


def run_query_tune(sentinel_client, kql_body: str, artifact_id: str, title: str,
                   backtest_hits: int, control_probe_result: dict) -> dict | None:
    """Stage 9: bounded narrowing loop, for a query whose backtest already
    reported needs_tuning. Returns tune.TuneResult.to_row(), or None if
    there's no primary probed table to narrow against (mirrors
    orchestrator.py's own primary_table lookup)."""
    probes = (control_probe_result or {}).get("tables") or []
    if not probes:
        return None
    primary_table = probes[0]["table"]

    body = rule_body(kql_body)
    timespan = f"P{BACKTEST_LOOKBACK_DAYS}D"
    distributions = collect_distributions(sentinel_client, body, timespan)
    tune_result = run_tune_loop(
        artifact_id=artifact_id, title=title, body=body,
        original_hits=backtest_hits, distributions=distributions,
        count_fn=make_count_fn(sentinel_client, timespan),
        field_population_fn=make_field_population_fn(sentinel_client, primary_table),
        distribution_fn=make_distribution_fn(sentinel_client, timespan),
    )
    return tune_result.to_row()
