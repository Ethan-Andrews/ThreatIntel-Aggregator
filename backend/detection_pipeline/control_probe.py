"""Stage 6: aggregate the per-table control probe into one verdict for a
whole detection, on top of control_query.py's plan-builder and sentinel.py's
per-table run_probe().

Three call sites need "build a control plan, run it against Sentinel, decide
if telemetry is good enough": the primary generation path (orchestrator.py),
alignment_check.py's diverges-fix validation, and coverage_ledger.py's
revalidate_strategy(). Rather than a third or fourth hand-rolled aggregation,
this module is the one shared seam -- deterministic, no AI, same discipline
as static_gate.py/control_query.py/backtest.py/tune.py.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from control_query import build_plan, ControlPlan

# Worst-of ordering across a multi-table rule's probes: any table with a
# hard error dominates, then any table with genuinely no data, then any
# table whose fields are dead-but-present, and only "ok" across every table
# counts as telemetry_ok. A rule that touches five tables and is missing
# telemetry on just one still can't be trusted to fire correctly.
_SEVERITY = {"probe_error": 3, "no_telemetry": 2, "dead_predicate": 1, "ok": 0}


def _outcome_disposition(outcome) -> str:
    """Mirrors sentinel.ProbeOutcome.disposition's exact logic, but reads
    the raw .error/.total/.dead_fields fields directly instead of trusting
    a .disposition property -- test_alignment_check.py's fake probe outcome
    (types.SimpleNamespace) only sets the raw fields, so relying on a
    computed property here would work against the real ProbeOutcome
    dataclass but break against that existing test double."""
    if getattr(outcome, "error", ""):
        return "probe_error"
    if getattr(outcome, "total", 0) == 0:
        return "no_telemetry"
    if getattr(outcome, "dead_fields", None):
        return "dead_predicate"
    return "ok"


@dataclass
class ControlProbeResult:
    plan: ControlPlan
    outcomes: list = field(default_factory=list)     # list[sentinel.ProbeOutcome]
    disposition: str = "no_plan"
    # no_plan | probe_error | no_telemetry | dead_predicate | ok

    @property
    def telemetry_ok(self) -> bool:
        return self.disposition == "ok"

    def to_row(self) -> dict:
        """Shape for analytics.control_probe_result."""
        return {
            "disposition": self.disposition,
            "target": self.plan.target,
            "warnings": self.plan.warnings,
            "tables": [
                {
                    "table": getattr(o, "table", ""),
                    "total": getattr(o, "total", 0),
                    "devices": getattr(o, "devices", None),
                    "dead_fields": getattr(o, "dead_fields", None) or [],
                    "disposition": _outcome_disposition(o),
                    "error": getattr(o, "error", ""),
                }
                for o in self.outcomes
            ],
        }


def run_control_probe(client, content: str, artifact_id: str = "",
                      title: str = "") -> ControlProbeResult:
    """Build the control plan for `content` and run every probe it derives.

    `run_probe` is imported lazily, inside the function, not at module
    scope -- existing tests monkeypatch it at call time, which only takes
    effect against a late-bound lookup; a module-top import would silently
    stop picking up the patch.

    Prefer the package-qualified `detection_pipeline.sentinel` so this
    binds to the SAME module (and the same QuerySemanticError/SentinelError
    class objects) as `client`, which orchestrator.py always builds via
    `from detection_pipeline.sentinel import SentinelClient`. The bare
    `from sentinel import run_probe` fallback loads sentinel.py a second
    time under a different module name -- Python does not deduplicate that
    -- so its exception classes are distinct from
    detection_pipeline.sentinel's, and run_probe's own `except
    QuerySemanticError` would silently fail to match a real semantic error
    (bad table/column name), letting it escape error handling entirely
    instead of being recorded as a normal "error" outcome. Same bug and fix
    as coverage_ledger.py's revalidate_strategy(), confirmed live 2026-09-01.
    """
    try:
        from detection_pipeline.sentinel import run_probe
    except ImportError:  # running as a standalone script from this directory
        from sentinel import run_probe

    plan = build_plan(content, artifact_id=artifact_id, title=title)
    result = ControlProbeResult(plan=plan)

    if not plan.probes:
        return result

    outcomes = []
    worst = "ok"
    for table, query in plan.queries():
        outcome = run_probe(client, table, query)
        outcomes.append(outcome)
        disposition = _outcome_disposition(outcome)
        if _SEVERITY[disposition] > _SEVERITY[worst]:
            worst = disposition

    result.outcomes = outcomes
    result.disposition = worst
    return result
