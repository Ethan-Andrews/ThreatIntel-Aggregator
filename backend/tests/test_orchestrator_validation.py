"""Tests for process_one()'s stage 6-9 wiring (static_gate -> control_probe
-> backtest -> tune-if-needed), sequenced before the single register_analytic()
INSERT. Monkeypatches orchestrator's module-level stage functions directly,
same pattern as test_orchestrator_alignment.py."""

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection_pipeline import orchestrator


class _FakeDetection:
    def __init__(self, content, artifact_id="art-1", title="Test detection",
                 description="Test description"):
        self.content = content
        self.artifact_id = artifact_id
        self.title = title
        self.description = description


class _FakeReport:
    def __init__(self, gaps):
        self.gaps = gaps
        self.undetermined = []
        self.summary = {"covered": 0}


class _FakeCandidate:
    hash = "a" * 64
    title = "Test Project"
    link = "https://example.com/article"
    operation_id = "op-1"
    project_title = "Test Project"
    source = "TestFeed"
    source_tier = 1
    severity = "High"
    ttps = ["T1053.005"]
    stack_matched_items = []
    asset_scope = []


_CONTENT = (
    "// MITRE ATT&CK: T1053.005 - Scheduled Task/Job: Scheduled Task\n"
    "DeviceProcessEvents | where FileName == \"schtasks.exe\" | take 1"
)


class _FakeDetectionsClient:
    def create_project(self, **kwargs):
        return "proj-1"

    def generate_from_project(self, **kwargs):
        return "proj-1", _FakeReport(gaps=[]), [_FakeDetection(_CONTENT)]


def _fake_gate(verdict="pass", durability=1.0, findings=None):
    return types.SimpleNamespace(
        verdict=verdict, durability=durability, findings=findings or [],
    )


def _fake_control_result(telemetry_ok=True, disposition="ok", tables=("DeviceProcessEvents",)):
    plan = types.SimpleNamespace(
        probes=[types.SimpleNamespace(table=t) for t in tables]
    )
    return types.SimpleNamespace(
        telemetry_ok=telemetry_ok, disposition=disposition, plan=plan,
        to_row=lambda: {"disposition": disposition},
    )


def _fake_backtest_result(disposition="clean", hits=0):
    return types.SimpleNamespace(disposition=disposition, hits=hits)


def _fake_tune_result(disposition="tuned"):
    return types.SimpleNamespace(disposition=disposition, to_row=lambda: {"disposition": disposition})


def _analytic_row(db_conn, strategy_id):
    return db_conn.execute(
        "SELECT static_gate_verdict, static_gate_durability, backtest_disposition, "
        "tune_history, control_probe_result, review_state, name, description "
        "FROM analytics WHERE strategy_id = ?",
        (strategy_id,),
    ).fetchone()


def _strategy_id(db_conn, technique_id="T1053.005"):
    return db_conn.execute(
        "SELECT id FROM detection_strategies WHERE technique_id = ?", (technique_id,)
    ).fetchone()["id"]


def test_static_gate_reject_skips_everything_downstream(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: object())
    monkeypatch.setattr(orchestrator, "gate_evaluate", lambda *a, **k: _fake_gate(verdict="reject"))

    def _boom(*a, **k):
        raise AssertionError("must not run past a static-gate reject")
    monkeypatch.setattr(orchestrator, "run_control_probe", _boom)
    monkeypatch.setattr(orchestrator, "run_backtest", _boom)
    monkeypatch.setattr(orchestrator, "run_tune_loop", _boom)
    monkeypatch.setattr(orchestrator, "check_alignment", _boom)

    result = orchestrator.RunResult()
    orchestrator.process_one(_FakeDetectionsClient(), db_conn, _FakeCandidate(), "kql", result,
                             sentinel_client=object())

    row = _analytic_row(db_conn, _strategy_id(db_conn))
    assert row["static_gate_verdict"] == "reject"
    assert row["review_state"] == "rejected"
    assert row["backtest_disposition"] is None
    assert row["control_probe_result"] is None


def test_process_one_persists_detection_name_and_description(db_conn, monkeypatch):
    """The whole point of this fix: det.title/det.description (already
    returned by detections.ai at generation time) must reach the analytics
    row, not be silently dropped before register_analytic()."""
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: object())
    monkeypatch.setattr(orchestrator, "gate_evaluate", lambda *a, **k: _fake_gate(verdict="reject"))
    monkeypatch.setattr(orchestrator, "_build_sentinel_client", lambda: None)

    class _NamedDetectionsClient(_FakeDetectionsClient):
        def generate_from_project(self, **kwargs):
            return "proj-1", _FakeReport(gaps=[]), [_FakeDetection(
                _CONTENT, title="Suspicious Scheduled Task Creation",
                description="Flags schtasks.exe creating a new scheduled task.",
            )]

    result = orchestrator.RunResult()
    orchestrator.process_one(_NamedDetectionsClient(), db_conn, _FakeCandidate(), "kql", result,
                             sentinel_client=None)

    row = _analytic_row(db_conn, _strategy_id(db_conn))
    assert row["name"] == "Suspicious Scheduled Task Creation"
    assert row["description"] == "Flags schtasks.exe creating a new scheduled task."


def test_static_gate_pass_no_sentinel_registers_gate_only(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: None)
    monkeypatch.setattr(orchestrator, "gate_evaluate", lambda *a, **k: _fake_gate(verdict="pass", durability=0.9))

    def _boom(*a, **k):
        raise AssertionError("must not probe telemetry without a sentinel_client")
    monkeypatch.setattr(orchestrator, "run_control_probe", _boom)
    monkeypatch.setattr(orchestrator, "run_backtest", _boom)
    monkeypatch.setattr(orchestrator, "run_tune_loop", _boom)
    monkeypatch.setattr(orchestrator, "_build_sentinel_client", lambda: None)

    result = orchestrator.RunResult()
    orchestrator.process_one(_FakeDetectionsClient(), db_conn, _FakeCandidate(), "kql", result,
                             sentinel_client=None)

    row = _analytic_row(db_conn, _strategy_id(db_conn))
    assert row["static_gate_verdict"] == "pass"
    assert float(row["static_gate_durability"]) == 0.9
    assert row["review_state"] == "pending"
    assert row["backtest_disposition"] is None
    assert row["control_probe_result"] is None


def test_dead_telemetry_skips_backtest(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: None)
    monkeypatch.setattr(orchestrator, "gate_evaluate", lambda *a, **k: _fake_gate(verdict="pass"))
    monkeypatch.setattr(orchestrator, "run_control_probe",
                        lambda *a, **k: _fake_control_result(telemetry_ok=False, disposition="no_telemetry"))

    def _boom(*a, **k):
        raise AssertionError("must not backtest when telemetry isn't confirmed")
    monkeypatch.setattr(orchestrator, "run_backtest", _boom)
    monkeypatch.setattr(orchestrator, "run_tune_loop", _boom)

    result = orchestrator.RunResult()
    orchestrator.process_one(_FakeDetectionsClient(), db_conn, _FakeCandidate(), "kql", result,
                             sentinel_client=object())

    row = _analytic_row(db_conn, _strategy_id(db_conn))
    assert row["backtest_disposition"] is None
    assert row["control_probe_result"]["disposition"] == "no_telemetry"


def test_clean_backtest_skips_tuning(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: None)
    monkeypatch.setattr(orchestrator, "gate_evaluate", lambda *a, **k: _fake_gate(verdict="pass"))
    monkeypatch.setattr(orchestrator, "run_control_probe", lambda *a, **k: _fake_control_result())
    monkeypatch.setattr(orchestrator, "run_backtest",
                        lambda *a, **k: _fake_backtest_result(disposition="clean", hits=0))

    def _boom(*a, **k):
        raise AssertionError("must not tune a clean result")
    monkeypatch.setattr(orchestrator, "run_tune_loop", _boom)

    result = orchestrator.RunResult()
    orchestrator.process_one(_FakeDetectionsClient(), db_conn, _FakeCandidate(), "kql", result,
                             sentinel_client=object())

    row = _analytic_row(db_conn, _strategy_id(db_conn))
    assert row["backtest_disposition"] == "clean"
    assert row["tune_history"] is None


def test_needs_tuning_triggers_tune_loop(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: None)
    monkeypatch.setattr(orchestrator, "gate_evaluate", lambda *a, **k: _fake_gate(verdict="pass"))
    monkeypatch.setattr(orchestrator, "run_control_probe",
                        lambda *a, **k: _fake_control_result(tables=("DeviceProcessEvents",)))
    monkeypatch.setattr(orchestrator, "run_backtest",
                        lambda *a, **k: _fake_backtest_result(disposition="needs_tuning", hits=50))
    monkeypatch.setattr(orchestrator, "collect_distributions", lambda *a, **k: {})
    monkeypatch.setattr(orchestrator, "make_count_fn", lambda *a, **k: (lambda body: 0))
    monkeypatch.setattr(orchestrator, "make_field_population_fn", lambda *a, **k: (lambda dim: True))
    monkeypatch.setattr(orchestrator, "make_distribution_fn", lambda *a, **k: (lambda body: {}))

    calls = {}
    def _fake_tune(**kwargs):
        calls["field_population_fn_table_arg"] = True
        return _fake_tune_result(disposition="tuned")
    monkeypatch.setattr(orchestrator, "run_tune_loop", _fake_tune)

    result = orchestrator.RunResult()
    orchestrator.process_one(_FakeDetectionsClient(), db_conn, _FakeCandidate(), "kql", result,
                             sentinel_client=object())

    assert calls.get("field_population_fn_table_arg")
    row = _analytic_row(db_conn, _strategy_id(db_conn))
    assert row["backtest_disposition"] == "needs_tuning"
    assert row["tune_history"]["disposition"] == "tuned"


def test_gate_pass_with_ai_client_runs_alignment_check(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: object())
    monkeypatch.setattr(orchestrator, "gate_evaluate", lambda *a, **k: _fake_gate(verdict="pass"))
    monkeypatch.setattr(orchestrator, "run_control_probe",
                        lambda *a, **k: _fake_control_result(telemetry_ok=False, disposition="no_telemetry"))

    calls = {}
    def _fake_check_alignment(ai_client, sentinel_client, conn, strategy_id, analytic_id=None):
        calls["analytic_id"] = analytic_id
        return types.SimpleNamespace(verdict="aligned")
    monkeypatch.setattr(orchestrator, "check_alignment", _fake_check_alignment)

    result = orchestrator.RunResult()
    orchestrator.process_one(_FakeDetectionsClient(), db_conn, _FakeCandidate(), "kql", result,
                             sentinel_client=object())

    assert calls.get("analytic_id") is not None


def test_gate_reject_never_runs_alignment_check_even_with_ai_client(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: object())
    monkeypatch.setattr(orchestrator, "gate_evaluate", lambda *a, **k: _fake_gate(verdict="reject"))

    def _boom(*a, **k):
        raise AssertionError("check_alignment must not run on a rejected draft")
    monkeypatch.setattr(orchestrator, "check_alignment", _boom)

    result = orchestrator.RunResult()
    orchestrator.process_one(_FakeDetectionsClient(), db_conn, _FakeCandidate(), "kql", result,
                             sentinel_client=object())

    row = _analytic_row(db_conn, _strategy_id(db_conn))
    assert row["review_state"] == "rejected"
