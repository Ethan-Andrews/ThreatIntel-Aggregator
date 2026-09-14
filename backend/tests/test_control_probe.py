"""Tests for control_probe.py's worst-of aggregation. Pure-logic: run_probe
is monkeypatched, no DB or network needed."""

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import control_probe


def _outcome(error="", total=1, dead_fields=None, table="DeviceProcessEvents"):
    return types.SimpleNamespace(table=table, error=error, total=total,
                                 dead_fields=dead_fields or [])


def test_run_control_probe_no_plan_when_no_table_recognized(monkeypatch):
    result = control_probe.run_control_probe(object(), "print 1")
    assert result.disposition == "no_plan"
    assert result.telemetry_ok is False
    assert result.outcomes == []


def test_run_control_probe_ok_when_all_tables_healthy(monkeypatch):
    # run_control_probe now prefers the package-qualified detection_pipeline
    # .sentinel import (fix for the QuerySemanticError identity bug -- see
    # control_probe.py), so patch both names; whichever the code actually
    # resolves at call time is the one that needs to be a fake.
    monkeypatch.setattr(
        "detection_pipeline.sentinel.run_probe",
        lambda client, table, q: _outcome(total=500, table=table),
    )
    monkeypatch.setattr(
        "sentinel.run_probe",
        lambda client, table, q: _outcome(total=500, table=table),
    )
    content = 'DeviceProcessEvents | where FileName == "evil123.exe"'
    result = control_probe.run_control_probe(object(), content, artifact_id="a1")
    assert result.disposition == "ok"
    assert result.telemetry_ok is True
    assert len(result.outcomes) == 1


def test_run_control_probe_no_telemetry_when_table_empty(monkeypatch):
    monkeypatch.setattr(
        "detection_pipeline.sentinel.run_probe",
        lambda client, table, q: _outcome(total=0, table=table),
    )
    monkeypatch.setattr(
        "sentinel.run_probe",
        lambda client, table, q: _outcome(total=0, table=table),
    )
    content = 'DeviceProcessEvents | where FileName == "evil123.exe"'
    result = control_probe.run_control_probe(object(), content)
    assert result.disposition == "no_telemetry"
    assert result.telemetry_ok is False


def test_run_control_probe_worst_of_across_tables(monkeypatch):
    """A multi-table rule with one healthy table and one erroring table
    reports the worse disposition, not the first or last."""
    calls = {"n": 0}

    def fake_run_probe(client, table, q):
        calls["n"] += 1
        if calls["n"] == 1:
            return _outcome(total=500, table=table)
        return _outcome(error="boom", table=table)

    monkeypatch.setattr("detection_pipeline.sentinel.run_probe", fake_run_probe)
    monkeypatch.setattr("sentinel.run_probe", fake_run_probe)
    content = (
        'let a = DeviceProcessEvents | where FileName == "evil123.exe";\n'
        'let b = DeviceNetworkEvents | where RemoteIP == "1.2.3.4";\n'
        "union a, b"
    )
    result = control_probe.run_control_probe(object(), content)
    assert result.disposition == "probe_error"
    assert result.telemetry_ok is False
    assert len(result.outcomes) == 2


def test_to_row_shape():
    plan = control_probe.build_plan("print 1")
    result = control_probe.ControlProbeResult(
        plan=plan, outcomes=[_outcome(total=10, table="DeviceProcessEvents")],
        disposition="ok",
    )
    row = result.to_row()
    assert row["disposition"] == "ok"
    assert row["tables"][0]["table"] == "DeviceProcessEvents"
    assert row["tables"][0]["total"] == 10


# ---------------------------------------------------------- dead_predicate --
# The one severity level (_SEVERITY: dead_predicate=1) never exercised by any
# existing test before this file -- fittingly, the "dead field" disposition
# was itself dead code from a coverage standpoint.

def test_outcome_disposition_is_dead_predicate_when_fields_present_but_dead():
    outcome = _outcome(total=500, dead_fields=["InitiatingProcessAccountName"])
    assert control_probe._outcome_disposition(outcome) == "dead_predicate"


def test_run_control_probe_dead_predicate_when_only_dead_fields(monkeypatch):
    monkeypatch.setattr(
        "detection_pipeline.sentinel.run_probe",
        lambda client, table, q: _outcome(total=500, dead_fields=["FileName"], table=table),
    )
    monkeypatch.setattr(
        "sentinel.run_probe",
        lambda client, table, q: _outcome(total=500, dead_fields=["FileName"], table=table),
    )
    content = 'DeviceProcessEvents | where FileName == "evil123.exe"'
    result = control_probe.run_control_probe(object(), content)
    assert result.disposition == "dead_predicate"
    assert result.telemetry_ok is False


def test_run_control_probe_worst_of_ranks_no_telemetry_above_dead_predicate(monkeypatch):
    """Confirms the actual severity ordering (_SEVERITY), not just that
    probe_error beats ok: a dead-predicate table and a no-telemetry table
    together must report no_telemetry (severity 2), not dead_predicate
    (severity 1) -- regardless of which one the loop sees first."""
    calls = {"n": 0}

    def fake_run_probe(client, table, q):
        calls["n"] += 1
        if calls["n"] == 1:
            return _outcome(total=500, dead_fields=["FileName"], table=table)
        return _outcome(total=0, table=table)

    monkeypatch.setattr("detection_pipeline.sentinel.run_probe", fake_run_probe)
    monkeypatch.setattr("sentinel.run_probe", fake_run_probe)
    content = (
        'let a = DeviceProcessEvents | where FileName == "evil123.exe";\n'
        'let b = DeviceNetworkEvents | where RemoteIP == "1.2.3.4";\n'
        "union a, b"
    )
    result = control_probe.run_control_probe(object(), content)
    assert result.disposition == "no_telemetry"
    assert len(result.outcomes) == 2


def test_to_row_includes_dead_fields_and_error_per_table():
    plan = control_probe.build_plan("print 1")
    outcomes = [
        _outcome(total=500, dead_fields=["FileName"], table="DeviceProcessEvents"),
        _outcome(error="table not licensed", table="DeviceNetworkEvents"),
    ]
    result = control_probe.ControlProbeResult(plan=plan, outcomes=outcomes,
                                              disposition="probe_error")
    row = result.to_row()
    assert row["tables"][0]["dead_fields"] == ["FileName"]
    assert row["tables"][0]["disposition"] == "dead_predicate"
    assert row["tables"][1]["error"] == "table not licensed"
    assert row["tables"][1]["disposition"] == "probe_error"
