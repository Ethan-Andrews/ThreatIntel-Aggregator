"""Tests for sentinel_hunt_test.py -- runs one Sentinel-native hunt query
through the same static-gate/control-probe/backtest/tune sequence
orchestrator.py already runs for AI-generated detections. Every stage
function is monkeypatched at the module-attribute level (not the underlying
Sentinel HTTP) since this module is a thin sequencing wrapper -- the stages
themselves already have their own dedicated test files."""

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection_pipeline import sentinel_hunt_test


def _gate(verdict="pass", findings=None):
    return types.SimpleNamespace(verdict=verdict, findings=findings or [])


def _control_result(telemetry_ok=True, row=None):
    return types.SimpleNamespace(
        telemetry_ok=telemetry_ok,
        to_row=lambda: row if row is not None else {"disposition": "ok", "tables": [{"table": "T"}]},
    )


def _backtest_result(disposition="clean", hits=0, error=""):
    return types.SimpleNamespace(disposition=disposition, hits=hits, error=error)


# --- run_query_check() -------------------------------------------------------

def test_run_query_check_gate_rejects_stops_before_any_sentinel_call(monkeypatch):
    monkeypatch.setattr(sentinel_hunt_test, "gate_evaluate", lambda body, **kw: _gate(
        verdict="reject", findings=[types.SimpleNamespace(code="TOO_BROAD", detail="no where clause")],
    ))
    called = {"control_probe": False}
    monkeypatch.setattr(
        sentinel_hunt_test, "run_control_probe",
        lambda *a, **kw: called.__setitem__("control_probe", True),
    )

    result = sentinel_hunt_test.run_query_check(object(), "T", "artifact-1", "title-1")

    assert result.gate_verdict == "reject"
    assert result.gate_findings == [{"code": "TOO_BROAD", "detail": "no where clause"}]
    assert result.error is not None
    assert called["control_probe"] is False


def test_run_query_check_no_sentinel_client_stops_after_gate(monkeypatch):
    monkeypatch.setattr(sentinel_hunt_test, "gate_evaluate", lambda body, **kw: _gate())
    result = sentinel_hunt_test.run_query_check(None, "T | take 1", "a", "t")
    assert result.gate_verdict == "pass"
    assert result.error == "no Sentinel client configured -- cannot probe telemetry or backtest"
    assert result.control_probe_result is None


def test_run_query_check_bad_telemetry_stops_before_backtest(monkeypatch):
    monkeypatch.setattr(sentinel_hunt_test, "gate_evaluate", lambda body, **kw: _gate())
    monkeypatch.setattr(
        sentinel_hunt_test, "run_control_probe",
        lambda *a, **kw: _control_result(telemetry_ok=False, row={"disposition": "no_telemetry"}),
    )
    called = {"backtest": False}
    monkeypatch.setattr(
        sentinel_hunt_test, "run_backtest",
        lambda *a, **kw: called.__setitem__("backtest", True),
    )

    result = sentinel_hunt_test.run_query_check(object(), "T | take 1", "a", "t")

    assert result.control_probe_result == {"disposition": "no_telemetry"}
    assert result.backtest_disposition is None
    assert called["backtest"] is False


def test_run_query_check_good_telemetry_runs_backtest(monkeypatch):
    monkeypatch.setattr(sentinel_hunt_test, "gate_evaluate", lambda body, **kw: _gate())
    monkeypatch.setattr(
        sentinel_hunt_test, "run_control_probe",
        lambda *a, **kw: _control_result(telemetry_ok=True),
    )
    monkeypatch.setattr(
        sentinel_hunt_test, "run_backtest",
        lambda *a, **kw: _backtest_result(disposition="needs_tuning", hits=5000),
    )

    result = sentinel_hunt_test.run_query_check(object(), "T | take 1", "a", "t")

    assert result.backtest_disposition == "needs_tuning"
    assert result.backtest_hits == 5000
    assert result.error is None


def test_run_query_check_backtest_error_is_surfaced(monkeypatch):
    monkeypatch.setattr(sentinel_hunt_test, "gate_evaluate", lambda body, **kw: _gate())
    monkeypatch.setattr(
        sentinel_hunt_test, "run_control_probe",
        lambda *a, **kw: _control_result(telemetry_ok=True),
    )
    monkeypatch.setattr(
        sentinel_hunt_test, "run_backtest",
        lambda *a, **kw: _backtest_result(error="query transport failure"),
    )

    result = sentinel_hunt_test.run_query_check(object(), "T | take 1", "a", "t")
    assert result.error == "query transport failure"


# --- run_query_tune() --------------------------------------------------------

def test_run_query_tune_no_probed_table_returns_none():
    result = sentinel_hunt_test.run_query_tune(
        object(), "T | take 1", "a", "t", backtest_hits=100, control_probe_result={"tables": []},
    )
    assert result is None


def test_run_query_tune_wires_primary_table_and_returns_to_row(monkeypatch):
    captured = {}

    def fake_run_tune_loop(**kwargs):
        captured.update(kwargs)
        return types.SimpleNamespace(to_row=lambda: {"disposition": "tuned", "final_body": "T | where X"})

    monkeypatch.setattr(sentinel_hunt_test, "collect_distributions", lambda *a, **kw: {})
    monkeypatch.setattr(sentinel_hunt_test, "make_count_fn", lambda *a, **kw: lambda *a2, **kw2: 0)
    monkeypatch.setattr(sentinel_hunt_test, "make_field_population_fn", lambda *a, **kw: lambda *a2, **kw2: 0)
    monkeypatch.setattr(sentinel_hunt_test, "make_distribution_fn", lambda *a, **kw: lambda *a2, **kw2: [])
    monkeypatch.setattr(sentinel_hunt_test, "run_tune_loop", fake_run_tune_loop)

    result = sentinel_hunt_test.run_query_tune(
        object(), "DeviceProcessEvents | take 1", "a", "t",
        backtest_hits=5000, control_probe_result={"tables": [{"table": "DeviceProcessEvents"}]},
    )

    assert result == {"disposition": "tuned", "final_body": "T | where X"}
    assert captured["original_hits"] == 5000
    assert captured["artifact_id"] == "a"


# --- build_sentinel_client() --------------------------------------------------

def test_build_sentinel_client_returns_none_on_construction_failure(monkeypatch):
    import detection_pipeline.sentinel as sentinel_module

    def _raise(*a, **kw):
        raise RuntimeError("no SENTINEL_WORKSPACE_ID configured")

    monkeypatch.setattr(sentinel_module, "SentinelClient", _raise)
    assert sentinel_hunt_test.build_sentinel_client() is None
