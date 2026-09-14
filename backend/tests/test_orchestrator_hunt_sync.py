"""Tests that process_one() only auto-syncs a hunt to Sentinel when
hunt_sync_settings.mode == 'auto', and only passes detections that clear the
static-gate + backtest bar (plus alignment, when require_alignment is set).
'off' (default) and 'manual' must never call sentinel_hunting.sync_hunt()
automatically -- see hunts.get_sync_eligible_detections() for the shared
eligibility filter and main.py's deploy endpoint for the manual path."""

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection_pipeline import hunt_sync_settings, orchestrator


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
    return types.SimpleNamespace(verdict=verdict, durability=durability, findings=findings or [])


def _fake_control_result(telemetry_ok=True, disposition="ok", tables=("DeviceProcessEvents",)):
    plan = types.SimpleNamespace(probes=[types.SimpleNamespace(table=t) for t in tables])
    return types.SimpleNamespace(
        telemetry_ok=telemetry_ok, disposition=disposition, plan=plan,
        to_row=lambda: {"disposition": disposition},
    )


def _fake_backtest_result(disposition="clean", hits=0):
    return types.SimpleNamespace(disposition=disposition, hits=hits)


def _run_clean_detection(db_conn, monkeypatch):
    """process_one() with a static-gate pass and a clean backtest -- the
    detection ends up eligible for sync (gate pass + backtest clean),
    without a MITRE alignment status set (so require_alignment=True would
    exclude it)."""
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: None)
    monkeypatch.setattr(orchestrator, "gate_evaluate", lambda *a, **k: _fake_gate(verdict="pass"))
    monkeypatch.setattr(orchestrator, "run_control_probe", lambda *a, **k: _fake_control_result())
    monkeypatch.setattr(orchestrator, "run_backtest",
                        lambda *a, **k: _fake_backtest_result(disposition="clean", hits=0))

    result = orchestrator.RunResult()
    orchestrator.process_one(_FakeDetectionsClient(), db_conn, _FakeCandidate(), "kql", result,
                             sentinel_client=object())


def test_off_mode_never_calls_sync_hunt(db_conn, monkeypatch):
    hunt_sync_settings.set_settings(db_conn, "off", True, "tester")

    def _boom(*a, **k):
        raise AssertionError("sync_hunt must not be called when mode is 'off'")
    monkeypatch.setattr(orchestrator.sentinel_hunting, "sync_hunt", _boom)

    _run_clean_detection(db_conn, monkeypatch)


def test_manual_mode_never_calls_sync_hunt_automatically(db_conn, monkeypatch):
    hunt_sync_settings.set_settings(db_conn, "manual", True, "tester")

    def _boom(*a, **k):
        raise AssertionError("sync_hunt must not be called automatically when mode is 'manual'")
    monkeypatch.setattr(orchestrator.sentinel_hunting, "sync_hunt", _boom)

    _run_clean_detection(db_conn, monkeypatch)


def test_auto_mode_with_require_alignment_skips_unaligned_detection(db_conn, monkeypatch):
    """Default require_alignment=True: a clean-backtest detection with no
    recorded MITRE alignment status must not be synced."""
    hunt_sync_settings.set_settings(db_conn, "auto", True, "tester")

    def _boom(*a, **k):
        raise AssertionError("sync_hunt must not be called: detection isn't MITRE-aligned")
    monkeypatch.setattr(orchestrator.sentinel_hunting, "sync_hunt", _boom)

    _run_clean_detection(db_conn, monkeypatch)


def test_auto_mode_without_require_alignment_syncs_eligible_detection(db_conn, monkeypatch):
    hunt_sync_settings.set_settings(db_conn, "auto", False, "tester")

    calls = {}
    def _fake_sync_hunt(conn, hunt_id, *, hunt_title, hunt_description, detections,
                       target_sentinel_hunt_id=None):
        calls["hunt_id"] = hunt_id
        calls["detections"] = detections
    monkeypatch.setattr(orchestrator.sentinel_hunting, "sync_hunt", _fake_sync_hunt)

    _run_clean_detection(db_conn, monkeypatch)

    assert calls, "sync_hunt should have been called"
    assert len(calls["detections"]) == 1
    assert calls["detections"][0]["technique_id"] == "T1053.005"


# --- Workstream E: severity gate + cadence -----------------------------
# docs/superpowers/specs/2026-09-04-live-feedback-round-6-design.md

def test_auto_mode_severity_gate_excludes_hunt_not_in_configured_set(db_conn, monkeypatch):
    """_FakeCandidate.severity == 'High' -> hunts.source_severity == 'High'.
    A severities set that doesn't include 'high' must skip this hunt's
    auto-sync silently -- never call sync_hunt, never mark it failed."""
    hunt_sync_settings.set_settings(db_conn, "auto", False, "tester")
    hunt_sync_settings.set_schedule(
        db_conn, severities=["critical"], interval_minutes=30,
        window_start_minute=None, window_end_minute=None, days_of_week=None,
        updated_by="tester",
    )

    def _boom(*a, **k):
        raise AssertionError("sync_hunt must not be called: severity not in configured set")
    monkeypatch.setattr(orchestrator.sentinel_hunting, "sync_hunt", _boom)

    _run_clean_detection(db_conn, monkeypatch)


def test_auto_mode_severity_gate_includes_matching_hunt(db_conn, monkeypatch):
    hunt_sync_settings.set_settings(db_conn, "auto", False, "tester")
    hunt_sync_settings.set_schedule(
        db_conn, severities=["high", "critical"], interval_minutes=30,
        window_start_minute=None, window_end_minute=None, days_of_week=None,
        updated_by="tester",
    )

    calls = {}
    def _fake_sync_hunt(conn, hunt_id, *, hunt_title, hunt_description, detections,
                       target_sentinel_hunt_id=None):
        calls["hunt_id"] = hunt_id
    monkeypatch.setattr(orchestrator.sentinel_hunting, "sync_hunt", _fake_sync_hunt)

    _run_clean_detection(db_conn, monkeypatch)

    assert calls, "sync_hunt should have been called: 'high' is in the configured set"


def test_auto_mode_severities_none_preserves_default_behavior(db_conn, monkeypatch):
    """severities left NULL (never configured) must impose no restriction
    at all -- same as this file's pre-existing (unqualified) auto-mode
    test, just asserted explicitly against set_schedule's own default."""
    hunt_sync_settings.set_settings(db_conn, "auto", False, "tester")
    hunt_sync_settings.set_schedule(
        db_conn, severities=None, interval_minutes=30,
        window_start_minute=None, window_end_minute=None, days_of_week=None,
        updated_by="tester",
    )

    calls = {}
    def _fake_sync_hunt(conn, hunt_id, *, hunt_title, hunt_description, detections,
                       target_sentinel_hunt_id=None):
        calls["hunt_id"] = hunt_id
    monkeypatch.setattr(orchestrator.sentinel_hunting, "sync_hunt", _fake_sync_hunt)

    _run_clean_detection(db_conn, monkeypatch)

    assert calls, "no severity restriction configured -- every eligible hunt must still sync"


def test_auto_mode_cadence_gate_skips_when_not_due(db_conn, monkeypatch):
    """A very long interval, with last_run_at just set to now, must skip
    this cycle's auto-sync -- reuses orchestrator_settings.is_due() as-is."""
    hunt_sync_settings.set_settings(db_conn, "auto", False, "tester")
    hunt_sync_settings.set_schedule(
        db_conn, severities=None, interval_minutes=10080,
        window_start_minute=None, window_end_minute=None, days_of_week=None,
        updated_by="tester",
    )
    hunt_sync_settings.mark_run_started(db_conn)

    def _boom(*a, **k):
        raise AssertionError("sync_hunt must not be called: not due yet per the cadence gate")
    monkeypatch.setattr(orchestrator.sentinel_hunting, "sync_hunt", _boom)

    _run_clean_detection(db_conn, monkeypatch)


def test_auto_mode_cadence_gate_no_prior_run_is_due_immediately(db_conn, monkeypatch):
    """last_run_at is NULL (never auto-synced before) -- orchestrator_
    settings.is_due() treats this as due immediately, same fail-open
    behavior the orchestrator's own schedule gate already relies on."""
    hunt_sync_settings.set_settings(db_conn, "auto", False, "tester")
    hunt_sync_settings.set_schedule(
        db_conn, severities=None, interval_minutes=10080,
        window_start_minute=None, window_end_minute=None, days_of_week=None,
        updated_by="tester",
    )

    calls = {}
    def _fake_sync_hunt(conn, hunt_id, *, hunt_title, hunt_description, detections,
                       target_sentinel_hunt_id=None):
        calls["hunt_id"] = hunt_id
    monkeypatch.setattr(orchestrator.sentinel_hunting, "sync_hunt", _fake_sync_hunt)

    _run_clean_detection(db_conn, monkeypatch)

    assert calls, "no prior run recorded -- must be due immediately regardless of interval_minutes"


# --- Auto-deploy default target (2026-09-04, post-round-6 follow-up) ------
# User ask: let 'auto' mode target one configured Sentinel Hunt by default,
# instead of always creating a dedicated hunt per TI article, while a
# hunt's own explicit per-hunt override (hunts.set_hunt_target()) still
# wins when both are set.

def test_auto_mode_passes_none_target_when_nothing_configured(db_conn, monkeypatch):
    """Baseline: no per-hunt override, no auto-deploy default configured --
    target_sentinel_hunt_id must reach sync_hunt() as None, preserving
    today's original "dedicated hunt per article" behavior exactly."""
    hunt_sync_settings.set_settings(db_conn, "auto", False, "tester")

    calls = {}
    def _fake_sync_hunt(conn, hunt_id, *, hunt_title, hunt_description, detections,
                       target_sentinel_hunt_id=None):
        calls["target_sentinel_hunt_id"] = target_sentinel_hunt_id
    monkeypatch.setattr(orchestrator.sentinel_hunting, "sync_hunt", _fake_sync_hunt)

    _run_clean_detection(db_conn, monkeypatch)

    assert calls == {"target_sentinel_hunt_id": None}


def test_auto_mode_falls_back_to_auto_deploy_default_when_no_per_hunt_target(db_conn, monkeypatch):
    hunt_sync_settings.set_settings(db_conn, "auto", False, "tester")
    hunt_sync_settings.set_auto_deploy_target(db_conn, "default-target-guid", "tester")
    # resolve_auto_deploy_target() checks sentinel_hunts.query_count -- no
    # row at all for this id means "not over threshold," so it must pass
    # the configured default straight through.
    monkeypatch.setattr(
        orchestrator.sentinel_hunting, "resolve_auto_deploy_target",
        lambda conn: "default-target-guid",
    )

    calls = {}
    def _fake_sync_hunt(conn, hunt_id, *, hunt_title, hunt_description, detections,
                       target_sentinel_hunt_id=None):
        calls["target_sentinel_hunt_id"] = target_sentinel_hunt_id
    monkeypatch.setattr(orchestrator.sentinel_hunting, "sync_hunt", _fake_sync_hunt)

    _run_clean_detection(db_conn, monkeypatch)

    assert calls == {"target_sentinel_hunt_id": "default-target-guid"}


def test_auto_mode_per_hunt_target_wins_over_auto_deploy_default(db_conn, monkeypatch):
    """A hunt's own explicit target_sentinel_hunt_id (set via hunts.set_
    hunt_target()) must be used even when a global auto-deploy default is
    also configured -- the per-hunt override is more specific and must not
    be silently overridden by a workspace-wide default."""
    from detection_pipeline import hunts as hunts_module

    hunt_sync_settings.set_settings(db_conn, "auto", False, "tester")
    hunt_sync_settings.set_auto_deploy_target(db_conn, "global-default-guid", "tester")
    # Pre-create the hunt process_one() will reuse (get_or_create_hunt() is
    # idempotent by source_entry_hash == _FakeCandidate.hash), then give it
    # its own explicit override.
    hunt_id = hunts_module.get_or_create_hunt(db_conn, _FakeCandidate.hash, title="Test Project")
    hunts_module.set_hunt_target(db_conn, hunt_id, "per-hunt-override-guid")

    def _boom_resolve(conn):
        raise AssertionError(
            "resolve_auto_deploy_target must not even be consulted when a per-hunt target is set"
        )
    monkeypatch.setattr(orchestrator.sentinel_hunting, "resolve_auto_deploy_target", _boom_resolve)

    calls = {}
    def _fake_sync_hunt(conn, hunt_id, *, hunt_title, hunt_description, detections,
                       target_sentinel_hunt_id=None):
        calls["target_sentinel_hunt_id"] = target_sentinel_hunt_id
    monkeypatch.setattr(orchestrator.sentinel_hunting, "sync_hunt", _fake_sync_hunt)

    _run_clean_detection(db_conn, monkeypatch)

    assert calls == {"target_sentinel_hunt_id": "per-hunt-override-guid"}
