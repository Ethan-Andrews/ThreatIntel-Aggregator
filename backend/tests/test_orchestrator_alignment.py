"""Tests that process_one() registers a strategy/analytic and runs the
alignment check when an AI client is configured, and skips both cleanly
when it isn't."""

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


class _FakeDetectionsClient:
    def create_project(self, **kwargs):
        return "proj-1"

    def generate_from_project(self, **kwargs):
        content = (
            "// MITRE ATT&CK: T1053.005 - Scheduled Task/Job: Scheduled Task\n"
            "DeviceProcessEvents | where FileName == \"schtasks.exe\" | take 1"
        )
        return "proj-1", _FakeReport(gaps=[]), [_FakeDetection(content)]


def test_process_one_registers_analytic_when_ai_client_configured(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: object())
    calls = {}

    def _fake_check_alignment(ai_client, sentinel_client, conn, strategy_id, analytic_id=None):
        calls["strategy_id"] = strategy_id
        calls["analytic_id"] = analytic_id
        return types.SimpleNamespace(verdict="aligned")

    monkeypatch.setattr(orchestrator, "check_alignment", _fake_check_alignment)

    result = orchestrator.RunResult()
    orchestrator.process_one(_FakeDetectionsClient(), db_conn, _FakeCandidate(), "kql", result)

    assert calls["analytic_id"] is not None
    strategy_row = db_conn.execute(
        "SELECT technique_id FROM detection_strategies WHERE id = ?", (calls["strategy_id"],)
    ).fetchone()
    assert strategy_row["technique_id"] == "T1053.005"


def test_process_one_skips_alignment_check_when_ai_not_configured(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: None)

    def _should_not_be_called(*args, **kwargs):
        raise AssertionError("check_alignment must not run without an AI client")

    monkeypatch.setattr(orchestrator, "check_alignment", _should_not_be_called)

    result = orchestrator.RunResult()
    orchestrator.process_one(_FakeDetectionsClient(), db_conn, _FakeCandidate(), "kql", result)

    # Registration still happens -- alignment checking is the part that's optional.
    row = db_conn.execute(
        "SELECT COUNT(*) FROM detection_strategies WHERE technique_id = ?", ("T1053.005",)
    ).fetchone()
    assert row[0] == 1
