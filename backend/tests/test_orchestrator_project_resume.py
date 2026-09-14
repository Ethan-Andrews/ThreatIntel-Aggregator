"""Tests that a candidate failing downstream of project creation resumes the
same detections.ai project on retry instead of creating a duplicate.

Confirmed live in prod (2026-08-20): one TI entry spawned 9+ duplicate
detections.ai projects across a few hours because process_one() kept failing
after create_project() but before outbox.mark_emitted(), and every retry
called generate_from_url() again, which unconditionally creates a fresh
project."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection_pipeline import orchestrator
from detection_pipeline.detections_client import DetectionsAIError


class _FakeReport:
    def __init__(self, gaps):
        self.gaps = gaps
        self.undetermined = []
        self.summary = {"covered": 0}


class _FakeCandidate:
    hash = "b" * 64
    title = "Test Project"
    link = "https://example.com/article"
    operation_id = "op-1"
    project_title = "Test Project"
    source = "TestFeed"
    source_tier = 1
    severity = "High"
    ttps = []
    stack_matched_items = []
    asset_scope = []


class _FailAfterCreateClient:
    """First call: creates a project, then blows up before generation
    finishes. Second call: must not create another project."""

    def __init__(self):
        self.create_project_calls = 0
        self.generate_from_project_calls = 0

    def create_project(self, **kwargs):
        self.create_project_calls += 1
        if self.create_project_calls > 1:
            raise AssertionError("must not create a second project on retry")
        return "proj-resumed"

    def generate_from_project(self, project_id, **kwargs):
        self.generate_from_project_calls += 1
        assert project_id == "proj-resumed"
        if self.generate_from_project_calls == 1:
            raise DetectionsAIError("simulated transient failure")
        return project_id, _FakeReport(gaps=[]), []


def test_project_id_saved_and_reused_after_downstream_failure(db_conn):
    client = _FailAfterCreateClient()
    result = orchestrator.RunResult()

    # First attempt: project gets created, then generation fails.
    orchestrator.process_one(client, db_conn, _FakeCandidate(), "kql", result)
    assert client.create_project_calls == 1
    assert client.generate_from_project_calls == 1

    saved = db_conn.execute(
        "SELECT project_id FROM detection_pipeline_attempts WHERE entry_hash = ?",
        (_FakeCandidate.hash,),
    ).fetchone()
    assert saved["project_id"] == "proj-resumed"

    # Second attempt (simulating the next scheduled run): must resume the
    # saved project, not create a new one.
    result2 = orchestrator.RunResult()
    orchestrator.process_one(client, db_conn, _FakeCandidate(), "kql", result2)
    assert client.create_project_calls == 1
    assert client.generate_from_project_calls == 2

    # Success clears the bookkeeping row.
    cleared = db_conn.execute(
        "SELECT project_id FROM detection_pipeline_attempts WHERE entry_hash = ?",
        (_FakeCandidate.hash,),
    ).fetchone()
    assert cleared is None
