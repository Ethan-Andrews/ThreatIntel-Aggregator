"""Tests for process_one()'s core control-flow branches that had zero prior
coverage before this file existed: the no-link skip, the terminal
PreprocessingFailed path, the transient PollTimeout/DetectionsAIError
retry-and-give-up contract (MAX_ATTEMPTS), the no-gaps fully_covered path,
and the extract_technique()-returns-None / check_coverage()-reuse paths.

Written for item C of the sentinel-hunts-sync handoff: a top-to-bottom
enumeration of every branch in orchestrator.py found these had never been
directly exercised -- every existing orchestrator test starts from a
candidate whose generate_from_project() already succeeds with a resolvable
gap, so the module's own retry/skip contract (the reason MAX_ATTEMPTS and
the PreprocessingFailed/transient split exist at all) was untested."""

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection_pipeline import orchestrator
from detection_pipeline.detections_client import PreprocessingFailed, DetectionsAIError, PollTimeout


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
    hash = "c" * 64
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


def _fake_gate(verdict="pass", durability=1.0, findings=None):
    return types.SimpleNamespace(verdict=verdict, durability=durability, findings=findings or [])


def _fake_gap(technique_id="T1053.005", title="Test gap"):
    return types.SimpleNamespace(
        primary_mitre_attack_id=technique_id, data_source="test",
        opportunity_title=title,
    )


# ---------------------------------------------------------------- no-link --

class _NoLinkCandidate(_FakeCandidate):
    hash = "d" * 64
    link = ""


def test_no_link_marks_emitted_and_skips_without_touching_the_client(db_conn):
    class _BoomIfCalledClient:
        def create_project(self, **kwargs):
            raise AssertionError("must not create a project when cand.link is empty")

        def generate_from_project(self, **kwargs):
            raise AssertionError("must not generate when cand.link is empty")

    result = orchestrator.RunResult()
    orchestrator.process_one(_BoomIfCalledClient(), db_conn, _NoLinkCandidate(), "kql", result)

    assert result.skipped == 1
    assert result.generated == 0


# ----------------------------------------------------- PreprocessingFailed --

class _PreprocessingFailedClient:
    def __init__(self):
        self.create_project_calls = 0

    def create_project(self, **kwargs):
        self.create_project_calls += 1
        return "proj-preproc"

    def generate_from_project(self, **kwargs):
        raise PreprocessingFailed("article could not be fetched")


def test_preprocessing_failed_is_terminal_marks_emitted_once(db_conn):
    """A permanently-unfetchable article must not be retried -- the identical
    failure would recur on every run, starving the rest of the queue."""
    client = _PreprocessingFailedClient()
    result = orchestrator.RunResult()

    orchestrator.process_one(client, db_conn, _FakeCandidate(), "kql", result)

    assert result.skipped == 1
    assert result.failed == 0
    assert client.create_project_calls == 1

    # A bookkeeping row does exist here (created by _save_project() right
    # after create_project() succeeds, before generate_from_project() ever
    # raises) -- but its attempts count stays 0, since _record_failure() is
    # only called from the transient-failure branch, never this terminal
    # one. Confirmed by running this test first without this assertion and
    # inspecting what was actually there, rather than assuming "terminal
    # means no row at all."
    row = db_conn.execute(
        "SELECT attempts, project_id FROM detection_pipeline_attempts WHERE entry_hash = ?",
        (_FakeCandidate.hash,),
    ).fetchone()
    assert row["attempts"] == 0
    assert row["project_id"] == "proj-preproc"


# --------------------------------------- transient failure + MAX_ATTEMPTS --

class _AlwaysTransientFailureClient:
    """Simulates a candidate whose generation fails the same transient way
    on every single run -- the real-world shape MAX_ATTEMPTS exists for."""

    def create_project(self, **kwargs):
        return "proj-transient"

    def generate_from_project(self, **kwargs):
        raise DetectionsAIError("simulated rate limit")


def test_transient_failure_is_retried_up_to_max_attempts_then_given_up(db_conn):
    client = _AlwaysTransientFailureClient()

    # Attempts 1 and 2: transient, left unclaimed so the next run retries.
    for expected_attempt in (1, 2):
        result = orchestrator.RunResult()
        orchestrator.process_one(client, db_conn, _FakeCandidate(), "kql", result)

        assert result.failed == 1, f"attempt {expected_attempt}: should count as failed, not skipped"
        assert result.skipped == 0

        row = db_conn.execute(
            "SELECT attempts FROM detection_pipeline_attempts WHERE entry_hash = ?",
            (_FakeCandidate.hash,),
        ).fetchone()
        assert row["attempts"] == expected_attempt

    # Attempt 3 == MAX_ATTEMPTS: give up, consume the entry so it stops
    # starving the rest of the priority-ordered queue.
    assert orchestrator.MAX_ATTEMPTS == 3, "test assumes the documented default of 3"
    result3 = orchestrator.RunResult()
    orchestrator.process_one(client, db_conn, _FakeCandidate(), "kql", result3)

    assert result3.skipped == 1
    assert result3.failed == 0


def test_poll_timeout_follows_the_same_transient_contract_as_detections_ai_error(db_conn):
    """PollTimeout is a distinct exception class from DetectionsAIError in
    detections_client.py but process_one() catches both in the same clause --
    confirm that's actually true rather than assumed from reading the code."""

    class _PollTimeoutClient:
        def create_project(self, **kwargs):
            return "proj-poll"

        def generate_from_project(self, **kwargs):
            raise PollTimeout("poll budget exhausted")

    result = orchestrator.RunResult()
    orchestrator.process_one(_PollTimeoutClient(), db_conn, _FakeCandidate(), "kql", result)

    assert result.failed == 1
    assert result.skipped == 0
    row = db_conn.execute(
        "SELECT attempts FROM detection_pipeline_attempts WHERE entry_hash = ?",
        (_FakeCandidate.hash,),
    ).fetchone()
    assert row["attempts"] == 1


# --------------------------------------------------------- fully_covered --

class _NoGapsClient:
    def create_project(self, **kwargs):
        return "proj-covered"

    def generate_from_project(self, **kwargs):
        # Existing coverage already handles everything this article
        # suggests -- a real, common outcome, not a failure.
        return "proj-covered", _FakeReport(gaps=[]), []


def test_no_gaps_counts_as_fully_covered_not_a_failure(db_conn):
    result = orchestrator.RunResult()
    orchestrator.process_one(_NoGapsClient(), db_conn, _FakeCandidate(), "kql", result)

    assert result.fully_covered == 1
    assert result.gaps_found == 0
    assert result.failed == 0
    assert result.skipped == 0
    # generated still increments -- generation itself succeeded, there was
    # simply nothing new to build.
    assert result.generated == 1


# ------------------------- extract_technique() None / check_coverage reuse --

class _UnresolvableDetectionClient:
    def create_project(self, **kwargs):
        return "proj-unresolvable"

    def generate_from_project(self, **kwargs):
        # No "// MITRE ATT&CK: ..." header at all -- extract_technique()
        # returns None for this.
        return "proj-unresolvable", _FakeReport(gaps=[_fake_gap()]), [
            _FakeDetection("DeviceProcessEvents | take 1", artifact_id="no-technique"),
        ]


def test_detection_with_no_extractable_technique_is_skipped_not_registered(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: None)
    monkeypatch.setattr(orchestrator, "_build_sentinel_client", lambda: None)

    def _boom(*a, **k):
        raise AssertionError("must not reach the static gate for an unresolvable detection")
    monkeypatch.setattr(orchestrator, "gate_evaluate", _boom)

    result = orchestrator.RunResult()
    orchestrator.process_one(_UnresolvableDetectionClient(), db_conn, _FakeCandidate(), "kql", result,
                             sentinel_client=None)

    assert result.alignment_checked == 0
    row = db_conn.execute(
        "SELECT COUNT(*) AS n FROM analytics WHERE source_entry_hash = ?",
        (_FakeCandidate.hash,),
    ).fetchone()
    assert row["n"] == 0


# --------------------- register_strategy() prefers MITRE's own objective --

class _NewTechniqueDetectionClient:
    def create_project(self, **kwargs):
        return "proj-new-technique"

    def generate_from_project(self, **kwargs):
        return "proj-new-technique", _FakeReport(gaps=[_fake_gap()]), [
            _FakeDetection(_CONTENT, artifact_id="art-new-technique"),
        ]


def test_register_strategy_falls_back_to_technique_name_with_no_cached_mitre_strategy(db_conn, monkeypatch):
    """No mitre_detection_strategies row exists for T1053.005 in this test
    DB -- confirms the pre-existing fallback still works, and that
    get_cached_strategy() never triggers a live sync (a network call would
    hang/fail in this sandbox)."""
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: None)
    monkeypatch.setattr(orchestrator, "_build_sentinel_client", lambda: None)
    monkeypatch.setattr(orchestrator, "gate_evaluate", lambda *a, **k: _fake_gate(verdict="reject"))

    result = orchestrator.RunResult()
    orchestrator.process_one(_NewTechniqueDetectionClient(), db_conn, _FakeCandidate(), "kql", result,
                             sentinel_client=None)

    row = db_conn.execute(
        "SELECT objective FROM detection_strategies WHERE technique_id = ?",
        ("T1053.005",),
    ).fetchone()
    assert row["objective"] == "Scheduled Task/Job: Scheduled Task"


def test_register_strategy_prefers_cached_mitre_objective_over_technique_name(db_conn, monkeypatch):
    """Confirmed live 2026-09-02: a novel technique's detection_strategies
    row got its objective from the raw technique_name (echoed straight out
    of the detection's own header), even when MITRE's own published
    objective for that exact technique was already sitting in the local
    cache -- register_strategy() never looked. This is the fix."""
    db_conn.execute(
        "INSERT INTO mitre_detection_strategies (id, det_id, technique_id, name, objective, catalog_version) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("x-mitre-detection-strategy--t1053.005", "DET0001", "T1053.005", "Scheduled Task",
         "Detect adversaries abusing task scheduling to execute malicious code.", "1.0"),
    )
    db_conn.commit()

    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: None)
    monkeypatch.setattr(orchestrator, "_build_sentinel_client", lambda: None)
    monkeypatch.setattr(orchestrator, "gate_evaluate", lambda *a, **k: _fake_gate(verdict="reject"))

    result = orchestrator.RunResult()
    orchestrator.process_one(_NewTechniqueDetectionClient(), db_conn, _FakeCandidate(), "kql", result,
                             sentinel_client=None)

    row = db_conn.execute(
        "SELECT objective FROM detection_strategies WHERE technique_id = ?",
        ("T1053.005",),
    ).fetchone()
    assert row["objective"] == "Detect adversaries abusing task scheduling to execute malicious code."


class _RepeatDetectionClient:
    """Two detections for the same technique in one run -- the second must
    reuse the strategy check_coverage() finds, not call register_strategy()
    again (which would violate detection_strategies' technique_id
    uniqueness)."""

    def create_project(self, **kwargs):
        return "proj-repeat"

    def generate_from_project(self, **kwargs):
        return "proj-repeat", _FakeReport(gaps=[_fake_gap()]), [
            _FakeDetection(_CONTENT, artifact_id="art-first"),
            _FakeDetection(_CONTENT, artifact_id="art-second"),
        ]


def test_second_detection_for_same_technique_reuses_existing_strategy(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "_build_ai_client", lambda: None)
    monkeypatch.setattr(orchestrator, "_build_sentinel_client", lambda: None)
    monkeypatch.setattr(orchestrator, "gate_evaluate", lambda *a, **k: _fake_gate(verdict="reject"))

    result = orchestrator.RunResult()
    orchestrator.process_one(_RepeatDetectionClient(), db_conn, _FakeCandidate(), "kql", result,
                             sentinel_client=None)

    strategies = db_conn.execute(
        "SELECT COUNT(*) AS n FROM detection_strategies WHERE technique_id = ?",
        ("T1053.005",),
    ).fetchone()
    assert strategies["n"] == 1, "must not create a duplicate strategy row for the same technique"

    analytics = db_conn.execute(
        "SELECT COUNT(*) AS n FROM analytics WHERE source_entry_hash = ?",
        (_FakeCandidate.hash,),
    ).fetchone()
    assert analytics["n"] == 2, "both detections should still register their own analytic row"
