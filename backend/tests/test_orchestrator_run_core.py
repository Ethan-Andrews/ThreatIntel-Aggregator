"""Tests for run()'s own control flow that had zero prior coverage before
this file existed: the pending==0 and dry_run early returns, the
per-candidate UNHANDLED-exception-plus-MAX_ATTEMPTS-give-up handler (the
exact real prod incident from 2026-08-20 -- one TI entry reprocessed on
every 30-minute run indefinitely because only the generate_from_url()
exception path was ever capped, see CLAUDE.md/sdlc skill Gotchas), the
three end-of-batch sweeps' non-fatal failure handling (the explicit
dead-code-risk area item C calls out -- "a Succeeded execution proves
nothing about what actually ran"), and main()'s exit-code contract.

Every existing orchestrator test calls process_one() directly, bypassing
run() itself entirely, except test_orchestrator_settings.py's single
disabled-switch test. This file exercises run() and main() as the real
entry points they are."""

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection_pipeline import orchestrator, orchestrator_settings


@pytest.fixture(autouse=True)
def _orchestrator_enabled(db_conn):
    # orchestrator_settings now defaults to disabled (off-by-default, see
    # pg_orchestrator_settings.sql) and tmp_db truncates the singleton row
    # every test -- this file tests run()'s own control flow, not the
    # enabled-gate itself (that's test_orchestrator_settings.py's job), so
    # every test here needs the gate explicitly open to reach the logic
    # under test.
    orchestrator_settings.set_enabled(db_conn, True, "test-setup")
    db_conn.commit()


def _insert_pending_entry(conn, entry_hash):
    conn.execute(
        """
        INSERT INTO entries
            (hash, source, title, link, published, ttps, triaged, severity,
             archived, is_duplicate, stack_match)
        VALUES (?, 'TestFeed', 'Test Title', 'https://example.com/a',
                to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
                'T1053.005', 1, 'High', 0, 0, 1)
        """,
        (entry_hash,),
    )
    conn.commit()


class _FakeReport:
    def __init__(self, gaps):
        self.gaps = gaps
        self.undetermined = []
        self.summary = {"covered": 0}


class _FakeSentinelClient:
    """A non-None sentinel_client stand-in with a working close() -- run()'s
    own finally block calls sentinel_client.close() unconditionally, and a
    bare object() there raises AttributeError *inside* that finally clause,
    which pre-empts the conn.close() right after it and leaks a real
    Postgres connection. Found exactly this way: the first draft of these
    sweep tests used object() and every one of them left a connection
    "idle in transaction," deadlocking the next test's TRUNCATE -- the same
    failure shape as the 2026-08-21 hang gotcha, just from a test fixture
    bug rather than a product one this time."""

    def close(self):
        pass


class _FakeDetectionsAIClient:
    """Context-manager-compatible stand-in for run()'s own
    `with DetectionsAIClient() as client:` construction."""

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def whoami(self):
        return {"team_name": "test-team"}

    def create_project(self, **kwargs):
        return "proj-1"

    def generate_from_project(self, **kwargs):
        return "proj-1", _FakeReport(gaps=[]), []


# ------------------------------------------------------ early returns --

def test_pending_zero_returns_immediately_without_claiming(db_conn, monkeypatch):
    # No entries inserted at all -- pending_count() must be 0.
    monkeypatch.setattr(orchestrator, "DetectionsAIClient", _FakeDetectionsAIClient)
    result = orchestrator.run(batch_size=5)
    assert result.claimed == 0
    assert result.generated == 0


def test_no_draft_provider_configured_releases_claim_and_still_runs_sweeps(db_conn, monkeypatch):
    """The actual bug this decoupling pass exists to fix: before, run()
    unconditionally did `with DetectionsAIClient() as client:` -- a
    deployment with no DETECTIONS_AI_API_KEY configured raised
    DetectionsAIError at construction, which propagated all the way out
    of run() uncaught. That meant an OSS user with no draft provider
    couldn't just skip generation, the whole batch aborted: candidates
    stayed claimed-but-unprocessed, and the maintenance sweeps below
    (disposition/revalidation/baseline) never got a chance to run at
    all. Confirms both halves of the fix: the claim is released (the
    entry is still pending afterward, not stuck), and every sweep still
    fires even though there is no draft provider."""
    entry_hash = "f" * 64
    _insert_pending_entry(db_conn, entry_hash)

    def _no_key(*a, **k):
        raise orchestrator.DetectionsAIError("DETECTIONS_AI_API_KEY is not set")
    monkeypatch.setattr(orchestrator, "DetectionsAIClient", _no_key)
    monkeypatch.setattr(orchestrator, "_build_sentinel_client", lambda: _FakeSentinelClient())

    swept = {"disposition": False, "revalidation": False, "baseline": False}
    monkeypatch.setattr(
        orchestrator.disposition_tracker, "sweep",
        lambda *a, **k: swept.__setitem__("disposition", True) or [],
    )
    monkeypatch.setattr(
        orchestrator, "sweep_revalidation",
        lambda *a, **k: swept.__setitem__("revalidation", True) or [],
    )
    monkeypatch.setattr(
        orchestrator.hit_baseline, "sweep_baseline",
        lambda *a, **k: swept.__setitem__("baseline", True) or [],
    )

    result = orchestrator.run(batch_size=5)

    assert result.claimed == 0
    assert result.generated == 0
    assert result.failed == 0
    row = db_conn.execute(
        "SELECT emitted_at FROM entries WHERE hash = ?", (entry_hash,)
    ).fetchone()
    assert row["emitted_at"] is None
    assert swept == {"disposition": True, "revalidation": True, "baseline": True}


def test_dry_run_claims_but_rolls_back_without_emitting_anything(db_conn, monkeypatch):
    entry_hash = "e" * 64
    _insert_pending_entry(db_conn, entry_hash)

    def _boom(*a, **k):
        raise AssertionError("dry_run must never construct the real detections.ai client")
    monkeypatch.setattr(orchestrator, "DetectionsAIClient", _boom)

    result = orchestrator.run(batch_size=5, dry_run=True)

    assert result.claimed == 1
    # The claim's FOR UPDATE lock must have been rolled back, not committed --
    # the entry is still pending afterward.
    row = db_conn.execute(
        "SELECT emitted_at FROM entries WHERE hash = ?", (entry_hash,)
    ).fetchone()
    assert row["emitted_at"] is None


# --------------------------- per-candidate UNHANDLED exception handler --

class _AlwaysUnhandledErrorClient(_FakeDetectionsAIClient):
    """Raises a plain ValueError -- not PreprocessingFailed, PollTimeout, or
    DetectionsAIError, so process_one()'s own except clauses don't catch it
    and it propagates up to run()'s own try/except around process_one()."""

    def generate_from_project(self, **kwargs):
        raise ValueError("simulated unexpected bug downstream of project creation")


def _reset_orchestrator_interval_gate(conn):
    """Each orchestrator.run() call in this test simulates an independent
    scheduled fire (a fresh container execution) -- not two calls racing
    within the same instant. Reset last_run_at so orchestrator_settings.
    is_due()'s interval check (added for the admin-configurable schedule
    feature) doesn't skip the next call, the same way real elapsed time
    between separate cron fires would clear it."""
    conn.execute("UPDATE orchestrator_settings SET last_run_at = NULL WHERE id = 1")
    conn.commit()


def test_run_catches_an_unhandled_process_one_exception_without_aborting_the_batch(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "DetectionsAIClient", _AlwaysUnhandledErrorClient)
    entry_hash = "f" * 64
    _insert_pending_entry(db_conn, entry_hash)

    for expected_attempt in (1, 2):
        _reset_orchestrator_interval_gate(db_conn)
        result = orchestrator.run(batch_size=5)
        assert result.claimed == 1
        assert result.failed == 1, f"attempt {expected_attempt}: run() must not itself crash"

        row = db_conn.execute(
            "SELECT attempts FROM detection_pipeline_attempts WHERE entry_hash = ?",
            (entry_hash,),
        ).fetchone()
        assert row["attempts"] == expected_attempt

        pending_row = db_conn.execute(
            "SELECT emitted_at FROM entries WHERE hash = ?", (entry_hash,)
        ).fetchone()
        assert pending_row["emitted_at"] is None, (
            f"attempt {expected_attempt}: must stay unclaimed for the next run to retry"
        )

    # Third run == MAX_ATTEMPTS: give up and consume the entry, exactly the
    # same discipline as process_one()'s own generation-failure path -- this
    # is the fix for the real prod incident where a candidate that failed
    # anywhere else in process_one() was reprocessed forever.
    assert orchestrator.MAX_ATTEMPTS == 3, "test assumes the documented default of 3"
    _reset_orchestrator_interval_gate(db_conn)
    result3 = orchestrator.run(batch_size=5)
    assert result3.failed == 1

    final_row = db_conn.execute(
        "SELECT emitted_at FROM entries WHERE hash = ?", (entry_hash,)
    ).fetchone()
    assert final_row["emitted_at"] is not None, "must be consumed after MAX_ATTEMPTS"


# ------------------------------------------------- end-of-batch sweeps --

def test_disposition_sweep_failure_does_not_abort_the_run(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "DetectionsAIClient", _FakeDetectionsAIClient)
    monkeypatch.setattr(orchestrator, "_build_sentinel_client", lambda: _FakeSentinelClient())

    def _boom(*a, **k):
        raise RuntimeError("simulated disposition sweep crash")
    monkeypatch.setattr(orchestrator.disposition_tracker, "sweep", _boom)

    entry_hash = "1" * 64
    _insert_pending_entry(db_conn, entry_hash)

    result = orchestrator.run(batch_size=5)

    assert result.claimed == 1
    row = db_conn.execute(
        "SELECT emitted_at FROM entries WHERE hash = ?", (entry_hash,)
    ).fetchone()
    assert row["emitted_at"] is not None, "the candidate loop itself must still have completed"


def test_revalidation_sweep_failure_does_not_abort_the_run(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "DetectionsAIClient", _FakeDetectionsAIClient)
    monkeypatch.setattr(orchestrator, "_build_sentinel_client", lambda: _FakeSentinelClient())

    def _boom(*a, **k):
        raise RuntimeError("simulated revalidation sweep crash")
    monkeypatch.setattr(orchestrator, "sweep_revalidation", _boom)

    entry_hash = "2" * 64
    _insert_pending_entry(db_conn, entry_hash)

    result = orchestrator.run(batch_size=5)

    assert result.claimed == 1
    row = db_conn.execute(
        "SELECT emitted_at FROM entries WHERE hash = ?", (entry_hash,)
    ).fetchone()
    assert row["emitted_at"] is not None


def test_baseline_sweep_failure_does_not_abort_the_run(db_conn, monkeypatch):
    monkeypatch.setattr(orchestrator, "DetectionsAIClient", _FakeDetectionsAIClient)
    monkeypatch.setattr(orchestrator, "_build_sentinel_client", lambda: _FakeSentinelClient())

    def _boom(*a, **k):
        raise RuntimeError("simulated baseline sweep crash")
    monkeypatch.setattr(orchestrator.hit_baseline, "sweep_baseline", _boom)

    entry_hash = "3" * 64
    _insert_pending_entry(db_conn, entry_hash)

    result = orchestrator.run(batch_size=5)

    assert result.claimed == 1
    row = db_conn.execute(
        "SELECT emitted_at FROM entries WHERE hash = ?", (entry_hash,)
    ).fetchone()
    assert row["emitted_at"] is not None


def test_all_three_sweeps_are_attempted_even_when_the_first_two_fail(db_conn, monkeypatch):
    """Each sweep's try/except must be independent -- one crashing must not
    skip the others."""
    monkeypatch.setattr(orchestrator, "DetectionsAIClient", _FakeDetectionsAIClient)
    monkeypatch.setattr(orchestrator, "_build_sentinel_client", lambda: _FakeSentinelClient())

    calls = {"disposition": False, "revalidation": False, "baseline": False}

    def _boom_disposition(*a, **k):
        calls["disposition"] = True
        raise RuntimeError("disposition crash")

    def _boom_revalidation(*a, **k):
        calls["revalidation"] = True
        raise RuntimeError("revalidation crash")

    def _record_baseline(*a, **k):
        calls["baseline"] = True
        return []

    monkeypatch.setattr(orchestrator.disposition_tracker, "sweep", _boom_disposition)
    monkeypatch.setattr(orchestrator, "sweep_revalidation", _boom_revalidation)
    monkeypatch.setattr(orchestrator.hit_baseline, "sweep_baseline", _record_baseline)

    entry_hash = "4" * 64
    _insert_pending_entry(db_conn, entry_hash)

    orchestrator.run(batch_size=5)

    assert calls == {"disposition": True, "revalidation": True, "baseline": True}


# --------------------------------------------------------------- main() --

def test_main_returns_zero_when_nothing_failed(monkeypatch):
    fake_result = orchestrator.RunResult(claimed=0, generated=0, failed=0)
    monkeypatch.setattr(orchestrator, "run", lambda **kwargs: fake_result)
    assert orchestrator.main() == 0


def test_main_returns_one_when_everything_attempted_failed(monkeypatch):
    fake_result = orchestrator.RunResult(claimed=2, generated=0, failed=2)
    monkeypatch.setattr(orchestrator, "run", lambda **kwargs: fake_result)
    assert orchestrator.main() == 1


def test_main_returns_zero_when_some_failed_but_others_generated(monkeypatch):
    """A partial failure (some articles just don't generate) is normal
    operation, not a systemic problem -- only "everything failed, nothing
    succeeded" should fail the Container Apps Job."""
    fake_result = orchestrator.RunResult(claimed=3, generated=1, failed=2)
    monkeypatch.setattr(orchestrator, "run", lambda **kwargs: fake_result)
    assert orchestrator.main() == 0


def test_main_returns_one_when_run_itself_raises(monkeypatch):
    def _boom(**kwargs):
        raise RuntimeError("simulated total run() crash")
    monkeypatch.setattr(orchestrator, "run", _boom)
    assert orchestrator.main() == 1
