"""Tests for alignment_check.py. Pure-logic tests need no DB or network;
DB tests use db_conn (real Postgres, per conftest.py)."""

import json as json_module
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import alignment_check

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_mitre_sync import _load_fixture, _FakeHttpClient  # noqa: E402


def test_coerce_verdict_output_accepts_valid_aligned():
    raw = '{"verdict": "aligned", "reasoning": "Matches MITRE guidance.", "suggested_kql": null}'
    result = alignment_check._coerce_verdict_output(raw)
    assert result == {"verdict": "aligned", "reasoning": "Matches MITRE guidance.", "suggested_kql": None}


def test_coerce_verdict_output_does_not_html_escape_reasoning():
    """Regression test: reasoning is rendered as plain JSX text in
    AlignmentReviewPanel ({item.ai_reasoning}), never dangerouslySetInnerHTML,
    so React already escapes it safely. A prior bug ran it through
    markupsafe.escape() before storage, which had no XSS benefit and
    corrupted apostrophes/ampersands into visible "&#39;"/"&amp;" in the UI
    (confirmed live: "MITRE's" rendered as "MITRE&#39;s" for hundreds of
    stored rows). Assert the raw characters survive unescaped."""
    raw = json_module.dumps({
        "verdict": "aligned",
        "reasoning": "Matches MITRE's guidance for A&B <tags> \"quoted\".",
        "suggested_kql": None,
    })
    result = alignment_check._coerce_verdict_output(raw)
    assert result["reasoning"] == "Matches MITRE's guidance for A&B <tags> \"quoted\"."


def test_coerce_verdict_output_strips_markdown_fence():
    raw = '```json\n{"verdict": "partial", "reasoning": "Unclear.", "suggested_kql": null}\n```'
    result = alignment_check._coerce_verdict_output(raw)
    assert result["verdict"] == "partial"


def test_coerce_verdict_output_keeps_suggested_kql_only_for_diverges():
    raw = '{"verdict": "aligned", "reasoning": "ok", "suggested_kql": "SomeTable | take 1"}'
    result = alignment_check._coerce_verdict_output(raw)
    assert result["suggested_kql"] is None


def test_coerce_verdict_output_diverges_keeps_suggested_kql():
    raw = '{"verdict": "diverges", "reasoning": "gap", "suggested_kql": "SomeTable | take 1"}'
    result = alignment_check._coerce_verdict_output(raw)
    assert result["suggested_kql"] == "SomeTable | take 1"


def test_coerce_verdict_output_falls_back_to_partial_on_bad_json():
    result = alignment_check._coerce_verdict_output("not json at all")
    assert result["verdict"] == "partial"
    assert result["suggested_kql"] is None


def test_coerce_verdict_output_falls_back_to_partial_on_unknown_verdict():
    raw = '{"verdict": "yes", "reasoning": "?", "suggested_kql": null}'
    result = alignment_check._coerce_verdict_output(raw)
    assert result["verdict"] == "partial"


def test_coerce_verdict_output_caps_reasoning_length():
    raw = '{"verdict": "aligned", "reasoning": "%s", "suggested_kql": null}' % ("x" * 5000)
    result = alignment_check._coerce_verdict_output(raw)
    assert len(result["reasoning"]) == 1000


def test_coerce_verdict_output_falls_back_to_partial_on_json_list():
    result = alignment_check._coerce_verdict_output("[1, 2, 3]")
    assert result["verdict"] == "partial"
    assert result["suggested_kql"] is None


def test_coerce_verdict_output_falls_back_to_partial_on_json_number():
    result = alignment_check._coerce_verdict_output("5")
    assert result["verdict"] == "partial"
    assert result["suggested_kql"] is None


def test_coerce_verdict_output_falls_back_to_partial_on_json_string():
    result = alignment_check._coerce_verdict_output('"hello"')
    assert result["verdict"] == "partial"
    assert result["suggested_kql"] is None


class _FakeAIResponse:
    def __init__(self, text):
        self.content = [type("Block", (), {"text": text})()]


class _FakeAIClient:
    def __init__(self, response_text):
        self._response_text = response_text
        self.last_call = None

    class _Messages:
        def __init__(self, outer):
            self._outer = outer

        def create(self, **kwargs):
            self._outer.last_call = kwargs
            return _FakeAIResponse(self._outer._response_text)

    @property
    def messages(self):
        return self._Messages(self)


def _seed_strategy(conn, technique_id="T1053.005"):
    row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, "Scheduled Task", "Detect scheduled task creation", []),
    ).fetchone()
    conn.commit()
    return row["id"]


def _seed_analytic(conn, strategy_id, kql_body="DeviceProcessEvents | take 1"):
    row = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body) "
        "VALUES (?, ?, ?) RETURNING id",
        (strategy_id, "test-hash", kql_body),
    ).fetchone()
    conn.commit()
    return row["id"]


def _patch_mitre_lookup(monkeypatch, bundle):
    """check_alignment() calls alignment_check.get_mitre_strategy(conn,
    technique_id) -- patch it to read the fixture bundle in-memory instead
    of touching the DB cache, isolating these tests from Tasks 4/5."""
    import mitre_sync
    monkeypatch.setattr(
        alignment_check, "get_mitre_strategy",
        lambda conn, technique_id: mitre_sync.extract_strategy(bundle, technique_id),
    )


def test_check_alignment_aligned_writes_status_and_no_review_row(db_conn, monkeypatch):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id)
    _patch_mitre_lookup(monkeypatch, _load_fixture())

    ai_client = _FakeAIClient(
        json_module.dumps({"verdict": "aligned", "reasoning": "Matches.", "suggested_kql": None})
    )

    result = alignment_check.check_alignment(ai_client, None, db_conn, strategy_id, analytic_id=analytic_id)

    assert result.verdict == "aligned"
    row = db_conn.execute(
        "SELECT mitre_alignment_status, mitre_alignment_reasoning, mitre_detection_strategy_id "
        "FROM detection_strategies WHERE id = ?",
        (strategy_id,),
    ).fetchone()
    assert row["mitre_alignment_status"] == "aligned"
    assert row["mitre_alignment_reasoning"] == "Matches."
    assert row["mitre_detection_strategy_id"] == "DET0210"

    review_count = db_conn.execute(
        "SELECT COUNT(*) FROM alignment_reviews WHERE strategy_id = ?", (strategy_id,)
    ).fetchone()[0]
    assert review_count == 0

    # The prompt included MITRE's structured analytics data, not just the
    # objective string -- confirms Task 8's prompt actually uses the
    # richer mitre_sync shape, not a leftover flat analytics_summary.
    prompt_content = ai_client.last_call["messages"][0]["content"]
    assert "sysmon" in prompt_content
    assert "Windows" in prompt_content


def test_check_alignment_partial_when_mitre_has_no_strategy(db_conn, monkeypatch):
    strategy_id = _seed_strategy(db_conn, technique_id="T9999.999")
    analytic_id = _seed_analytic(db_conn, strategy_id)
    _patch_mitre_lookup(monkeypatch, _load_fixture())

    ai_client = _FakeAIClient("should not be called")
    result = alignment_check.check_alignment(ai_client, None, db_conn, strategy_id, analytic_id=analytic_id)

    assert result.verdict == "partial"
    assert ai_client.last_call is None  # never reached the AI call
    row = db_conn.execute(
        "SELECT status FROM alignment_reviews WHERE id = ?", (result.review_id,)
    ).fetchone()
    assert row["status"] == "queued_for_rereview"


def test_check_alignment_partial_when_mitre_sync_fails(db_conn, monkeypatch):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id)

    def _boom(conn, technique_id):
        raise RuntimeError("network unreachable")

    monkeypatch.setattr(alignment_check, "get_mitre_strategy", _boom)

    ai_client = _FakeAIClient("should not be called")
    result = alignment_check.check_alignment(ai_client, None, db_conn, strategy_id, analytic_id=analytic_id)

    assert result.verdict == "partial"
    assert "network unreachable" in result.reasoning
    assert ai_client.last_call is None


def test_check_alignment_partial_ai_verdict(db_conn, monkeypatch):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id)
    _patch_mitre_lookup(monkeypatch, _load_fixture())

    ai_client = _FakeAIClient(
        json_module.dumps({"verdict": "partial", "reasoning": "Unclear.", "suggested_kql": None})
    )
    result = alignment_check.check_alignment(ai_client, None, db_conn, strategy_id, analytic_id=analytic_id)

    assert result.verdict == "partial"
    row = db_conn.execute(
        "SELECT mitre_detection_strategy_id FROM detection_strategies WHERE id = ?", (strategy_id,)
    ).fetchone()
    assert row["mitre_detection_strategy_id"] == "DET0210"  # recorded even on a partial verdict


import types


def _fake_probe_outcome(error=False, total=1, dead_fields=None):
    return types.SimpleNamespace(error=error, total=total, dead_fields=dead_fields or [])


def test_check_alignment_diverges_declines_when_no_log_source_resolves(db_conn, monkeypatch):
    """The Linux/auditd analytic in the fixture has no registered resolver
    (SentinelTelemetryResolver only knows Windows) -- the AI's draft must
    be discarded, never run through static_gate at all."""
    strategy_id = _seed_strategy(db_conn, technique_id="T1053.005")
    analytic_id = _seed_analytic(db_conn, strategy_id, kql_body="crontab | take 1")
    bundle = _load_fixture()

    import mitre_sync

    def _linux_only_strategy(conn, technique_id):
        full = mitre_sync.extract_strategy(bundle, technique_id)
        full.analytics = [a for a in full.analytics if a["platform"] == "Linux"]
        return full

    monkeypatch.setattr(alignment_check, "get_mitre_strategy", _linux_only_strategy)

    ai_client = _FakeAIClient(json_module.dumps({
        "verdict": "diverges", "reasoning": "MITRE covers crontab modification too.",
        "suggested_kql": "DeviceProcessEvents | where FileName == \"crontab\"",
    }))

    result = alignment_check.check_alignment(ai_client, None, db_conn, strategy_id, analytic_id=analytic_id)

    assert result.verdict == "diverges"
    assert result.suggested_kql is None
    row = db_conn.execute(
        "SELECT validation_result FROM alignment_reviews WHERE id = ?", (result.review_id,)
    ).fetchone()
    validation = row["validation_result"]
    if isinstance(validation, str):
        validation = json_module.loads(validation)
    assert validation["gap_reason"] == "no log source for this analytic resolved to a known table"
    assert validation["log_source_checks"][0]["resolved"] is None


def test_check_alignment_diverges_declines_when_telemetry_not_populated(db_conn, monkeypatch):
    """The Windows/sysmon analytic resolves to DeviceProcessEvents, but the
    probe reports zero rows -- still no fix surfaced, distinct reason."""
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id)
    bundle = _load_fixture()

    import mitre_sync

    def _windows_only_strategy(conn, technique_id):
        full = mitre_sync.extract_strategy(bundle, technique_id)
        full.analytics = [a for a in full.analytics if a["platform"] == "Windows"]
        return full

    monkeypatch.setattr(alignment_check, "get_mitre_strategy", _windows_only_strategy)
    # control_probe.run_control_probe now prefers the package-qualified
    # detection_pipeline.sentinel import (fix for the QuerySemanticError
    # identity bug -- see control_probe.py), so patch both names.
    monkeypatch.setattr("detection_pipeline.sentinel.run_probe", lambda client, table, q: _fake_probe_outcome(total=0))
    monkeypatch.setattr("sentinel.run_probe", lambda client, table, q: _fake_probe_outcome(total=0))

    ai_client = _FakeAIClient(json_module.dumps({
        "verdict": "diverges", "reasoning": "MITRE recommends process-creation coverage too.",
        "suggested_kql": "DeviceProcessEvents | where FileName == \"schtasks.exe\"",
    }))

    result = alignment_check.check_alignment(
        ai_client, sentinel_client=object(), conn=db_conn, strategy_id=strategy_id, analytic_id=analytic_id,
    )

    assert result.verdict == "diverges"
    assert result.suggested_kql is None
    row = db_conn.execute(
        "SELECT validation_result FROM alignment_reviews WHERE id = ?", (result.review_id,)
    ).fetchone()
    validation = row["validation_result"]
    if isinstance(validation, str):
        validation = json_module.loads(validation)
    assert validation["gap_reason"] == "resolved table(s) have no confirmed telemetry in this tenant"
    assert validation["log_source_checks"][0]["resolved"]["table"] == "DeviceProcessEvents"


def test_check_alignment_diverges_validates_fix_when_telemetry_confirmed(db_conn, monkeypatch):
    """Telemetry resolves AND is populated -- the AI's draft proceeds to
    static_gate, which rejects it here (adversary-chosen literal), so this
    exercises the full gated path without needing a live backtest."""
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id)
    bundle = _load_fixture()

    import mitre_sync

    def _windows_only_strategy(conn, technique_id):
        full = mitre_sync.extract_strategy(bundle, technique_id)
        full.analytics = [a for a in full.analytics if a["platform"] == "Windows"]
        return full

    monkeypatch.setattr(alignment_check, "get_mitre_strategy", _windows_only_strategy)
    monkeypatch.setattr("detection_pipeline.sentinel.run_probe", lambda client, table, q: _fake_probe_outcome(total=500))
    monkeypatch.setattr("sentinel.run_probe", lambda client, table, q: _fake_probe_outcome(total=500))

    bad_kql = 'DeviceProcessEvents | where FileName == "evil123.exe"'
    ai_client = _FakeAIClient(json_module.dumps({
        "verdict": "diverges", "reasoning": "MITRE recommends scoping by process ancestry.",
        "suggested_kql": bad_kql,
    }))

    result = alignment_check.check_alignment(
        ai_client, sentinel_client=object(), conn=db_conn, strategy_id=strategy_id, analytic_id=analytic_id,
    )

    assert result.verdict == "diverges"
    assert result.suggested_kql is None  # static_gate rejected it -- discarded, not surfaced
    row = db_conn.execute(
        "SELECT validation_result, status FROM alignment_reviews WHERE id = ?", (result.review_id,)
    ).fetchone()
    assert row["status"] == "pending_review"
    validation = row["validation_result"]
    if isinstance(validation, str):
        validation = json_module.loads(validation)
    assert validation["telemetry_probes"][0]["ok"] is True
    assert validation["static_gate"]["verdict"] == "reject"

    strategy_row = db_conn.execute(
        "SELECT mitre_alignment_status FROM detection_strategies WHERE id = ?", (strategy_id,)
    ).fetchone()
    assert strategy_row["mitre_alignment_status"] == "diverges"


def test_check_alignment_diverges_skips_probe_when_no_sentinel_client(db_conn, monkeypatch):
    """sentinel_client=None (e.g. orchestrator.py couldn't build one) --
    telemetry can't be confirmed, so the draft is discarded, same as an
    unpopulated table, not treated as an error."""
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id)
    bundle = _load_fixture()

    import mitre_sync

    def _windows_only_strategy(conn, technique_id):
        full = mitre_sync.extract_strategy(bundle, technique_id)
        full.analytics = [a for a in full.analytics if a["platform"] == "Windows"]
        return full

    monkeypatch.setattr(alignment_check, "get_mitre_strategy", _windows_only_strategy)

    ai_client = _FakeAIClient(json_module.dumps({
        "verdict": "diverges", "reasoning": "gap", "suggested_kql": "DeviceProcessEvents | take 1",
    }))

    result = alignment_check.check_alignment(ai_client, None, db_conn, strategy_id, analytic_id=analytic_id)

    assert result.suggested_kql is None
    row = db_conn.execute(
        "SELECT validation_result FROM alignment_reviews WHERE id = ?", (result.review_id,)
    ).fetchone()
    validation = row["validation_result"]
    if isinstance(validation, str):
        validation = json_module.loads(validation)
    assert validation["telemetry_probes"] == "skipped: no sentinel_client provided"


def test_run_rereview_sweep_resolves_partial_to_aligned(db_conn, monkeypatch):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id)
    old_review = db_conn.execute(
        "INSERT INTO alignment_reviews (strategy_id, analytic_id, verdict, ai_reasoning, status) "
        "VALUES (?, ?, 'partial', 'was unclear', 'queued_for_rereview') RETURNING id",
        (strategy_id, analytic_id),
    ).fetchone()
    db_conn.commit()

    _patch_mitre_lookup(monkeypatch, _load_fixture())
    ai_client = _FakeAIClient(
        json_module.dumps({"verdict": "aligned", "reasoning": "Now clear.", "suggested_kql": None})
    )

    results = alignment_check.run_rereview_sweep(ai_client, None, db_conn, batch_size=10)

    assert len(results) == 1
    assert results[0].verdict == "aligned"
    old_row = db_conn.execute(
        "SELECT status FROM alignment_reviews WHERE id = ?", (old_review["id"],)
    ).fetchone()
    assert old_row["status"] == "rereview_resolved"


def test_run_rereview_sweep_leaves_still_partial_untouched(db_conn, monkeypatch):
    strategy_id = _seed_strategy(db_conn, technique_id="T9999.999")
    analytic_id = _seed_analytic(db_conn, strategy_id)
    old_review = db_conn.execute(
        "INSERT INTO alignment_reviews (strategy_id, analytic_id, verdict, ai_reasoning, status) "
        "VALUES (?, ?, 'partial', 'still unclear', 'queued_for_rereview') RETURNING id",
        (strategy_id, analytic_id),
    ).fetchone()
    db_conn.commit()

    _patch_mitre_lookup(monkeypatch, _load_fixture())  # T9999.999 has no MITRE strategy -> stays partial
    ai_client = _FakeAIClient("should not be called")

    alignment_check.run_rereview_sweep(ai_client, None, db_conn, batch_size=10)

    old_row = db_conn.execute(
        "SELECT status FROM alignment_reviews WHERE id = ?", (old_review["id"],)
    ).fetchone()
    assert old_row["status"] == "queued_for_rereview"
