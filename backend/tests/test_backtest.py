"""Tests for backtest.py -- stage 8's full-rule backtest and evidence
bundle. Before this file existed, run_backtest() had ZERO direct test
coverage anywhere in this suite: every existing reference to it
(test_orchestrator_validation.py, test_orchestrator_hunt_sync.py,
test_disposition_tracker.py) monkeypatches it away entirely, so its own
regex time-window parsing, query construction, and every one of its error
branches were exercised only in production, never by a test.

Pure-logic pieces (rule_body, own_time_window, count_query, evidence_query,
_truncate, the disposition/hits_per_90d properties) need no fake client at
all. run_backtest() itself is exercised via a fake SentinelClient whose
.query() is scripted call-by-call, matching the real SentinelClient.query()
contract (returns a dataclass with .columns/.rows/.first()/.dicts(), see
sentinel.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import backtest
# backtest.py's own try/except import prefers "detection_pipeline.sentinel"
# (it succeeds here, since backend/ is already on sys.path from conftest) --
# a bare "import sentinel" loads a SEPARATE module object with its own
# distinct SentinelError/QuerySemanticError classes, and an instance of the
# wrong one would silently fail to match backtest.py's `except SentinelError`
# clause. Import from the same place backtest.py itself resolved to.
from detection_pipeline.sentinel import QueryResult, SentinelError, QuerySemanticError


def _result(columns, rows, elapsed=0.01):
    return QueryResult(columns=columns, rows=rows, elapsed=elapsed)


class _ScriptedClient:
    """Returns each entry in `responses` in order, one per .query() call.
    An entry that's an Exception instance is raised instead of returned."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.queries = []

    def query(self, kusto, timespan=None):
        self.queries.append(kusto)
        resp = self._responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp


# ------------------------------------------------------------- rule_body --

def test_rule_body_strips_header_comments_and_trailing_semicolon():
    content = (
        "// Title: Test\n// Description: does a thing\n\n"
        'DeviceProcessEvents | where FileName == "evil.exe";\n'
    )
    body = backtest.rule_body(content)
    assert "//" not in body
    assert not body.endswith(";")
    assert body.startswith("DeviceProcessEvents")


# ------------------------------------------------------- own_time_window --

def test_own_time_window_literal_ago():
    label, hours = backtest.own_time_window(
        'DeviceProcessEvents | where TimeGenerated > ago(30d) | where FileName == "x"'
    )
    assert label == "ago(30d)"
    assert hours == 30 * 24.0


def test_own_time_window_resolves_let_bound_variable():
    body = (
        "let lookback = 7d;\n"
        "DeviceProcessEvents | where TimeGenerated > ago(lookback)"
    )
    label, hours = backtest.own_time_window(body)
    assert label == "ago(7d)"
    assert hours == 7 * 24.0


def test_own_time_window_absent_returns_empty():
    label, hours = backtest.own_time_window('DeviceProcessEvents | where FileName == "x"')
    assert label == ""
    assert hours == 0.0


def test_own_time_window_picks_narrowest_of_multiple():
    """A rule with more than one ago() bound (e.g. two let-bound sub-ranges)
    must report the narrowest, since that's the window that actually
    constrains a linear pipeline the tightest."""
    body = (
        "DeviceProcessEvents | where TimeGenerated > ago(30d)\n"
        "| where TimeGenerated > ago(2h)"
    )
    label, hours = backtest.own_time_window(body)
    assert label == "ago(2h)"
    assert hours == 2.0


# ----------------------------------------------------- count/evidence_query --

def test_count_query_appends_count():
    assert backtest.count_query("DeviceProcessEvents | take 1") == \
        "DeviceProcessEvents | take 1\n| count"


def test_evidence_query_readable_hits_takes_rows():
    q = backtest.evidence_query("DeviceProcessEvents", hits=2)
    assert q.endswith(f"| take {backtest.EVIDENCE_ROWS}")


def test_evidence_query_noisy_hits_returns_distribution():
    q = backtest.evidence_query("DeviceProcessEvents", hits=50)
    assert "summarize Hits = count() by DeviceName" in q
    assert "top 20 by Hits desc" in q


# ------------------------------------------------------------- _truncate --

def test_truncate_long_string_gets_suffix():
    long_value = "x" * (backtest.MAX_FIELD_CHARS + 50)
    out = backtest._truncate(long_value)
    assert out.startswith("x" * backtest.MAX_FIELD_CHARS)
    assert out.endswith("...[+50]")


def test_truncate_short_string_and_non_string_pass_through():
    assert backtest._truncate("short") == "short"
    assert backtest._truncate(42) == 42
    assert backtest._truncate(None) is None


# --------------------------------------------- disposition / hits_per_90d --

def test_disposition_backtest_error_when_error_set():
    out = backtest.BacktestOutcome(artifact_id="a", title="t", hits=0, error="boom")
    assert out.disposition == "backtest_error"


def test_disposition_clean_when_zero_hits():
    out = backtest.BacktestOutcome(artifact_id="a", title="t", hits=0)
    assert out.disposition == "clean"


def test_disposition_tunable_at_readable_boundary():
    out = backtest.BacktestOutcome(artifact_id="a", title="t", hits=backtest.READABLE_HITS)
    assert out.disposition == "tunable"


def test_disposition_needs_tuning_above_readable_boundary():
    out = backtest.BacktestOutcome(artifact_id="a", title="t", hits=backtest.READABLE_HITS + 1)
    assert out.disposition == "needs_tuning"


def test_hits_per_90d_zero_window_returns_raw_hits():
    out = backtest.BacktestOutcome(artifact_id="a", title="t", hits=7, window_hours=0.0)
    assert out.hits_per_90d == 7.0


def test_hits_per_90d_scales_to_full_retention_window():
    # 10 hits over a 1-day (24h) window, scaled to 90d = 10 * 90 = 900.
    out = backtest.BacktestOutcome(artifact_id="a", title="t", hits=10, window_hours=24.0)
    assert out.hits_per_90d == 900.0


# ------------------------------------------------------------ run_backtest --

_BODY = 'DeviceProcessEvents | where FileName == "evil.exe"'


def test_run_backtest_empty_body_after_stripping_comments_is_an_error():
    out = backtest.run_backtest(_ScriptedClient([]), "// Title: x\n// nothing else\n")
    assert out.disposition == "backtest_error"
    assert "no executable query" in out.error


def test_run_backtest_semantic_error_is_reported_not_treated_as_zero_hits():
    client = _ScriptedClient([QuerySemanticError("unknown column 'Bogus'")])
    out = backtest.run_backtest(client, _BODY)
    assert out.hits == 0
    assert out.error.startswith("semantic:")
    assert out.disposition == "backtest_error"


def test_run_backtest_generic_sentinel_error_on_count_query():
    client = _ScriptedClient([SentinelError("workspace unreachable")])
    out = backtest.run_backtest(client, _BODY)
    assert out.error == "workspace unreachable"
    assert out.disposition == "backtest_error"


def test_run_backtest_count_query_returns_no_rows_is_an_error():
    client = _ScriptedClient([_result(["Count"], [])])
    out = backtest.run_backtest(client, _BODY)
    assert out.error == "count returned no rows"
    assert out.disposition == "backtest_error"


def test_run_backtest_zero_hits_skips_evidence_entirely():
    def _boom(*a, **k):
        raise AssertionError("must not query for evidence when hits == 0")
    client = _ScriptedClient([_result(["Count"], [[0]])])
    client.query = lambda kusto, timespan=None: (
        _result(["Count"], [[0]]) if "| count" in kusto else _boom()
    )
    out = backtest.run_backtest(client, _BODY)
    assert out.hits == 0
    assert out.disposition == "clean"
    assert out.evidence_rows == []


def test_run_backtest_with_evidence_false_skips_evidence_even_with_hits():
    calls = {"n": 0}
    def _query(kusto, timespan=None):
        calls["n"] += 1
        return _result(["Count"], [[5]])
    client = _ScriptedClient([])
    client.query = _query
    out = backtest.run_backtest(client, _BODY, with_evidence=False)
    assert out.hits == 5
    assert calls["n"] == 1, "only the count query should have run"
    assert out.evidence_rows == []
    assert out.distribution == []


def test_run_backtest_evidence_fetch_failure_keeps_hit_count():
    """Evidence is supporting material -- losing it must not discard an
    already-good hit count."""
    client = _ScriptedClient([
        _result(["Count"], [[2]]),
        SentinelError("evidence query throttled"),
    ])
    out = backtest.run_backtest(client, _BODY)
    assert out.hits == 2
    assert out.error.startswith("evidence unavailable:")


def test_run_backtest_readable_hits_populates_evidence_rows_truncated():
    long_path = "a" * (backtest.MAX_FIELD_CHARS + 10)
    client = _ScriptedClient([
        _result(["Count"], [[2]]),
        _result(["DeviceName", "FolderPath"], [["dev1", long_path]]),
    ])
    out = backtest.run_backtest(client, _BODY)
    assert out.hits == 2
    assert out.disposition == "tunable"
    assert out.evidence_columns == ["DeviceName", "FolderPath"]
    assert out.evidence_rows[0][0] == "dev1"
    assert out.evidence_rows[0][1].endswith("...[+10]")
    assert out.distribution == []


def test_run_backtest_noisy_hits_populates_distribution_not_rows():
    client = _ScriptedClient([
        _result(["Count"], [[500]]),
        _result(["DeviceName", "Hits"], [["dev1", 300], ["dev2", 200]]),
    ])
    out = backtest.run_backtest(client, _BODY)
    assert out.hits == 500
    assert out.disposition == "needs_tuning"
    assert out.evidence_rows == []
    assert out.distribution == [
        {"DeviceName": "dev1", "Hits": 300},
        {"DeviceName": "dev2", "Hits": 200},
    ]
