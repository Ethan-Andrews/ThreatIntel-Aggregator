"""Tests for tune.py -- stage 7's bounded, deterministic rule narrowing.

Before this file existed, tune.py had ZERO direct test coverage anywhere in
this suite: test_orchestrator_validation.py only ever monkeypatches
orchestrator.run_tune_loop away entirely. That leaves the actual narrowing
algorithm -- eligibility checks, candidate selection, the safe-insertion-point
search, and above all the bounded loop's own termination logic (dead-field
skip, increase-abort, no-reduction-abort, the iteration cap, and the
distribution-refresh fallback) -- as pure, consequential business logic
(it programmatically rewrites detection rule bodies) that no test has ever
exercised directly.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import tune


_SIMPLE = 'DeviceProcessEvents\n| where FileName == "schtasks.exe"\n| take 50'
_WITH_PROJECT = (
    'DeviceProcessEvents\n| where FileName == "schtasks.exe"\n'
    '| project TimeGenerated, DeviceName, AccountName'
)


def _dist(**dims):
    return dict(dims)


# --------------------------------------------------------------- is_narrowable --

def test_is_narrowable_declines_multi_let_bound_rule():
    body = 'let x = 1d;\nDeviceProcessEvents | where FileName == "a.exe"'
    eligible, reason = tune.is_narrowable(body)
    assert eligible is False
    assert "let-bound" in reason


def test_is_narrowable_declines_join():
    body = 'DeviceProcessEvents | where FileName == "a.exe" | join DeviceNetworkEvents on DeviceId'
    eligible, reason = tune.is_narrowable(body)
    assert eligible is False
    assert "join" in reason.lower()


def test_is_narrowable_declines_union():
    # A proper multi-line where-clause (matching _SIMPLE's shape) is required
    # here so this actually isolates the union check -- a single-line body
    # with "| where" not at the start of its own line fails the *where*
    # check regardless of union, which would let this test pass for the
    # wrong reason. Confirmed by sabotage: dropping the union check from
    # is_narrowable() did NOT fail this test in its original single-line form.
    body = _SIMPLE + "\nunion DeviceNetworkEvents"
    eligible, reason = tune.is_narrowable(body)
    assert eligible is False
    assert "union" in reason.lower() or "join" in reason.lower()


def test_is_narrowable_declines_when_no_where_clause_to_anchor_on():
    body = "DeviceProcessEvents | take 50"
    eligible, reason = tune.is_narrowable(body)
    assert eligible is False
    assert "where" in reason.lower()


def test_is_narrowable_accepts_simple_single_table_rule():
    eligible, reason = tune.is_narrowable(_SIMPLE)
    assert eligible is True
    assert reason == ""


# ------------------------------------------------------------ propose_narrowing --

def test_propose_narrowing_ignores_dimension_outside_candidate_list():
    distributions = _dist(DeviceName=[("dev1", 80), ("dev2", 15), ("dev3", 5)])
    assert tune.propose_narrowing(distributions, set()) is None


def test_propose_narrowing_ignores_dimension_below_min_values():
    distributions = _dist(AccountName=[("bob", 80), ("alice", 20)])  # only 2
    assert tune.propose_narrowing(distributions, set()) is None


def test_propose_narrowing_ignores_share_below_threshold():
    distributions = _dist(AccountName=[("bob", 25), ("alice", 25), ("carol", 25), ("dave", 25)])
    assert tune.propose_narrowing(distributions, set()) is None


def test_propose_narrowing_selects_dimension_above_threshold():
    distributions = _dist(AccountName=[("bob", 80), ("alice", 15), ("carol", 5)])
    cand = tune.propose_narrowing(distributions, set())
    assert cand is not None
    assert cand.dimension == "AccountName"
    assert cand.excluded_value == "bob"
    assert cand.share == 0.80


def test_propose_narrowing_picks_highest_share_across_qualifying_dimensions():
    distributions = _dist(
        AccountName=[("bob", 60), ("alice", 25), ("carol", 15)],
        FileName=[("evil.exe", 90), ("good.exe", 7), ("meh.exe", 3)],
    )
    cand = tune.propose_narrowing(distributions, set())
    assert cand.dimension == "FileName"
    assert cand.excluded_value == "evil.exe"


def test_propose_narrowing_falls_back_to_next_value_when_top_already_excluded():
    # alice's share is computed against the ORIGINAL total (100), not a
    # renormalized remaining total -- 35 must still clear the 0.30
    # threshold on its own for this fallback to actually qualify.
    distributions = _dist(AccountName=[("bob", 60), ("alice", 35), ("carol", 5)])
    cand = tune.propose_narrowing(distributions, {("AccountName", "bob")})
    assert cand is not None
    assert cand.excluded_value == "alice"
    assert cand.share == 0.35


def test_propose_narrowing_skips_fallback_value_whose_share_is_too_thin():
    """Same shape as above, but alice's own share against the original
    total falls under the threshold -- the fallback must not lower the bar
    just because it's a fallback."""
    distributions = _dist(AccountName=[("bob", 80), ("alice", 15), ("carol", 5)])
    cand = tune.propose_narrowing(distributions, {("AccountName", "bob")})
    assert cand is None


def test_propose_narrowing_skips_dimension_when_every_value_already_excluded():
    distributions = _dist(AccountName=[("bob", 80), ("alice", 15), ("carol", 5)])
    already = {("AccountName", "bob"), ("AccountName", "alice"), ("AccountName", "carol")}
    assert tune.propose_narrowing(distributions, already) is None


def test_propose_narrowing_ignores_dimension_with_zero_total_hits():
    distributions = _dist(AccountName=[("bob", 0), ("alice", 0), ("carol", 0)])
    assert tune.propose_narrowing(distributions, set()) is None


# --------------------------------------------------- apply_narrowing / insertion --

def test_apply_narrowing_inserts_right_after_last_where():
    cand = tune.NarrowingCandidate("AccountName", "bob", 0.8, 3)
    out = tune.apply_narrowing(_SIMPLE, cand)
    lines = out.splitlines()
    where_idx = next(i for i, l in enumerate(lines) if l.strip().startswith("| where"))
    assert lines[where_idx + 1] == cand.predicate


def test_apply_narrowing_inserts_before_blocking_project_stage():
    cand = tune.NarrowingCandidate("AccountName", "bob", 0.8, 3)
    out = tune.apply_narrowing(_WITH_PROJECT, cand)
    lines = out.splitlines()
    predicate_idx = lines.index(cand.predicate)
    project_idx = next(i for i, l in enumerate(lines) if l.strip().startswith("| project"))
    assert predicate_idx < project_idx


def test_apply_narrowing_returns_none_with_no_safe_insertion_point():
    cand = tune.NarrowingCandidate("AccountName", "bob", 0.8, 3)
    assert tune.apply_narrowing("DeviceProcessEvents | take 50", cand) is None


def test_narrowing_candidate_predicate_uses_verbatim_string_and_escapes_quotes():
    cand = tune.NarrowingCandidate("FolderPath", 'C:\\Users\\a"b', 0.5, 3)
    assert cand.predicate == '| where FolderPath != @"C:\\Users\\a""b"'


# ------------------------------------------------------------ referenced_dimensions --

def test_referenced_dimensions_excludes_project_alias_targets():
    body = (
        'DeviceProcessEvents | where FileName == "a.exe"\n'
        '| project AccountName = InitiatingProcessAccountName, FileName = InitiatingProcessFileName'
    )
    dims = tune.referenced_dimensions(body)
    # AccountName/FileName only appear as local aliases the rule itself
    # creates -- they must not be proposed as narrowing dimensions.
    assert "AccountName" not in dims
    assert "FileName" not in dims


def test_referenced_dimensions_includes_genuine_raw_column_reference():
    body = 'DeviceProcessEvents | where InitiatingProcessFileName == "a.exe"'
    dims = tune.referenced_dimensions(body)
    assert "InitiatingProcessFileName" in dims


def test_referenced_dimensions_mixed_alias_and_raw_column():
    body = (
        'DeviceProcessEvents | where InitiatingProcessFileName == "a.exe"\n'
        '| project AccountName = InitiatingProcessAccountName'
    )
    dims = tune.referenced_dimensions(body)
    assert "InitiatingProcessFileName" in dims
    assert "AccountName" not in dims


# ------------------------------------------------------------- distribution_query --

def test_distribution_query_none_with_no_safe_insertion_point():
    assert tune.distribution_query("DeviceProcessEvents | take 50", "AccountName") is None


def test_distribution_query_builds_summarize_and_top():
    q = tune.distribution_query(_SIMPLE, "AccountName")
    assert "summarize Hits = count() by AccountName" in q
    assert "top 20 by Hits desc" in q


# ------------------------------------------------------------- collect_distributions --

class _FakeQueryResult:
    def __init__(self, rows):
        self._rows = rows

    def dicts(self):
        return self._rows


class _FakeClient:
    def __init__(self, by_dimension):
        self._by_dimension = by_dimension

    def query(self, q, timespan=None):
        for dim, result in self._by_dimension.items():
            if f"by {dim}" in q:
                if isinstance(result, Exception):
                    raise result
                return _FakeQueryResult(result)
        return _FakeQueryResult([])


def test_collect_distributions_only_queries_referenced_dimensions():
    body = 'DeviceProcessEvents\n| where InitiatingProcessFileName == "a.exe"'
    client = _FakeClient({
        "InitiatingProcessFileName": [{"InitiatingProcessFileName": "a.exe", "Hits": 10}],
    })
    out = tune.collect_distributions(client, body, "P90D")
    assert list(out.keys()) == ["InitiatingProcessFileName"]
    assert out["InitiatingProcessFileName"] == [("a.exe", 10)]


def test_collect_distributions_skips_dimension_whose_query_raises():
    body = (
        'DeviceProcessEvents\n| where InitiatingProcessFileName == "a.exe" '
        'and InitiatingProcessAccountName == "bob"'
    )
    client = _FakeClient({
        "InitiatingProcessFileName": RuntimeError("query failed"),
        "InitiatingProcessAccountName": [{"InitiatingProcessAccountName": "bob", "Hits": 5}],
    })
    out = tune.collect_distributions(client, body, "P90D")
    assert "InitiatingProcessFileName" not in out
    assert out["InitiatingProcessAccountName"] == [("bob", 5)]


def test_collect_distributions_drops_empty_values_and_sorts_descending():
    body = 'DeviceProcessEvents\n| where InitiatingProcessFileName == "a.exe"'
    client = _FakeClient({
        "InitiatingProcessFileName": [
            {"InitiatingProcessFileName": "", "Hits": 99},
            {"InitiatingProcessFileName": "low.exe", "Hits": 2},
            {"InitiatingProcessFileName": "high.exe", "Hits": 40},
        ],
    })
    out = tune.collect_distributions(client, body, "P90D")
    assert out["InitiatingProcessFileName"] == [("high.exe", 40), ("low.exe", 2)]


# --------------------------------------------------------------- verify_clean --

def _probe(error="", total=1, dead_fields=None):
    import types
    return types.SimpleNamespace(error=error, total=total, dead_fields=dead_fields or [])


class _FakePlan:
    def __init__(self, entries):
        self._entries = entries

    def queries(self):
        return self._entries


def test_verify_clean_ok_when_all_probes_healthy():
    plan = _FakePlan([("DeviceProcessEvents", "q1")])
    status, issues = tune.verify_clean(object(), plan, lambda c, t, q: _probe(total=500))
    assert status == "ok"
    assert issues == []


def test_verify_clean_reports_error_and_short_circuits_dead_field_reporting():
    plan = _FakePlan([("DeviceProcessEvents", "q1"), ("DeviceNetworkEvents", "q2")])
    def run_probe_fn(c, table, q):
        if table == "DeviceProcessEvents":
            return _probe(error="table not licensed")
        return _probe(total=0)
    status, issues = tune.verify_clean(object(), plan, run_probe_fn)
    assert status == "error"
    assert any("table not licensed" in i for i in issues)


def test_verify_clean_reports_dead_fields_including_no_telemetry_table():
    plan = _FakePlan([("DeviceProcessEvents", "q1")])
    status, issues = tune.verify_clean(
        object(), plan, lambda c, t, q: _probe(total=500, dead_fields=["InitiatingProcessAccountName"])
    )
    assert status == "dead_fields"
    assert issues == ["DeviceProcessEvents.InitiatingProcessAccountName"]


def test_verify_clean_reports_no_telemetry_at_all():
    plan = _FakePlan([("DeviceProcessEvents", "q1")])
    status, issues = tune.verify_clean(object(), plan, lambda c, t, q: _probe(total=0))
    assert status == "dead_fields"
    assert "no telemetry" in issues[0]


# --------------------------------------------------------------- run_tune_loop --

def _count_fn_table(hits_by_body):
    """count_fn that returns a scripted hit count keyed by the exact body
    text it's called with."""
    def fn(body):
        return hits_by_body[body]
    return fn


def test_run_tune_loop_not_narrowable_records_reason_and_stops_immediately():
    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body="DeviceProcessEvents | take 50",
        original_hits=10, distributions={}, count_fn=lambda b: 0,
        field_population_fn=lambda d: True,
    )
    assert result.disposition == "not_narrowable"
    assert len(result.iterations) == 1
    assert "where" in result.iterations[0].note.lower()


def test_run_tune_loop_no_candidate_available_needs_human_tuning_with_no_iterations():
    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions={}, count_fn=lambda b: 0, field_population_fn=lambda d: True,
    )
    assert result.disposition == "needs_human_tuning"
    assert result.iterations == []


def test_run_tune_loop_skips_dead_field_candidate_and_tries_next():
    distributions = _dist(
        AccountName=[("bob", 80), ("alice", 15), ("carol", 5)],
        FileName=[("evil.exe", 70), ("good.exe", 20), ("meh.exe", 10)],
    )
    narrowed_body = tune.apply_narrowing(_SIMPLE, tune.NarrowingCandidate("FileName", "evil.exe", 0.7, 3))
    count_fn = _count_fn_table({narrowed_body: 2})

    def field_population_fn(dim):
        return dim != "AccountName"  # AccountName is dead; FileName is fine

    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions=distributions, count_fn=count_fn,
        field_population_fn=field_population_fn,
    )
    assert result.iterations[0].field_check == "dead_field"
    assert result.iterations[0].candidate.dimension == "AccountName"
    assert result.iterations[1].field_check == "ok"
    assert result.iterations[1].candidate.dimension == "FileName"
    assert result.disposition == "tuned"
    assert result.final_hits == 2


def test_run_tune_loop_exhausts_all_iterations_as_dead_fields_via_for_else():
    """Every one of MAX_TUNE_ITERATIONS candidates is dead -- the for loop
    runs to completion without ever `break`ing, so Python's for/else fires.
    Distinct from the 'no candidate at all' test above: here a candidate
    IS found every time, it's just never usable."""
    distributions = _dist(
        AccountName=[("bob", 80), ("alice", 15), ("carol", 5)],
        FileName=[("evil.exe", 70), ("good.exe", 20), ("meh.exe", 10)],
        FolderPath=[("c:\\a", 60), ("c:\\b", 30), ("c:\\c", 10)],
    )
    assert tune.MAX_TUNE_ITERATIONS == 3, "test assumes the documented default of 3"
    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions=distributions, count_fn=lambda b: 0,
        field_population_fn=lambda d: False,
    )
    assert len(result.iterations) == 3
    assert all(it.field_check == "dead_field" for it in result.iterations)
    assert result.disposition == "needs_human_tuning"


def test_run_tune_loop_no_safe_insertion_point_is_not_narrowable():
    # is_narrowable() requires a where-clause, but a body whose where-line
    # sits after a blocking stage can still slip past that check while
    # apply_narrowing() itself finds no safe point (defensive re-check).
    body = "DeviceProcessEvents\n| where FileName == \"a.exe\"\n| project FileName"
    # Force apply_narrowing to fail by monkeypatching is impractical here;
    # instead directly assert apply_narrowing's None propagates through
    # run_tune_loop by using a body where the safe insertion point search
    # itself returns None: a where-line matched, but everything after it
    # (including the where-line) is inside a blocking stage already -- not
    # reachable via is_narrowable's own gate, so exercise apply_narrowing's
    # defensive branch directly instead (see test_apply_narrowing_returns_none
    # above) and confirm run_tune_loop's handling of that None by monkeypatching.
    import types
    distributions = _dist(AccountName=[("bob", 80), ("alice", 15), ("carol", 5)])
    original_apply = tune.apply_narrowing
    try:
        tune.apply_narrowing = lambda body, cand: None
        result = tune.run_tune_loop(
            artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
            distributions=distributions, count_fn=lambda b: 0,
            field_population_fn=lambda d: True,
        )
    finally:
        tune.apply_narrowing = original_apply
    assert result.disposition == "not_narrowable"
    assert result.iterations[-1].field_check == "error"


def test_run_tune_loop_increase_in_hits_is_a_tuner_defect_and_stops():
    distributions = _dist(AccountName=[("bob", 80), ("alice", 15), ("carol", 5)])
    narrowed_body = tune.apply_narrowing(_SIMPLE, tune.NarrowingCandidate("AccountName", "bob", 0.8, 3))
    count_fn = _count_fn_table({narrowed_body: 15})  # went UP from 10

    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions=distributions, count_fn=count_fn,
        field_population_fn=lambda d: True,
    )
    assert result.disposition == "needs_human_tuning"
    assert "increased" in result.iterations[0].note
    assert result.final_hits == 10, "must not adopt a narrowing that made things worse"


def test_run_tune_loop_no_reduction_stops_as_needs_human_tuning():
    distributions = _dist(AccountName=[("bob", 80), ("alice", 15), ("carol", 5)])
    narrowed_body = tune.apply_narrowing(_SIMPLE, tune.NarrowingCandidate("AccountName", "bob", 0.8, 3))
    count_fn = _count_fn_table({narrowed_body: 10})  # unchanged

    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions=distributions, count_fn=count_fn,
        field_population_fn=lambda d: True,
    )
    assert result.disposition == "needs_human_tuning"
    assert "no reduction" in result.iterations[0].note
    assert result.final_hits == 10


def test_run_tune_loop_reaches_zero_hits_is_clean_after_tuning():
    distributions = _dist(AccountName=[("bob", 80), ("alice", 15), ("carol", 5)])
    narrowed_body = tune.apply_narrowing(_SIMPLE, tune.NarrowingCandidate("AccountName", "bob", 0.8, 3))
    count_fn = _count_fn_table({narrowed_body: 0})

    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions=distributions, count_fn=count_fn,
        field_population_fn=lambda d: True,
    )
    assert result.disposition == "clean_after_tuning"
    assert result.final_hits == 0
    assert result.final_body == narrowed_body


def test_run_tune_loop_reaches_readable_range_is_tuned():
    distributions = _dist(AccountName=[("bob", 80), ("alice", 15), ("carol", 5)])
    narrowed_body = tune.apply_narrowing(_SIMPLE, tune.NarrowingCandidate("AccountName", "bob", 0.8, 3))
    count_fn = _count_fn_table({narrowed_body: 3})

    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions=distributions, count_fn=count_fn,
        field_population_fn=lambda d: True,
    )
    assert result.disposition == "tuned"
    assert result.final_hits == 3


def test_run_tune_loop_iteration_cap_reached_notes_it_and_stops():
    """A rule that keeps genuinely reducing but never reaches the readable
    range within MAX_TUNE_ITERATIONS stops at the cap, not silently forever."""
    assert tune.MAX_TUNE_ITERATIONS == 3
    distributions = _dist(
        AccountName=[("bob", 80), ("alice", 15), ("carol", 5)],
        FileName=[("evil.exe", 70), ("good.exe", 20), ("meh.exe", 10)],
        FolderPath=[("c:\\a", 60), ("c:\\b", 30), ("c:\\c", 10)],
    )
    body1 = tune.apply_narrowing(_SIMPLE, tune.NarrowingCandidate("AccountName", "bob", 0.8, 3))
    body2 = tune.apply_narrowing(body1, tune.NarrowingCandidate("FileName", "evil.exe", 0.7, 3))
    body3 = tune.apply_narrowing(body2, tune.NarrowingCandidate("FolderPath", "c:\\a", 0.6, 3))
    count_fn = _count_fn_table({body1: 8, body2: 6, body3: 5})

    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions=distributions, count_fn=count_fn,
        field_population_fn=lambda d: True,
    )
    assert result.disposition == "needs_human_tuning"
    assert len(result.iterations) == 3
    assert "iteration cap reached" in result.iterations[-1].note
    assert result.final_hits == 5


def test_run_tune_loop_refreshes_distributions_via_distribution_fn_between_iterations():
    distributions = _dist(AccountName=[("bob", 80), ("alice", 15), ("carol", 5)])
    body1 = tune.apply_narrowing(_SIMPLE, tune.NarrowingCandidate("AccountName", "bob", 0.8, 3))
    body2 = tune.apply_narrowing(body1, tune.NarrowingCandidate("FileName", "evil.exe", 0.9, 3))
    count_fn = _count_fn_table({body1: 8, body2: 2})

    refreshed = _dist(FileName=[("evil.exe", 90), ("good.exe", 7), ("meh.exe", 3)])
    calls = []
    def distribution_fn(body):
        calls.append(body)
        return refreshed

    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions=distributions, count_fn=count_fn,
        field_population_fn=lambda d: True, distribution_fn=distribution_fn,
    )
    assert calls == [body1], "must refresh against the newly-narrowed body, not the original"
    assert result.disposition == "tuned"
    assert result.final_hits == 2


def test_run_tune_loop_distribution_fn_exception_falls_back_to_stale_distributions():
    # alice's share (35/100) must clear CONCENTRATION_THRESHOLD on its own
    # against the ORIGINAL total for the second iteration to propose it at
    # all -- see test_propose_narrowing_falls_back_to_next_value_when_top_already_excluded.
    distributions = _dist(AccountName=[("bob", 60), ("alice", 35), ("carol", 5)])
    body1 = tune.apply_narrowing(_SIMPLE, tune.NarrowingCandidate("AccountName", "bob", 0.6, 3))
    # Second iteration proposes AccountName's next value ("alice") again --
    # only possible if the stale (unrefreshed) `distributions` dict is what's
    # actually used, proving the failed refresh degraded gracefully instead
    # of aborting the loop.
    body2 = tune.apply_narrowing(body1, tune.NarrowingCandidate("AccountName", "alice", 0.35, 3))
    count_fn = _count_fn_table({body1: 8, body2: 3})

    def _boom(body):
        raise RuntimeError("distribution query failed")

    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions=distributions, count_fn=count_fn,
        field_population_fn=lambda d: True, distribution_fn=_boom,
    )
    assert result.disposition == "tuned"
    assert result.final_hits == 3
    assert result.iterations[1].candidate.excluded_value == "alice"


# --- to_row() final_body persistence ------------------------------------
# tune.py previously stored only iteration bookkeeping into
# analytics.tune_history -- never the actual proposed KQL text, so nothing
# downstream had a real suggestion to show or apply. final_body must appear
# for the two dispositions where a genuine narrowed query actually exists
# ('tuned' and 'clean_after_tuning'), and must be None everywhere else so a
# reviewer never mistakes "no real suggestion" for one.

def test_to_row_includes_final_body_when_tuned():
    distributions = _dist(AccountName=[("bob", 80), ("alice", 15), ("carol", 5)])
    narrowed_body = tune.apply_narrowing(_SIMPLE, tune.NarrowingCandidate("AccountName", "bob", 0.8, 3))
    count_fn = _count_fn_table({narrowed_body: 3})

    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions=distributions, count_fn=count_fn,
        field_population_fn=lambda d: True,
    )
    assert result.disposition == "tuned"
    row = result.to_row()
    assert row["final_body"] == narrowed_body
    assert row["final_body"] != result.original_body


def test_to_row_includes_final_body_when_clean_after_tuning():
    distributions = _dist(AccountName=[("bob", 80), ("alice", 15), ("carol", 5)])
    narrowed_body = tune.apply_narrowing(_SIMPLE, tune.NarrowingCandidate("AccountName", "bob", 0.8, 3))
    count_fn = _count_fn_table({narrowed_body: 0})

    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions=distributions, count_fn=count_fn,
        field_population_fn=lambda d: True,
    )
    assert result.disposition == "clean_after_tuning"
    assert result.to_row()["final_body"] == narrowed_body


def test_to_row_final_body_is_none_when_needs_human_tuning():
    distributions = _dist(AccountName=[("bob", 80), ("alice", 15), ("carol", 5)])
    narrowed_body = tune.apply_narrowing(_SIMPLE, tune.NarrowingCandidate("AccountName", "bob", 0.8, 3))
    count_fn = _count_fn_table({narrowed_body: 10})  # unchanged -> needs_human_tuning

    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions=distributions, count_fn=count_fn,
        field_population_fn=lambda d: True,
    )
    assert result.disposition == "needs_human_tuning"
    assert result.to_row()["final_body"] is None


def test_to_row_final_body_is_none_when_not_narrowable():
    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body="let x = 1;\n" + _SIMPLE, original_hits=10,
        distributions={}, count_fn=lambda body: 0, field_population_fn=lambda d: True,
    )
    assert result.disposition == "not_narrowable"
    assert result.to_row()["final_body"] is None


def test_to_row_final_body_is_none_when_no_candidate_needs_human_tuning():
    result = tune.run_tune_loop(
        artifact_id="a1", title="t", body=_SIMPLE, original_hits=10,
        distributions={}, count_fn=lambda body: 0, field_population_fn=lambda d: True,
    )
    assert result.disposition == "needs_human_tuning"
    assert result.final_body == result.original_body  # runner default, never adopted
    assert result.to_row()["final_body"] is None
