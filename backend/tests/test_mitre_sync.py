"""Pure-logic tests for mitre_sync.py's STIX fetch/parse -- no network, no DB."""

import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import mitre_sync

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "mitre_stix_sample.json"


def _load_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_parse_bundle_extracts_one_strategy_two_analytics_two_data_components():
    bundle = _load_fixture()
    strategies, data_components = mitre_sync.parse_bundle(bundle)

    assert len(strategies) == 1
    assert strategies[0].technique_id == "T1053.005"
    assert strategies[0].det_id == "DET0210"
    assert len(strategies[0].analytics) == 2
    assert {dc.name for dc in data_components} == {"Process Creation", "Command Execution"}


def test_parse_bundle_excludes_strategy_without_detects_relationship():
    """A detection-strategy object with no 'detects' relationship to any
    technique has no resolvable technique_id -- parse_bundle() must skip it
    silently (decline safely) rather than raise or include it with a None
    technique_id. The fixture's 'x-mitre-detection-strategy--fixture-orphan'
    object exists for exactly this case."""
    bundle = _load_fixture()
    strategies, _ = mitre_sync.parse_bundle(bundle)

    assert len(strategies) == 1
    assert all(s.id != "x-mitre-detection-strategy--fixture-orphan" for s in strategies)
    assert all(s.det_id != "DET9999" for s in strategies)


def test_extract_strategy_finds_matching_technique_with_both_platforms():
    bundle = _load_fixture()
    strategy = mitre_sync.extract_strategy(bundle, "T1053.005")

    assert strategy.technique_id == "T1053.005"
    assert strategy.det_id == "DET0210"
    assert "scheduled task" in strategy.objective.lower()
    assert strategy.catalog_version == "18.0-test"
    assert len(strategy.analytics) == 2

    windows = next(a for a in strategy.analytics if a["platform"] == "Windows")
    assert windows["name"] == "Scheduled Task Creation via schtasks.exe"
    assert windows["log_sources"] == [
        {"data_component": "Process Creation", "name": "sysmon", "channel": "1"}
    ]
    assert windows["mutable_elements"][0]["field"] == "process_command_line"

    linux = next(a for a in strategy.analytics if a["platform"] == "Linux")
    assert linux["log_sources"] == [
        {"data_component": "Command Execution", "name": "auditd", "channel": "SYSCALL"}
    ]
    assert linux["mutable_elements"] == []


def test_extract_strategy_returns_none_det_id_for_unmatched_technique():
    bundle = _load_fixture()
    strategy = mitre_sync.extract_strategy(bundle, "T9999.999")

    assert strategy.technique_id == "T9999.999"
    assert strategy.det_id is None
    assert strategy.objective is None
    assert strategy.analytics == []


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeHttpClient:
    def __init__(self, payload):
        self._payload = payload

    def get(self, url, follow_redirects=True):
        return _FakeResponse(self._payload)


def test_fetch_stix_bundle_returns_parsed_json():
    payload = {"objects": []}
    result = mitre_sync.fetch_stix_bundle(http_client=_FakeHttpClient(payload))
    assert result == payload


class _FailingResponse:
    def raise_for_status(self):
        raise httpx.HTTPStatusError(
            "503 Server Error", request=httpx.Request("GET", "https://example.test"),
            response=httpx.Response(503, request=httpx.Request("GET", "https://example.test")),
        )

    def json(self):
        raise AssertionError("json() should not be called when raise_for_status() raises")


class _FailingHttpClient:
    def get(self, url, follow_redirects=True):
        return _FailingResponse()


def test_fetch_stix_bundle_raises_on_http_error():
    """fetch_stix_bundle()'s docstring promises it 'raises on failure' --
    callers (alignment_check.py) decide what that means, but the exception
    must actually propagate rather than being swallowed."""
    with pytest.raises(httpx.HTTPStatusError):
        mitre_sync.fetch_stix_bundle(http_client=_FailingHttpClient())


def test_sync_all_populates_all_three_tables(db_conn):
    bundle = _load_fixture()
    counts = mitre_sync.sync_all(db_conn, http_client=_FakeHttpClient(bundle))

    assert counts == {"strategies": 1, "data_components": 2}
    strategy_count = db_conn.execute("SELECT COUNT(*) FROM mitre_detection_strategies").fetchone()[0]
    analytic_count = db_conn.execute("SELECT COUNT(*) FROM mitre_analytics").fetchone()[0]
    dc_count = db_conn.execute("SELECT COUNT(*) FROM mitre_data_components").fetchone()[0]
    assert strategy_count == 1
    assert analytic_count == 2
    assert dc_count == 2


def test_sync_all_is_idempotent(db_conn):
    bundle = _load_fixture()
    mitre_sync.sync_all(db_conn, http_client=_FakeHttpClient(bundle))
    mitre_sync.sync_all(db_conn, http_client=_FakeHttpClient(bundle))

    strategy_count = db_conn.execute("SELECT COUNT(*) FROM mitre_detection_strategies").fetchone()[0]
    analytic_count = db_conn.execute("SELECT COUNT(*) FROM mitre_analytics").fetchone()[0]
    assert strategy_count == 1
    assert analytic_count == 2


class _FlakyConn:
    """Wraps a real connection and raises on the Nth execute() call, to
    simulate a non-SQL exception interrupting sync_all()'s write loop
    partway through (e.g. a schema-drift bug against the real live
    catalog). Delegates everything else -- including commit()/rollback()
    -- to the real connection so the test can verify against the same
    underlying transaction."""

    def __init__(self, real_conn, fail_at):
        self._real = real_conn
        self._calls = 0
        self._fail_at = fail_at

    def execute(self, query, params=None):
        self._calls += 1
        if self._calls == self._fail_at:
            raise RuntimeError("simulated mid-sync failure")
        return self._real.execute(query, params)

    def commit(self):
        self._real.commit()

    def rollback(self):
        self._real.rollback()


def test_sync_all_rolls_back_on_mid_sync_failure(db_conn):
    """The fixture's write order is: 2 data_components, then 1 strategy,
    then 2 analytics -- 5 execute() calls for a clean run. Failing on the
    3rd call (the strategy insert) means 2 writes already landed inside
    the open transaction before the exception hits; sync_all() must roll
    those back too, not just skip the ones after the failure, so nothing
    partial is ever visible to a later get_mitre_strategy() /
    _has_synced_before() check."""
    bundle = _load_fixture()
    flaky = _FlakyConn(db_conn, fail_at=3)

    with pytest.raises(RuntimeError, match="simulated mid-sync failure"):
        mitre_sync.sync_all(flaky, http_client=_FakeHttpClient(bundle))

    dc_count = db_conn.execute("SELECT COUNT(*) FROM mitre_data_components").fetchone()[0]
    strategy_count = db_conn.execute("SELECT COUNT(*) FROM mitre_detection_strategies").fetchone()[0]
    analytic_count = db_conn.execute("SELECT COUNT(*) FROM mitre_analytics").fetchone()[0]
    assert dc_count == 0
    assert strategy_count == 0
    assert analytic_count == 0

    # The cache must still register as "never synced" so a subsequent
    # get_mitre_strategy() retries the sync rather than treating the
    # rolled-back attempt as done.
    assert mitre_sync._has_synced_before(db_conn) is False


def test_get_cached_strategy_reconstructs_full_shape(db_conn):
    bundle = _load_fixture()
    mitre_sync.sync_all(db_conn, http_client=_FakeHttpClient(bundle))

    strategy = mitre_sync.get_cached_strategy(db_conn, "T1053.005")

    assert strategy.det_id == "DET0210"
    assert len(strategy.analytics) == 2
    windows = next(a for a in strategy.analytics if a["platform"] == "Windows")
    assert windows["log_sources"][0] == {"data_component": "Process Creation", "name": "sysmon", "channel": "1"}


def test_get_cached_strategy_returns_none_det_id_for_uncached_technique(db_conn):
    bundle = _load_fixture()
    mitre_sync.sync_all(db_conn, http_client=_FakeHttpClient(bundle))

    strategy = mitre_sync.get_cached_strategy(db_conn, "T9999.999")

    assert strategy.det_id is None
    assert strategy.analytics == []


def test_get_mitre_strategy_syncs_once_when_cache_empty(db_conn):
    bundle = _load_fixture()
    calls = {"n": 0}

    class _CountingHttpClient(_FakeHttpClient):
        def get(self, url, follow_redirects=True):
            calls["n"] += 1
            return super().get(url, follow_redirects=follow_redirects)

    strategy = mitre_sync.get_mitre_strategy(db_conn, "T1053.005", http_client=_CountingHttpClient(bundle))
    assert strategy.det_id == "DET0210"
    assert calls["n"] == 1

    # Cache is now populated -- a second call, even for a technique with no
    # strategy of its own, must not trigger another sync.
    strategy2 = mitre_sync.get_mitre_strategy(db_conn, "T9999.999", http_client=_CountingHttpClient(bundle))
    assert strategy2.det_id is None
    assert calls["n"] == 1


# --- Gap coverage: _as_list()'s two branches and get_cached_strategy()'s
# dangling-reference fallback aren't exercised by the tests above (psycopg
# always hands back jsonb columns already decoded to list/dict, and
# sync_all() always inserts every data component the bundle references, so
# neither the "value is a raw JSON string" nor the "referenced data
# component id has no matching row" path comes up through the sync_all() /
# get_cached_strategy() flow alone). Both are real "decline safely" paths
# per their docstrings, so cover them directly.


def test_as_list_returns_list_unchanged():
    assert mitre_sync._as_list(["a", "b"]) == ["a", "b"]


def test_as_list_parses_json_string():
    assert mitre_sync._as_list('[{"a": 1}]') == [{"a": 1}]


def test_as_list_treats_none_as_empty_list():
    assert mitre_sync._as_list(None) == []


def test_get_cached_strategy_falls_back_to_raw_id_for_dangling_data_component_ref(db_conn):
    """A log_source_reference whose data_component_id has no matching row in
    mitre_data_components must not crash or silently drop the reference --
    it falls back to the raw id via get_cached_strategy()'s
    dc_name_by_id.get(id, id) lookup. sync_all()'s own write order (all
    data components upserted before any analytic that references them)
    makes this impossible to reach through sync_all() itself; the real
    source would be the upstream STIX bundle containing a dangling
    reference, or a row seeded directly by ops tooling -- which is what
    this test does."""
    db_conn.execute(
        "INSERT INTO mitre_detection_strategies (id, det_id, technique_id, name, objective, catalog_version) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("x-mitre-detection-strategy--dangling", "DET0001", "T0001", "Test Strategy",
         "Test objective", "1.0"),
    )
    db_conn.execute(
        "INSERT INTO mitre_analytics "
        "(id, detection_strategy_id, name, description, platform, log_source_references, mutable_elements) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("x-mitre-analytic--dangling", "x-mitre-detection-strategy--dangling", "Test Analytic", "desc", "Windows",
         json.dumps([{"data_component_id": "x-mitre-data-component--missing", "name": "src", "channel": "chan"}]),
         json.dumps([])),
    )
    db_conn.commit()

    strategy = mitre_sync.get_cached_strategy(db_conn, "T0001")

    assert strategy.analytics[0]["log_sources"][0] == {
        "data_component": "x-mitre-data-component--missing", "name": "src", "channel": "chan",
    }
