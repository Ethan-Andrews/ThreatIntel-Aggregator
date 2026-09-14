"""Tests for sentinel_hunt_sync.py -- the read-only ARM client that pulls
Sentinel's own hunt/query inventory into sentinel_hunts/sentinel_hunt_queries.
HTTP is mocked via httpx.MockTransport, same convention as
test_sentinel_hunting.py (the write-side sibling)."""

import json
import sys
import types
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import sentinel_hunt_sync

# Captured before any test monkeypatches sentinel_hunt_sync.SentinelHuntReadClient
# itself (sync_all() tests below do exactly that) -- using the module
# attribute here instead would recurse into whatever it's been patched to.
_RealSentinelHuntReadClient = sentinel_hunt_sync.SentinelHuntReadClient


class _FakeCredential:
    def get_token(self, scope):
        return types.SimpleNamespace(token="fake-arm-token", expires_on=9999999999)


def _client_with_transport(handler, **kwargs):
    client = _RealSentinelHuntReadClient(
        subscription_id="sub-1", resource_group="rg-1", workspace_name="ws-1",
        credential=_FakeCredential(), **kwargs,
    )
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


# --- is_enabled() ----------------------------------------------------------

def test_is_enabled_false_by_default(monkeypatch):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)
    assert sentinel_hunt_sync.is_enabled() is False


def test_is_enabled_true_when_set(monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    assert sentinel_hunt_sync.is_enabled() is True


# --- SentinelHuntReadClient config validation -------------------------------

def test_client_requires_subscription_resource_group_and_workspace(monkeypatch):
    for var in ("AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP", "SENTINEL_WORKSPACE_NAME"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(sentinel_hunt_sync.SentinelHuntSyncError, match="AZURE_SUBSCRIPTION_ID"):
        sentinel_hunt_sync.SentinelHuntReadClient(credential=_FakeCredential())


# --- list_hunts() / pagination ---------------------------------------------

def test_list_hunts_single_page():
    def handler(request):
        assert request.url.path.endswith("/providers/Microsoft.SecurityInsights/hunts")
        assert "api-version=2023-12-01-preview" in str(request.url)
        return httpx.Response(200, json={"value": [{"name": "hunt-1"}, {"name": "hunt-2"}]})

    client = _client_with_transport(handler)
    hunts = client.list_hunts()
    assert [h["name"] for h in hunts] == ["hunt-1", "hunt-2"]


def test_list_hunts_walks_nextlink_across_multiple_pages():
    """The whole point of pagination here: a workspace with far more hunts
    (or, per list_hunt_relations, far more queries in one hunt -- the
    800+ case the original ask named) than fit in one ARM page must not
    silently return only the first page."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if "nextLink" not in str(request.url) and calls["n"] == 1:
            return httpx.Response(200, json={
                "value": [{"name": "hunt-1"}],
                "nextLink": "https://management.azure.com/fake-next-page?nextLink=true",
            })
        return httpx.Response(200, json={"value": [{"name": "hunt-2"}]})

    client = _client_with_transport(handler)
    hunts = client.list_hunts()
    assert [h["name"] for h in hunts] == ["hunt-1", "hunt-2"]
    assert calls["n"] == 2


def test_list_hunts_raises_on_error_status():
    def handler(request):
        return httpx.Response(403, text="Forbidden")

    client = _client_with_transport(handler)
    with pytest.raises(sentinel_hunt_sync.SentinelHuntSyncError, match="403"):
        client.list_hunts()


# --- list_hunt_relations() --------------------------------------------------

def test_list_hunt_relations_targets_correct_path():
    captured = {}

    def handler(request):
        captured["path"] = request.url.path
        return httpx.Response(200, json={"value": []})

    client = _client_with_transport(handler)
    client.list_hunt_relations("hunt-abc")
    assert captured["path"].endswith("/hunts/hunt-abc/relations")


# --- list_saved_searches() --------------------------------------------------

def test_list_saved_searches_not_paginated_single_call():
    """SavedSearchesOperations.list_by_workspace has no top/skipToken --
    confirm this makes exactly one call and doesn't try to follow a
    nextLink that will never be present."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        assert "savedSearches" in request.url.path
        assert "api-version=2020-08-01" in str(request.url)
        return httpx.Response(200, json={"value": [{"name": "q-1"}]})

    client = _client_with_transport(handler)
    result = client.list_saved_searches()
    assert calls["n"] == 1
    assert result == [{"name": "q-1"}]


# --- sync_all() --------------------------------------------------------------

def test_sync_all_disabled_is_noop(monkeypatch, db_conn):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)
    result = sentinel_hunt_sync.sync_all(db_conn)
    assert result == {
        "enabled": False, "hunts_synced": 0, "queries_synced": 0, "errors": [],
        "hunts_removed": 0, "queries_removed": 0, "sweep_skipped_hunts": [],
    }


def test_sync_all_upserts_hunts_and_matched_queries(monkeypatch, db_conn):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")

    saved_search_id = (
        "/subscriptions/sub-1/resourceGroups/rg-1/providers/"
        "Microsoft.OperationalInsights/workspaces/ws-1/savedSearches/query-1"
    )

    def handler(request):
        path = request.url.path
        if path.endswith("/hunts"):
            return httpx.Response(200, json={"value": [{
                "name": "hunt-1",
                "properties": {
                    "displayName": "Suspicious Process Chains",
                    "description": "hunt desc",
                    "status": "Active",
                    "hypothesisStatus": "Unknown",
                    "attackTactics": ["Execution"],
                    "attackTechniques": ["T1059"],
                },
            }]})
        if path.endswith("/relations"):
            return httpx.Response(200, json={"value": [{
                "properties": {
                    "relatedResourceId": saved_search_id,
                    "relatedResourceKind": "SavedSearch",
                },
            }]})
        if path.endswith("/savedSearches"):
            return httpx.Response(200, json={"value": [{
                "id": saved_search_id,
                "name": "query-1",
                "properties": {
                    "displayName": "Suspicious child process",
                    "query": "DeviceProcessEvents | take 1",
                    "tags": [{"Name": "description", "Value": "a query"}],
                },
            }]})
        raise AssertionError(f"unexpected path: {path}")

    monkeypatch.setattr(
        sentinel_hunt_sync, "SentinelHuntReadClient",
        lambda *a, **kw: _client_with_transport(handler),
    )

    result = sentinel_hunt_sync.sync_all(db_conn)
    assert result["enabled"] is True
    assert result["hunts_synced"] == 1
    assert result["queries_synced"] == 1
    assert result["errors"] == []

    hunt_row = db_conn.execute(
        "SELECT display_name, query_count, status FROM sentinel_hunts WHERE sentinel_hunt_id = ?",
        ("hunt-1",),
    ).fetchone()
    assert hunt_row["display_name"] == "Suspicious Process Chains"
    assert hunt_row["query_count"] == 1
    assert hunt_row["status"] == "Active"

    query_row = db_conn.execute(
        "SELECT display_name, kql_body FROM sentinel_hunt_queries "
        "WHERE sentinel_saved_search_id = ?",
        ("query-1",),
    ).fetchone()
    assert query_row["display_name"] == "Suspicious child process"
    assert query_row["kql_body"] == "DeviceProcessEvents | take 1"


def test_sync_all_strips_html_from_hunt_and_query_descriptions(monkeypatch, db_conn):
    """Sentinel's own portal stores Hunt/query description as rich-text HTML
    (e.g. `<p><span>...</span></p>`) -- confirmed live via a screenshot
    showing the raw tags rendered as literal on-screen text in
    SentinelHuntsPanel.js, since this app never parses HTML for display.
    Stripped at sync time so no consumer needs to make that trust call."""
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")

    saved_search_id = (
        "/subscriptions/sub-1/resourceGroups/rg-1/providers/"
        "Microsoft.OperationalInsights/workspaces/ws-1/savedSearches/query-1"
    )

    def handler(request):
        path = request.url.path
        if path.endswith("/hunts"):
            return httpx.Response(200, json={"value": [{
                "name": "hunt-1",
                "properties": {
                    "displayName": "Suspicious Process Chains",
                    "description": "<p><span>A Valid DKIM Signature Over an "
                                    "Unauthorized Message</span></p>",
                    "status": "Active",
                    "hypothesisStatus": "Unknown",
                    "attackTactics": ["Execution"],
                    "attackTechniques": ["T1059"],
                },
            }]})
        if path.endswith("/relations"):
            return httpx.Response(200, json={"value": [{
                "properties": {
                    "relatedResourceId": saved_search_id,
                    "relatedResourceKind": "SavedSearch",
                },
            }]})
        if path.endswith("/savedSearches"):
            return httpx.Response(200, json={"value": [{
                "id": saved_search_id,
                "name": "query-1",
                "properties": {
                    "displayName": "Suspicious child process",
                    "query": "DeviceProcessEvents | take 1",
                    "tags": [{"Name": "description", "Value": "<div>a query</div>"}],
                },
            }]})
        raise AssertionError(f"unexpected path: {path}")

    monkeypatch.setattr(
        sentinel_hunt_sync, "SentinelHuntReadClient",
        lambda *a, **kw: _client_with_transport(handler),
    )

    result = sentinel_hunt_sync.sync_all(db_conn)
    assert result["errors"] == []

    hunt_row = db_conn.execute(
        "SELECT description FROM sentinel_hunts WHERE sentinel_hunt_id = ?",
        ("hunt-1",),
    ).fetchone()
    assert hunt_row["description"] == "A Valid DKIM Signature Over an Unauthorized Message"
    assert "<" not in hunt_row["description"]

    query_row = db_conn.execute(
        "SELECT description FROM sentinel_hunt_queries WHERE sentinel_saved_search_id = ?",
        ("query-1",),
    ).fetchone()
    assert query_row["description"] == "a query"
    assert "<" not in query_row["description"]


def test_strip_html_passes_through_none_and_empty_unchanged():
    assert sentinel_hunt_sync._strip_html(None) is None
    assert sentinel_hunt_sync._strip_html("") == ""
    assert sentinel_hunt_sync._strip_html("plain text") == "plain text"


def test_sync_all_matches_the_real_relatedresourcetype_shape(monkeypatch, db_conn):
    """Regression test: confirmed live 2026-09-01 against a real workspace,
    GET .../hunts/{id}/relations does NOT echo back relatedResourceKind (the
    field the write path's PUT body sends) -- it carries relatedResourceType
    instead, valued "Microsoft.OperationalInsights/SavedSearches", and the
    relatedResourceId path segment is "SavedSearches" (capital S), not the
    lowercase "savedSearches" the list-saved-searches response's own `id`
    uses. Checking only relatedResourceKind meant every hunt's query list
    silently read back empty, in prod, for every real hunt including ones
    with dozens of already-linked queries."""
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")

    saved_search_arm_id_lowercase = (
        "/subscriptions/sub-1/resourceGroups/rg-1/providers/"
        "Microsoft.OperationalInsights/workspaces/ws-1/savedSearches/query-1"
    )
    saved_search_arm_id_relation_casing = (
        "/subscriptions/sub-1/resourceGroups/rg-1/providers/"
        "Microsoft.OperationalInsights/workspaces/ws-1/SavedSearches/query-1"
    )

    def handler(request):
        path = request.url.path
        if path.endswith("/hunts"):
            return httpx.Response(200, json={"value": [{
                "name": "hunt-1", "properties": {"displayName": "Real Hunt"},
            }]})
        if path.endswith("/relations"):
            return httpx.Response(200, json={"value": [{
                "properties": {
                    "relatedResourceId": saved_search_arm_id_relation_casing,
                    "relatedResourceName": "query-1",
                    "relatedResourceType": "Microsoft.OperationalInsights/SavedSearches",
                    # No relatedResourceKind key at all -- confirmed live.
                },
            }]})
        if path.endswith("/savedSearches"):
            return httpx.Response(200, json={"value": [{
                "id": saved_search_arm_id_lowercase,
                "name": "query-1",
                "properties": {"displayName": "Real Query", "query": "T | take 1"},
            }]})
        raise AssertionError(f"unexpected path: {path}")

    monkeypatch.setattr(
        sentinel_hunt_sync, "SentinelHuntReadClient",
        lambda *a, **kw: _client_with_transport(handler),
    )

    result = sentinel_hunt_sync.sync_all(db_conn)
    assert result["queries_synced"] == 1

    hunt_row = db_conn.execute(
        "SELECT query_count FROM sentinel_hunts WHERE sentinel_hunt_id = ?", ("hunt-1",)
    ).fetchone()
    assert hunt_row["query_count"] == 1
    query_row = db_conn.execute(
        "SELECT display_name FROM sentinel_hunt_queries WHERE sentinel_saved_search_id = ?",
        ("query-1",),
    ).fetchone()
    assert query_row["display_name"] == "Real Query"


def test_sync_all_reupsert_updates_existing_rows_not_duplicates(monkeypatch, db_conn):
    """A second sync of the same hunt/query must update the existing rows
    (idempotent by sentinel_hunt_id / sentinel_saved_search_id), not create
    duplicates."""
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")

    saved_search_id = (
        "/subscriptions/sub-1/resourceGroups/rg-1/providers/"
        "Microsoft.OperationalInsights/workspaces/ws-1/savedSearches/query-1"
    )
    display_name = {"value": "First Name"}

    def handler(request):
        path = request.url.path
        if path.endswith("/hunts"):
            return httpx.Response(200, json={"value": [{
                "name": "hunt-1",
                "properties": {"displayName": display_name["value"], "description": "d"},
            }]})
        if path.endswith("/relations"):
            return httpx.Response(200, json={"value": [{
                "properties": {
                    "relatedResourceId": saved_search_id,
                    "relatedResourceKind": "SavedSearch",
                },
            }]})
        if path.endswith("/savedSearches"):
            return httpx.Response(200, json={"value": [{
                "id": saved_search_id, "name": "query-1",
                "properties": {"displayName": "q", "query": "T | take 1"},
            }]})
        raise AssertionError(f"unexpected path: {path}")

    monkeypatch.setattr(
        sentinel_hunt_sync, "SentinelHuntReadClient",
        lambda *a, **kw: _client_with_transport(handler),
    )

    sentinel_hunt_sync.sync_all(db_conn)
    display_name["value"] = "Renamed Hunt"
    sentinel_hunt_sync.sync_all(db_conn)

    count = db_conn.execute("SELECT COUNT(*) FROM sentinel_hunts").fetchone()[0]
    assert count == 1
    row = db_conn.execute(
        "SELECT display_name FROM sentinel_hunts WHERE sentinel_hunt_id = ?", ("hunt-1",)
    ).fetchone()
    assert row["display_name"] == "Renamed Hunt"


def test_sync_all_one_hunt_relations_failure_does_not_abort_others(monkeypatch, db_conn):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")

    def handler(request):
        path = request.url.path
        if path.endswith("/hunts"):
            return httpx.Response(200, json={"value": [
                {"name": "hunt-bad", "properties": {"displayName": "Bad"}},
                {"name": "hunt-good", "properties": {"displayName": "Good"}},
            ]})
        if path.endswith("/hunts/hunt-bad/relations"):
            return httpx.Response(500, text="boom")
        if path.endswith("/relations"):
            return httpx.Response(200, json={"value": []})
        if path.endswith("/savedSearches"):
            return httpx.Response(200, json={"value": []})
        raise AssertionError(f"unexpected path: {path}")

    monkeypatch.setattr(
        sentinel_hunt_sync, "SentinelHuntReadClient",
        lambda *a, **kw: _client_with_transport(handler),
    )

    result = sentinel_hunt_sync.sync_all(db_conn)
    assert result["hunts_synced"] == 2
    assert len(result["errors"]) == 1
    assert "hunt-bad" in result["errors"][0]
    # A relations-fetch failure means we couldn't confirm hunt-bad's query
    # list this run, but the hunt itself was still seen -- its own
    # sentinel_hunts row must not be swept.
    assert result["sweep_skipped_hunts"] == ["hunt-bad"]
    assert result["hunts_removed"] == 0

    names = {
        r["sentinel_hunt_id"]
        for r in db_conn.execute("SELECT sentinel_hunt_id FROM sentinel_hunts").fetchall()
    }
    assert names == {"hunt-bad", "hunt-good"}


# --- sweep (mark-and-sweep delete for removed hunts/queries) ---------------
# Workstream H, docs/superpowers/specs/2026-09-04-live-feedback-round-6-design.md

def _enable_sync(monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")


def _mock_client(monkeypatch, handler):
    monkeypatch.setattr(
        sentinel_hunt_sync, "SentinelHuntReadClient",
        lambda *a, **kw: _client_with_transport(handler),
    )


def _empty_handler(hunts_value):
    def handler(request):
        path = request.url.path
        if path.endswith("/hunts"):
            return httpx.Response(200, json={"value": hunts_value})
        if path.endswith("/relations"):
            return httpx.Response(200, json={"value": []})
        if path.endswith("/savedSearches"):
            return httpx.Response(200, json={"value": []})
        raise AssertionError(f"unexpected path: {path}")
    return handler


def test_sweep_deletes_hunt_no_longer_present_and_cascades_its_queries(monkeypatch, db_conn):
    """A hunt present in a prior sync but absent from this run's list_hunts()
    response gets deleted, and its queries go with it via the existing
    ON DELETE CASCADE -- no separate query-level delete needed for this
    case."""
    _enable_sync(monkeypatch)
    _mock_client(monkeypatch, _empty_handler([
        {"name": "hunt-keep", "properties": {"displayName": "Keep"}},
        {"name": "hunt-gone", "properties": {"displayName": "Gone"}},
    ]))
    sentinel_hunt_sync.sync_all(db_conn)
    db_conn.execute(
        "INSERT INTO sentinel_hunt_queries "
        "(hunt_id, sentinel_saved_search_id, display_name, kql_body) "
        "SELECT id, 'orphan-query', 'orphan', 'T | take 1' FROM sentinel_hunts "
        "WHERE sentinel_hunt_id = 'hunt-gone'"
    )
    db_conn.commit()

    _mock_client(monkeypatch, _empty_handler([
        {"name": "hunt-keep", "properties": {"displayName": "Keep"}},
    ]))
    result = sentinel_hunt_sync.sync_all(db_conn)

    assert result["hunts_removed"] == 1
    ids = {r["sentinel_hunt_id"] for r in db_conn.execute("SELECT sentinel_hunt_id FROM sentinel_hunts").fetchall()}
    assert ids == {"hunt-keep"}
    assert db_conn.execute(
        "SELECT COUNT(*) FROM sentinel_hunt_queries WHERE sentinel_saved_search_id = 'orphan-query'"
    ).fetchone()[0] == 0


def test_sweep_deletes_query_removed_from_relations_leaves_others_alone(monkeypatch, db_conn):
    """A query removed from one hunt's relations (still-present hunt,
    smaller relations list this run) gets deleted; a query under a
    DIFFERENT hunt is untouched even though it wasn't in THIS hunt's
    relations list."""
    _enable_sync(monkeypatch)

    def handler_two_queries(request):
        path = request.url.path
        if path.endswith("/hunts"):
            return httpx.Response(200, json={"value": [{"name": "hunt-1", "properties": {}}]})
        if path.endswith("/relations"):
            return httpx.Response(200, json={"value": [
                {"properties": {"relatedResourceId": "/.../savedSearches/q-1", "relatedResourceKind": "SavedSearch"}},
                {"properties": {"relatedResourceId": "/.../savedSearches/q-2", "relatedResourceKind": "SavedSearch"}},
            ]})
        if path.endswith("/savedSearches"):
            return httpx.Response(200, json={"value": [
                {"id": "/.../savedSearches/q-1", "name": "q-1", "properties": {"displayName": "Q1", "query": "T"}},
                {"id": "/.../savedSearches/q-2", "name": "q-2", "properties": {"displayName": "Q2", "query": "T"}},
            ]})
        raise AssertionError(path)

    _mock_client(monkeypatch, handler_two_queries)
    sentinel_hunt_sync.sync_all(db_conn)

    def handler_one_query(request):
        path = request.url.path
        if path.endswith("/hunts"):
            return httpx.Response(200, json={"value": [{"name": "hunt-1", "properties": {}}]})
        if path.endswith("/relations"):
            return httpx.Response(200, json={"value": [
                {"properties": {"relatedResourceId": "/.../savedSearches/q-1", "relatedResourceKind": "SavedSearch"}},
            ]})
        if path.endswith("/savedSearches"):
            return httpx.Response(200, json={"value": [
                {"id": "/.../savedSearches/q-1", "name": "q-1", "properties": {"displayName": "Q1", "query": "T"}},
            ]})
        raise AssertionError(path)

    _mock_client(monkeypatch, handler_one_query)
    result = sentinel_hunt_sync.sync_all(db_conn)

    assert result["queries_removed"] == 1
    ids = {r["sentinel_saved_search_id"] for r in db_conn.execute("SELECT sentinel_saved_search_id FROM sentinel_hunt_queries").fetchall()}
    assert ids == {"q-1"}


def test_sweep_skips_hunt_whose_relations_fetch_failed_this_run(monkeypatch, db_conn):
    """The failure-mode test that matters most: hunt A's relations fetch
    raises this run, hunt B's succeeds normally. Hunt A's pre-existing
    queries must survive untouched -- a transient fetch error must never
    read as 'Sentinel removed every query in this hunt.' Hunt B's own
    sweep must proceed normally in the same run."""
    _enable_sync(monkeypatch)

    def handler_seed(request):
        path = request.url.path
        if path.endswith("/hunts"):
            return httpx.Response(200, json={"value": [
                {"name": "hunt-a", "properties": {}}, {"name": "hunt-b", "properties": {}},
            ]})
        if path.endswith("/hunts/hunt-a/relations"):
            return httpx.Response(200, json={"value": [
                {"properties": {"relatedResourceId": "/.../savedSearches/a-1", "relatedResourceKind": "SavedSearch"}},
            ]})
        if path.endswith("/hunts/hunt-b/relations"):
            return httpx.Response(200, json={"value": [
                {"properties": {"relatedResourceId": "/.../savedSearches/b-1", "relatedResourceKind": "SavedSearch"}},
                {"properties": {"relatedResourceId": "/.../savedSearches/b-2", "relatedResourceKind": "SavedSearch"}},
            ]})
        if path.endswith("/savedSearches"):
            return httpx.Response(200, json={"value": [
                {"id": "/.../savedSearches/a-1", "name": "a-1", "properties": {"displayName": "A1", "query": "T"}},
                {"id": "/.../savedSearches/b-1", "name": "b-1", "properties": {"displayName": "B1", "query": "T"}},
                {"id": "/.../savedSearches/b-2", "name": "b-2", "properties": {"displayName": "B2", "query": "T"}},
            ]})
        raise AssertionError(path)

    _mock_client(monkeypatch, handler_seed)
    sentinel_hunt_sync.sync_all(db_conn)
    assert db_conn.execute("SELECT COUNT(*) FROM sentinel_hunt_queries").fetchone()[0] == 3

    def handler_a_fails(request):
        path = request.url.path
        if path.endswith("/hunts"):
            return httpx.Response(200, json={"value": [
                {"name": "hunt-a", "properties": {}}, {"name": "hunt-b", "properties": {}},
            ]})
        if path.endswith("/hunts/hunt-a/relations"):
            return httpx.Response(500, text="transient ARM error")
        if path.endswith("/hunts/hunt-b/relations"):
            # b-2 no longer present this run -- a real removal.
            return httpx.Response(200, json={"value": [
                {"properties": {"relatedResourceId": "/.../savedSearches/b-1", "relatedResourceKind": "SavedSearch"}},
            ]})
        if path.endswith("/savedSearches"):
            return httpx.Response(200, json={"value": [
                {"id": "/.../savedSearches/a-1", "name": "a-1", "properties": {"displayName": "A1", "query": "T"}},
                {"id": "/.../savedSearches/b-1", "name": "b-1", "properties": {"displayName": "B1", "query": "T"}},
            ]})
        raise AssertionError(path)

    _mock_client(monkeypatch, handler_a_fails)
    result = sentinel_hunt_sync.sync_all(db_conn)

    assert result["sweep_skipped_hunts"] == ["hunt-a"]
    assert result["hunts_removed"] == 0  # both hunts still seen this run
    assert result["queries_removed"] == 1  # only b-2

    a_ids = {
        r["sentinel_saved_search_id"] for r in db_conn.execute(
            "SELECT q.sentinel_saved_search_id FROM sentinel_hunt_queries q "
            "JOIN sentinel_hunts h ON h.id = q.hunt_id WHERE h.sentinel_hunt_id = 'hunt-a'"
        ).fetchall()
    }
    assert a_ids == {"a-1"}, "hunt-a's query must survive a relations-fetch failure untouched"

    b_ids = {
        r["sentinel_saved_search_id"] for r in db_conn.execute(
            "SELECT q.sentinel_saved_search_id FROM sentinel_hunt_queries q "
            "JOIN sentinel_hunts h ON h.id = q.hunt_id WHERE h.sentinel_hunt_id = 'hunt-b'"
        ).fetchall()
    }
    assert b_ids == {"b-1"}, "hunt-b's real removal (b-2) must still be swept in the same run"


def test_sweep_never_runs_when_top_level_hunts_fetch_fails(monkeypatch, db_conn):
    """A hard failure fetching list_hunts() itself (before any hunt is
    even processed) must abort the sweep entirely -- it must never read
    as 'the workspace now has zero hunts.'"""
    _enable_sync(monkeypatch)
    _mock_client(monkeypatch, _empty_handler([{"name": "hunt-1", "properties": {}}]))
    sentinel_hunt_sync.sync_all(db_conn)
    assert db_conn.execute("SELECT COUNT(*) FROM sentinel_hunts").fetchone()[0] == 1

    def handler_fails(request):
        return httpx.Response(500, text="ARM outage")

    _mock_client(monkeypatch, handler_fails)
    result = sentinel_hunt_sync.sync_all(db_conn)

    assert result["hunts_removed"] == 0
    assert result["queries_removed"] == 0
    assert len(result["errors"]) == 1
    assert db_conn.execute("SELECT COUNT(*) FROM sentinel_hunts").fetchone()[0] == 1, \
        "a failed top-level fetch must not delete pre-existing rows"


def test_sweep_deletes_everything_on_genuinely_empty_successful_fetch(monkeypatch, db_conn):
    """The counterpart to the guard above: a real, successful, empty
    list_hunts() response (no exception at all) is a legitimate state and
    must still sweep correctly -- the guards must not over-correct into
    never deleting anything out of excess caution."""
    _enable_sync(monkeypatch)
    _mock_client(monkeypatch, _empty_handler([{"name": "hunt-1", "properties": {}}]))
    sentinel_hunt_sync.sync_all(db_conn)
    assert db_conn.execute("SELECT COUNT(*) FROM sentinel_hunts").fetchone()[0] == 1

    _mock_client(monkeypatch, _empty_handler([]))
    result = sentinel_hunt_sync.sync_all(db_conn)

    assert result["hunts_removed"] == 1
    assert db_conn.execute("SELECT COUNT(*) FROM sentinel_hunts").fetchone()[0] == 0
