"""Tests for sentinel_hunting.py -- the (feature-flagged, non-fatal) ARM
client that syncs our own hunts/analytics rows into Microsoft Sentinel's
real Hunts feature and hunting-query saved searches. HTTP is mocked via
httpx.MockTransport (no network, no real Azure credentials needed) so this
can be verified before RBAC is granted -- see the module docstring."""

import sys
import types
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import sentinel_hunting


class _FakeCredential:
    def get_token(self, scope):
        return types.SimpleNamespace(token="fake-arm-token", expires_on=9999999999)


def _client_with_transport(handler, **kwargs):
    client = sentinel_hunting.SentinelHuntingClient(
        subscription_id="sub-1", resource_group="rg-1", workspace_name="ws-1",
        credential=_FakeCredential(), **kwargs,
    )
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


# --- is_enabled() -------------------------------------------------------

def test_is_enabled_false_by_default(monkeypatch):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)
    assert sentinel_hunting.is_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "True", "yes", "YES"])
def test_is_enabled_true_for_truthy_values(monkeypatch, value):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", value)
    assert sentinel_hunting.is_enabled() is True


def test_is_enabled_false_for_other_values(monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "false")
    assert sentinel_hunting.is_enabled() is False


# --- arm_safe_id() -------------------------------------------------------

def test_arm_safe_id_is_deterministic():
    assert sentinel_hunting.arm_safe_id("hunt", "42") == sentinel_hunting.arm_safe_id("hunt", "42")


def test_arm_safe_id_differs_for_different_input():
    assert sentinel_hunting.arm_safe_id("hunt", "42") != sentinel_hunting.arm_safe_id("hunt", "43")


def test_arm_safe_id_looks_like_a_guid():
    result = sentinel_hunting.arm_safe_id("query", "1", "2")
    assert len(result) == 36
    assert result.count("-") == 4


# --- SentinelHuntingClient config validation -----------------------------

def test_client_requires_subscription_resource_group_and_workspace(monkeypatch):
    for var in ("AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP", "SENTINEL_WORKSPACE_NAME"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(sentinel_hunting.SentinelHuntingError, match="AZURE_SUBSCRIPTION_ID"):
        sentinel_hunting.SentinelHuntingClient(credential=_FakeCredential())


# --- upsert_saved_search() -----------------------------------------------

def test_upsert_saved_search_sends_correct_request_shape():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["method"] = request.method
        captured["body"] = request.read()
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"id": "ok"})

    client = _client_with_transport(handler)
    resource_id = client.upsert_saved_search(
        "search-1", display_name="Suspicious Scheduled Task Creation",
        query="DeviceProcessEvents | take 1",
        description="Flags schtasks.exe", tactics=["Execution", "Persistence"],
        techniques=["T1053.005"],
        created_by="Threat Intel Aggregator", created_time_utc="2026-08-31T20:00:00.000Z",
    )

    assert captured["method"] == "PUT"
    assert "/savedSearches/search-1" in captured["url"]
    assert "api-version=2020-08-01" in captured["url"]
    assert captured["auth"] == "Bearer fake-arm-token"
    import json as _json
    body = _json.loads(captured["body"])
    # "Hunt Queries" (singular "Hunt") + version=2 -- confirmed live
    # 2026-09-01 from the Sentinel portal's own network traffic while
    # manually linking a query to a hunt; "Hunting Queries" (no version) is
    # what Microsoft's own doc example uses for the general library tab,
    # not a Hunt-linked query.
    assert body["properties"]["category"] == "Hunt Queries"
    assert body["properties"]["version"] == 2
    assert body["properties"]["displayName"] == "Suspicious Scheduled Task Creation"
    assert body["properties"]["query"] == "DeviceProcessEvents | take 1"
    # Lowercase tag names -- confirmed live 2026-08-31 against a real
    # Content-Hub-authored query's actual persisted tags in this workspace,
    # not the PascalCase shown in Microsoft's own (misleading) REST API doc.
    tags_by_name = {t["Name"]: t["Value"] for t in body["properties"]["tags"]}
    assert set(tags_by_name) == {
        "description", "tactics", "techniques", "createdBy", "createdTimeUtc",
    }
    assert tags_by_name["tactics"] == "Execution,Persistence"
    assert tags_by_name["techniques"] == "T1053.005"
    assert tags_by_name["createdBy"] == "Threat Intel Aggregator"
    assert tags_by_name["createdTimeUtc"] == "2026-08-31T20:00:00.000Z"
    assert resource_id.endswith("/savedSearches/search-1")


def test_upsert_saved_search_raises_on_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="Forbidden")

    client = _client_with_transport(handler)
    with pytest.raises(sentinel_hunting.SentinelHuntingError, match="403"):
        client.upsert_saved_search("search-1", "Name", "X | take 1")


# --- upsert_hunt() ---------------------------------------------------------

def test_upsert_hunt_sends_correct_request_shape():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = request.read()
        return httpx.Response(201, json={"id": "ok"})

    client = _client_with_transport(handler)
    resource_id = client.upsert_hunt(
        "hunt-1", display_name="BTR Reforged", description="APT campaign",
        attack_techniques=["T1053.005"],
    )

    assert "/providers/Microsoft.SecurityInsights/hunts/hunt-1" in captured["url"]
    assert "api-version=2023-12-01-preview" in captured["url"]
    import json as _json
    body = _json.loads(captured["body"])
    assert body["properties"]["displayName"] == "BTR Reforged"
    assert body["properties"]["attackTechniques"] == ["T1053.005"]
    assert body["properties"]["status"] == "New"
    assert resource_id.endswith("/hunts/hunt-1")


def test_upsert_hunt_truncates_display_name_under_100_chars():
    """Confirmed live 2026-09-02: ARM 400s a hunt PUT with "displayName
    must have length < 100" -- a source TI article's title routinely
    exceeds that, and the 200-char cap this used to share with
    upsert_saved_search() was never actually validated against the hunts
    endpoint specifically."""
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read()
        return httpx.Response(201, json={"id": "ok"})

    client = _client_with_transport(handler)
    long_title = "A" * 150
    resource_id = client.upsert_hunt("hunt-1", display_name=long_title, description="desc")

    import json as _json
    body = _json.loads(captured["body"])
    assert len(body["properties"]["displayName"]) < 100
    assert resource_id.endswith("/hunts/hunt-1")


# --- link_query_to_hunt() --------------------------------------------------

def test_link_query_to_hunt_sends_correct_request_shape():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = request.read()
        return httpx.Response(200, json={"id": "ok"})

    client = _client_with_transport(handler)
    client.link_query_to_hunt("hunt-1", "relation-1", "/subscriptions/.../savedSearches/search-1")

    assert "/hunts/hunt-1/relations/relation-1" in captured["url"]
    import json as _json
    body = _json.loads(captured["body"])
    assert body["properties"]["relatedResourceId"] == "/subscriptions/.../savedSearches/search-1"
    # Defaults to "SavedSearch" -- required for the Sentinel portal's Queries
    # tab to bucket this relation as a query rather than showing "No queries
    # were found" despite the hunt's own relation count being correct.
    assert body["properties"]["relatedResourceKind"] == "SavedSearch"


def test_link_query_to_hunt_allows_overriding_related_resource_kind():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read()
        return httpx.Response(200, json={"id": "ok"})

    client = _client_with_transport(handler)
    client.link_query_to_hunt(
        "hunt-1", "relation-1", "/subscriptions/.../bookmarks/bm-1",
        related_resource_kind="HuntingBookmark",
    )

    import json as _json
    body = _json.loads(captured["body"])
    assert body["properties"]["relatedResourceKind"] == "HuntingBookmark"


# --- list_hunts() ----------------------------------------------------------

def test_list_hunts_returns_id_and_display_name():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).endswith(
            "/providers/Microsoft.SecurityInsights/hunts?api-version=2023-12-01-preview"
        )
        return httpx.Response(200, json={"value": [
            {"name": "guid-1", "properties": {"displayName": "In the News V2"}},
            {"name": "guid-2", "properties": {"displayName": "Ransomware Watch"}},
        ]})

    client = _client_with_transport(handler)
    result = client.list_hunts()

    assert result == [
        {"id": "guid-1", "display_name": "In the News V2"},
        {"id": "guid-2", "display_name": "Ransomware Watch"},
    ]


def test_list_hunts_follows_next_link_pagination():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if "page2" not in str(request.url):
            return httpx.Response(200, json={
                "value": [{"name": "guid-1", "properties": {"displayName": "Page One"}}],
                "nextLink": "https://management.azure.com/page2",
            })
        return httpx.Response(200, json={
            "value": [{"name": "guid-2", "properties": {"displayName": "Page Two"}}],
        })

    client = _client_with_transport(handler)
    result = client.list_hunts()

    assert len(calls) == 2
    assert [h["display_name"] for h in result] == ["Page One", "Page Two"]


def test_list_hunts_raises_on_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="Forbidden")

    client = _client_with_transport(handler)
    with pytest.raises(sentinel_hunting.SentinelHuntingError):
        client.list_hunts()


# --- list_existing_hunts() --------------------------------------------------

def test_list_existing_hunts_reports_disabled_without_constructing_a_client(monkeypatch):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)

    def _boom(*a, **k):
        raise AssertionError("must not construct a client when sync is disabled")
    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _boom)

    result = sentinel_hunting.list_existing_hunts()
    assert result == {"enabled": False, "hunts": [], "error": None}


def test_list_existing_hunts_returns_hunts_when_enabled(monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    class _FakeClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def list_hunts(self):
            return [{"id": "guid-1", "display_name": "In the News V2"}]

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _FakeClient)

    result = sentinel_hunting.list_existing_hunts()
    assert result == {
        "enabled": True,
        "hunts": [{"id": "guid-1", "display_name": "In the News V2"}],
        "error": None,
    }


def test_list_existing_hunts_degrades_to_empty_list_on_failure(monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    class _FailingClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def list_hunts(self):
            raise sentinel_hunting.SentinelHuntingError("RBAC not granted yet")

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _FailingClient)

    result = sentinel_hunting.list_existing_hunts()
    assert result["enabled"] is True
    assert result["hunts"] == []
    assert "RBAC not granted yet" in result["error"]


# --- sync_hunt() orchestration --------------------------------------------

def test_sync_hunt_is_a_noop_when_disabled(monkeypatch, db_conn):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)

    def _boom(*a, **k):
        raise AssertionError("must not construct a client when sync is disabled")
    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _boom)

    sentinel_hunting.sync_hunt(
        db_conn, hunt_id=1, hunt_title="T", hunt_description="D", detections=[],
    )
    # No exception, and nothing written -- there's no hunt row to update
    # since this test doesn't seed one; the point is purely "no ARM call".


def test_sync_hunt_upserts_hunt_and_each_detection_then_marks_synced(monkeypatch, db_conn):
    import hunts as hunts_module
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "entry-hash-1", title="BTR Reforged")

    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    calls = {"hunts": [], "searches": [], "links": []}

    class _FakeClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def upsert_hunt(self, hunt_id, **kwargs):
            calls["hunts"].append((hunt_id, kwargs))
            return f"/hunts/{hunt_id}"
        def upsert_saved_search(self, search_id, **kwargs):
            calls["searches"].append((search_id, kwargs))
            return f"/savedSearches/{search_id}"
        def link_query_to_hunt(self, hunt_id, relation_id, related_resource_id, **kwargs):
            calls["links"].append((hunt_id, relation_id, related_resource_id))

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _FakeClient)

    detections = [
        {"id": 1, "name": "Detection A", "description": "Desc A", "kql_body": "X | take 1",
         "technique_id": "T1053.005", "technique_name": "Scheduled Task"},
        {"id": 2, "name": "Detection B", "description": "Desc B", "kql_body": "Y | take 1",
         "technique_id": "T1059.001", "technique_name": "PowerShell"},
    ]
    sentinel_hunting.sync_hunt(
        db_conn, hunt_id, hunt_title="BTR Reforged", hunt_description="APT campaign",
        detections=detections,
    )

    assert len(calls["hunts"]) == 1
    assert calls["hunts"][0][1]["display_name"] == "BTR Reforged"
    assert set(calls["hunts"][0][1]["attack_techniques"]) == {"T1053", "T1059"}
    assert len(calls["searches"]) == 2
    assert len(calls["links"]) == 2

    # Each saved search gets its own detection's technique/tactics, derived
    # from mitre_tactics -- not the raw technique_name (confirmed live
    # 2026-08-31: a saved search's "tactics" tag was showing an entire
    # embedded YARA rule because technique_name was being used directly).
    # techniques is the base technique id (sub-technique suffix stripped),
    # matching the real "techniques" tag convention confirmed live.
    searches_by_id = {sid: kwargs for sid, kwargs in calls["searches"]}
    det_a_kwargs = next(kwargs for kwargs in searches_by_id.values() if kwargs["techniques"] == ["T1053"])
    assert set(det_a_kwargs["tactics"]) == {"Execution", "Persistence", "PrivilegeEscalation"}
    assert det_a_kwargs["created_by"] == "Threat Intel Aggregator"
    assert det_a_kwargs["created_time_utc"]
    det_b_kwargs = next(kwargs for kwargs in searches_by_id.values() if kwargs["techniques"] == ["T1059"])
    assert set(det_b_kwargs["tactics"]) == {"Execution"}

    row = db_conn.execute("SELECT sentinel_hunt_id, sentinel_sync_error FROM hunts WHERE id = ?",
                          (hunt_id,)).fetchone()
    assert row["sentinel_hunt_id"] is not None
    assert row["sentinel_sync_error"] is None


def test_sync_hunt_with_a_target_links_into_the_existing_hunt_without_upserting_it(monkeypatch, db_conn):
    """target_sentinel_hunt_id (an admin's existing Sentinel Hunt, e.g. "In
    the News V2") must never have its own title/description/status
    overwritten by ours -- upsert_hunt() must not be called at all."""
    import hunts as hunts_module
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "entry-hash-1", title="BTR Reforged")
    hunts_module.set_hunt_target(db_conn, hunt_id, "existing-hunt-guid")

    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    calls = {"hunts": [], "searches": [], "links": []}

    class _FakeClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def upsert_hunt(self, hunt_id, **kwargs):
            calls["hunts"].append((hunt_id, kwargs))
            return f"/hunts/{hunt_id}"
        def upsert_saved_search(self, search_id, **kwargs):
            calls["searches"].append((search_id, kwargs))
            return f"/savedSearches/{search_id}"
        def link_query_to_hunt(self, hunt_id, relation_id, related_resource_id, **kwargs):
            calls["links"].append((hunt_id, relation_id, related_resource_id))

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _FakeClient)

    detections = [
        {"id": 1, "name": "Detection A", "description": "Desc A", "kql_body": "X | take 1",
         "technique_id": "T1053.005", "technique_name": "Scheduled Task"},
    ]
    sentinel_hunting.sync_hunt(
        db_conn, hunt_id, hunt_title="BTR Reforged", hunt_description="APT campaign",
        detections=detections, target_sentinel_hunt_id="existing-hunt-guid",
    )

    assert calls["hunts"] == []  # never touched the existing hunt's own metadata
    assert len(calls["links"]) == 1
    assert calls["links"][0][0] == "existing-hunt-guid"  # linked into the target, not a derived id

    row = db_conn.execute("SELECT sentinel_hunt_id, sentinel_sync_error FROM hunts WHERE id = ?",
                          (hunt_id,)).fetchone()
    assert row["sentinel_hunt_id"] == "existing-hunt-guid"
    assert row["sentinel_sync_error"] is None


def test_sync_hunt_falls_back_to_technique_name_when_detection_name_is_null(monkeypatch, db_conn):
    """Confirmed live 2026-09-01: some analytics rows have name=None (an
    upstream gap in orchestrator.py's title parsing, not fixed here), and
    the old fallback to bare technique_id produced Sentinel saved searches
    literally named "T1005"/"T1087.004" with no way to distinguish them.
    technique_name is a real, human-readable value already on every det
    dict -- prefer it over the bare id."""
    import hunts as hunts_module
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "entry-hash-1", title="T")

    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    calls = {"searches": []}

    class _FakeClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def upsert_hunt(self, hunt_id, **kwargs):
            return f"/hunts/{hunt_id}"
        def upsert_saved_search(self, search_id, **kwargs):
            calls["searches"].append(kwargs)
            return f"/savedSearches/{search_id}"
        def link_query_to_hunt(self, *a, **k):
            pass

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _FakeClient)

    detections = [
        {"id": 1, "name": None, "description": "D", "kql_body": "X | take 1",
         "technique_id": "T1005", "technique_name": "Data from Local System"},
    ]
    sentinel_hunting.sync_hunt(
        db_conn, hunt_id, hunt_title="T", hunt_description="D", detections=detections,
    )

    assert calls["searches"][0]["display_name"] == "Data from Local System"


def test_sync_hunt_derives_attack_tactics_for_upsert_hunt(monkeypatch, db_conn):
    import hunts as hunts_module
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "entry-hash-1", title="BTR Reforged")

    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    calls = {"hunts": []}

    class _FakeClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def upsert_hunt(self, hunt_id, **kwargs):
            calls["hunts"].append(kwargs)
            return f"/hunts/{hunt_id}"
        def upsert_saved_search(self, search_id, **kwargs):
            return f"/savedSearches/{search_id}"
        def link_query_to_hunt(self, *a, **k):
            pass

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _FakeClient)

    detections = [
        {"id": 1, "name": "A", "description": "D", "kql_body": "X | take 1",
         "technique_id": "T1053.005", "technique_name": "Scheduled Task"},
    ]
    sentinel_hunting.sync_hunt(
        db_conn, hunt_id, hunt_title="T", hunt_description="D", detections=detections,
    )

    assert calls["hunts"][0]["attack_techniques"] == ["T1053"]
    assert set(calls["hunts"][0]["attack_tactics"]) == {
        "Execution", "Persistence", "PrivilegeEscalation",
    }


def test_sync_hunt_keeps_sentinel_hunt_id_on_partial_failure(monkeypatch, db_conn):
    """upsert_hunt succeeding then a later saved-search/link call failing must
    not discard the real Sentinel hunt id -- that hunt genuinely exists in
    Sentinel by then. Confirmed live 2026-08-31: hunts showing up with 0
    linked queries while our own DB recorded sentinel_hunt_id=None for them."""
    import hunts as hunts_module
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "entry-hash-1", title="T")

    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    class _PartiallyFailingClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def upsert_hunt(self, hunt_id, **kwargs):
            return f"/hunts/{hunt_id}"
        def upsert_saved_search(self, *a, **k):
            raise sentinel_hunting.SentinelHuntingError("400 Bad Request: Invalid tag value")

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _PartiallyFailingClient)

    detections = [
        {"id": 1, "name": "A", "description": "D", "kql_body": "X | take 1",
         "technique_id": "T1053.005", "technique_name": "Scheduled Task"},
    ]
    sentinel_hunting.sync_hunt(
        db_conn, hunt_id, hunt_title="T", hunt_description="D", detections=detections,
    )

    row = db_conn.execute("SELECT sentinel_hunt_id, sentinel_sync_error FROM hunts WHERE id = ?",
                          (hunt_id,)).fetchone()
    assert row["sentinel_hunt_id"] is not None
    assert "400" in row["sentinel_sync_error"]


def test_sync_hunt_one_detection_failure_does_not_abort_the_rest(monkeypatch, db_conn):
    """Regression test: confirmed live 2026-09-01 -- sync_hunt() used to wrap
    the entire per-detection loop in one try/except, so one detection's
    upsert_saved_search()/link_query_to_hunt() failure aborted every
    remaining detection too, even ones that would have succeeded. Real
    symptom: some pipeline-created hunts showed 0 linked queries in
    Sentinel while others showed all of them, depending purely on which
    detection happened to fail first. Each detection must now be isolated:
    a failure on detection #2 must not prevent #1 (already synced) or #3
    (not yet attempted) from being created and linked."""
    import hunts as hunts_module
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "entry-hash-1", title="T")

    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    calls = {"searches": [], "links": []}

    class _SecondDetectionFailsClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def upsert_hunt(self, hunt_id, **kwargs):
            return f"/hunts/{hunt_id}"
        def upsert_saved_search(self, search_id, **kwargs):
            if kwargs.get("display_name") == "Detection B":
                raise sentinel_hunting.SentinelHuntingError("400 Bad Request: Invalid tag value")
            calls["searches"].append(search_id)
            return f"/savedSearches/{search_id}"
        def link_query_to_hunt(self, hunt_id, relation_id, related_resource_id, **kwargs):
            calls["links"].append(relation_id)

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _SecondDetectionFailsClient)

    detections = [
        {"id": 1, "name": "Detection A", "description": "D", "kql_body": "X | take 1",
         "technique_id": "T1053.005", "technique_name": "Scheduled Task"},
        {"id": 2, "name": "Detection B", "description": "D", "kql_body": "Y | take 1",
         "technique_id": "T1059.001", "technique_name": "PowerShell"},
        {"id": 3, "name": "Detection C", "description": "D", "kql_body": "Z | take 1",
         "technique_id": "T1005", "technique_name": "Data from Local System"},
    ]
    sentinel_hunting.sync_hunt(
        db_conn, hunt_id, hunt_title="T", hunt_description="D", detections=detections,
    )

    # Detections 1 and 3 (either side of the failure) both got their saved
    # search created and linked -- the failure on #2 didn't take them out.
    assert len(calls["searches"]) == 2
    assert len(calls["links"]) == 2

    row = db_conn.execute("SELECT sentinel_hunt_id, sentinel_sync_error FROM hunts WHERE id = ?",
                          (hunt_id,)).fetchone()
    assert row["sentinel_hunt_id"] is not None
    assert "1/3" in row["sentinel_sync_error"]
    assert "id=2" in row["sentinel_sync_error"]
    assert "400" in row["sentinel_sync_error"]


def test_upsert_saved_search_truncates_description_tag_to_256_chars():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read()
        return httpx.Response(200, json={"id": "ok"})

    client = _client_with_transport(handler)
    client.upsert_saved_search(
        "search-1", display_name="Name", query="X | take 1",
        description="x" * 400,
    )

    import json as _json
    body = _json.loads(captured["body"])
    tag = next(t for t in body["properties"]["tags"] if t["Name"] == "description")
    assert len(tag["Value"]) == 256


def test_upsert_saved_search_truncates_tactics_tag_to_256_chars():
    """A corrupted technique_name (e.g. an embedded YARA rule -- seen live
    2026-08-31, hunt #44) must not blow past the same ARM tag-value limit
    Description is truncated for."""
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read()
        return httpx.Response(200, json={"id": "ok"})

    client = _client_with_transport(handler)
    client.upsert_saved_search(
        "search-1", display_name="Name", query="X | take 1",
        tactics=["y" * 400],
    )

    import json as _json
    body = _json.loads(captured["body"])
    tag = next(t for t in body["properties"]["tags"] if t["Name"] == "tactics")
    assert len(tag["Value"]) == 256


def test_upsert_saved_search_truncates_techniques_tag_to_256_chars():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read()
        return httpx.Response(200, json={"id": "ok"})

    client = _client_with_transport(handler)
    client.upsert_saved_search(
        "search-1", display_name="Name", query="X | take 1",
        techniques=["T" + "1" * 400],
    )

    import json as _json
    body = _json.loads(captured["body"])
    tag = next(t for t in body["properties"]["tags"] if t["Name"] == "techniques")
    assert len(tag["Value"]) == 256


def test_upsert_saved_search_sends_techniques_tag_comma_joined_no_spaces():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read()
        return httpx.Response(200, json={"id": "ok"})

    client = _client_with_transport(handler)
    client.upsert_saved_search(
        "search-1", display_name="Name", query="X | take 1",
        techniques=["T1053.005", "T1059.001"],
    )

    import json as _json
    body = _json.loads(captured["body"])
    tag = next(t for t in body["properties"]["tags"] if t["Name"] == "techniques")
    assert tag["Value"] == "T1053.005,T1059.001"


def test_sync_hunt_records_error_and_does_not_raise_on_failure(monkeypatch, db_conn):
    import hunts as hunts_module
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "entry-hash-1", title="T")

    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    class _FailingClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def upsert_hunt(self, *a, **k):
            raise sentinel_hunting.SentinelHuntingError("403 Forbidden: RBAC not granted yet")

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _FailingClient)

    # Must not raise -- this mirrors every other Sentinel-backed sweep in
    # this pipeline, which never fails the batch over one bad sync.
    sentinel_hunting.sync_hunt(
        db_conn, hunt_id, hunt_title="T", hunt_description="D", detections=[],
    )

    row = db_conn.execute("SELECT sentinel_hunt_id, sentinel_sync_error FROM hunts WHERE id = ?",
                          (hunt_id,)).fetchone()
    assert row["sentinel_hunt_id"] is None
    assert "403" in row["sentinel_sync_error"]


# --- append_entity_mapping_extends() ---------------------------------------

def test_append_entity_mapping_extends_appends_known_columns():
    kql = (
        "DeviceProcessEvents\n"
        "| where FileName =~ \"sshpass\"\n"
        "| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, "
        "InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath"
    )
    result = sentinel_hunting.append_entity_mapping_extends(kql)

    assert "| extend Account_0_Name = AccountName" in result
    assert "| extend Host_0_HostName = DeviceName" in result
    assert "| extend File_0_Name = InitiatingProcessFileName" in result
    assert "| extend File_0_Directory = InitiatingProcessFolderPath" in result
    assert "| extend Process_0_CommandLine = ProcessCommandLine" in result
    assert "| extend Process_1_CommandLine = InitiatingProcessCommandLine" in result
    assert result.startswith(kql)


def test_append_entity_mapping_extends_returns_unchanged_when_no_known_columns():
    kql = "CustomTable_CL | where Foo == \"bar\" | project TimeGenerated, Foo"
    assert sentinel_hunting.append_entity_mapping_extends(kql) == kql


def test_append_entity_mapping_extends_handles_empty_body():
    assert sentinel_hunting.append_entity_mapping_extends("") == ""
    assert sentinel_hunting.append_entity_mapping_extends("   ") == "   "


def test_append_entity_mapping_extends_only_matches_whole_words():
    # "AccountNameSuffix" must not trigger an AccountName mapping -- that
    # column doesn't exist, and the extend would break the query at run time.
    kql = "SomeTable | project TimeGenerated, AccountNameSuffix"
    assert sentinel_hunting.append_entity_mapping_extends(kql) == kql


def test_append_entity_mapping_extends_maps_bare_file_columns_too():
    # The file an event is actually ABOUT (DeviceFileEvents' own
    # FileName/FolderPath) is a distinct File entity instance from the
    # initiating process's own file -- gets its own, second index.
    kql = "DeviceFileEvents | project TimeGenerated, FileName, FolderPath"
    result = sentinel_hunting.append_entity_mapping_extends(kql)
    assert "| extend File_0_Name = FileName" in result
    assert "| extend File_0_Directory = FolderPath" in result


def test_append_entity_mapping_extends_skips_column_dropped_by_later_summarize():
    # FileName/FolderPath are only used in the `where` filter -- the final
    # `summarize` doesn't carry them into the output, so an extend against
    # them here would fail live with "column not found." Regression test
    # for the exact class of bug confirmed live 2026-09-02.
    kql = (
        "DeviceFileEvents\n"
        "| where FileName =~ \"evil.exe\" and FolderPath has \"temp\"\n"
        "| summarize count() by DeviceName"
    )
    result = sentinel_hunting.append_entity_mapping_extends(kql)
    assert "File_0_Name" not in result
    assert "File_0_Directory" not in result
    assert "| extend Host_0_HostName = DeviceName" in result


def test_append_entity_mapping_extends_skips_column_dropped_by_later_project():
    kql = (
        "DeviceProcessEvents\n"
        "| where InitiatingProcessFileName =~ \"cmd.exe\"\n"
        "| project TimeGenerated, DeviceName, AccountName"
    )
    result = sentinel_hunting.append_entity_mapping_extends(kql)
    assert "File_0_Name" not in result
    assert "| extend Account_0_Name = AccountName" in result
    assert "| extend Host_0_HostName = DeviceName" in result


def test_append_entity_mapping_extends_project_rename_is_not_treated_as_narrowing():
    # project-rename keeps every column, just renames one -- must not be
    # mistaken for a plain `project` that drops unlisted columns.
    kql = (
        "DeviceProcessEvents\n"
        "| where AccountName == \"bob\"\n"
        "| project-rename User = AccountName"
    )
    result = sentinel_hunting.append_entity_mapping_extends(kql)
    assert "| extend Account_0_Name = AccountName" in result


# --- deploy_all_hunts() -----------------------------------------------

def _seed_strategy(conn, technique_id="T1053.005", technique_name="Scheduled Task"):
    row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, technique_name, "Detect it", []),
    ).fetchone()
    conn.commit()
    return row["id"]


def _seed_eligible_analytic(conn, strategy_id, hunt_id, name="Detection"):
    row = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, name, "
        " hunt_id, static_gate_verdict, backtest_disposition) "
        "VALUES (?, ?, ?, ?, ?, 'pass', 'clean') RETURNING id",
        (strategy_id, "hash-" + str(strategy_id), "X | take 1", name, hunt_id),
    ).fetchone()
    conn.commit()
    return row["id"]


def test_deploy_all_hunts_is_a_noop_when_disabled(monkeypatch, db_conn):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)

    def _boom(*a, **k):
        raise AssertionError("must not construct a client when sync is disabled")
    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _boom)

    result = sentinel_hunting.deploy_all_hunts(db_conn)
    assert result == {"enabled": False, "total": 0, "succeeded": 0, "failed": []}


def test_deploy_all_hunts_deploys_never_synced_hunt(monkeypatch, db_conn):
    import hunts as hunts_module
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "entry-hash-1", title="Never Synced")
    _seed_eligible_analytic(db_conn, strategy_id, hunt_id)

    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    class _FakeClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def upsert_hunt(self, hunt_id, **kwargs): return f"/hunts/{hunt_id}"
        def upsert_saved_search(self, search_id, **kwargs): return f"/savedSearches/{search_id}"
        def link_query_to_hunt(self, *a, **k): pass

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _FakeClient)

    result = sentinel_hunting.deploy_all_hunts(db_conn)
    assert result == {"enabled": True, "total": 1, "succeeded": 1, "failed": []}

    row = db_conn.execute("SELECT sentinel_hunt_id FROM hunts WHERE id = ?", (hunt_id,)).fetchone()
    assert row["sentinel_hunt_id"] is not None


def test_deploy_all_hunts_skips_hunt_already_up_to_date(monkeypatch, db_conn):
    import hunts as hunts_module
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "entry-hash-1", title="Up To Date")
    hunts_module.mark_hunt_synced(db_conn, hunt_id, sentinel_hunt_id="sentinel-guid-1")

    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    def _boom(*a, **k):
        raise AssertionError("an already-synced, unchanged hunt must not be touched")
    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _boom)

    result = sentinel_hunting.deploy_all_hunts(db_conn)
    assert result == {"enabled": True, "total": 0, "succeeded": 0, "failed": []}


def test_deploy_all_hunts_reports_hunt_with_no_eligible_detections_as_failed(monkeypatch, db_conn):
    import hunts as hunts_module
    hunts_module.get_or_create_hunt(db_conn, "entry-hash-1", title="Nothing Eligible Yet")

    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    def _boom(*a, **k):
        raise AssertionError("must not attempt an ARM call for a hunt with no eligible detections")
    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _boom)

    result = sentinel_hunting.deploy_all_hunts(db_conn)
    assert result["total"] == 1
    assert result["succeeded"] == 0
    assert len(result["failed"]) == 1
    assert "static gate" in result["failed"][0]["reason"] or "backtest" in result["failed"][0]["reason"]


def test_deploy_all_hunts_one_hunt_failure_does_not_abort_the_batch(monkeypatch, db_conn):
    """Per-hunt isolation, same discipline sync_hunt() already uses for one
    detection's failure inside a single hunt -- one hunt's ARM failure must
    not stop the rest of the batch from being attempted."""
    import hunts as hunts_module
    strategy_a = _seed_strategy(db_conn, "T1053.005", "Scheduled Task")
    strategy_b = _seed_strategy(db_conn, "T1059.001", "PowerShell")
    failing_hunt = hunts_module.get_or_create_hunt(db_conn, "entry-hash-fail", title="Will Fail")
    ok_hunt = hunts_module.get_or_create_hunt(db_conn, "entry-hash-ok", title="Will Succeed")
    _seed_eligible_analytic(db_conn, strategy_a, failing_hunt)
    _seed_eligible_analytic(db_conn, strategy_b, ok_hunt)

    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    def _client_factory():
        # arm_safe_id("hunt", str(hunt_id)) is deterministic per hunt_id, so
        # capture which real hunt each fake ARM id belongs to up front.
        failing_arm_id = sentinel_hunting.arm_safe_id("hunt", str(failing_hunt))

        class _MixedClient:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def upsert_hunt(self, hunt_id, **kwargs):
                if hunt_id == failing_arm_id:
                    raise sentinel_hunting.SentinelHuntingError("500 Internal Server Error")
                return f"/hunts/{hunt_id}"
            def upsert_saved_search(self, search_id, **kwargs):
                return f"/savedSearches/{search_id}"
            def link_query_to_hunt(self, *a, **k):
                pass
        return _MixedClient

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _client_factory())

    result = sentinel_hunting.deploy_all_hunts(db_conn)
    assert result["total"] == 2
    assert result["succeeded"] == 1
    assert len(result["failed"]) == 1
    assert result["failed"][0]["hunt_id"] == failing_hunt

    ok_row = db_conn.execute("SELECT sentinel_hunt_id FROM hunts WHERE id = ?", (ok_hunt,)).fetchone()
    assert ok_row["sentinel_hunt_id"] is not None
    failing_row = db_conn.execute("SELECT sentinel_sync_error FROM hunts WHERE id = ?",
                                  (failing_hunt,)).fetchone()
    assert "500" in failing_row["sentinel_sync_error"]


# --- Auto-deploy default target + rollover (2026-09-04, post-round-6) -----
# User ask: an admin-configurable default Sentinel Hunt for the 'auto'
# mode's automatic push, with 975-query rollover to the next "In The News:
# Hunts vN" when the configured target fills up. See orchestrator.py's
# auto-sync block for how resolve_auto_deploy_target() feeds sync_hunt().

import hunt_sync_settings


def _seed_sentinel_hunt(conn, sentinel_hunt_id, display_name, query_count=0):
    conn.execute(
        "INSERT INTO sentinel_hunts (sentinel_hunt_id, display_name, query_count) "
        "VALUES (?, ?, ?)",
        (sentinel_hunt_id, display_name, query_count),
    )
    conn.commit()


def test_resolve_auto_deploy_target_returns_none_when_unset(db_conn):
    assert sentinel_hunting.resolve_auto_deploy_target(db_conn) is None


def test_resolve_auto_deploy_target_returns_configured_target_when_under_threshold(db_conn):
    hunt_sync_settings.set_auto_deploy_target(db_conn, "target-guid-1", "tester")
    _seed_sentinel_hunt(db_conn, "target-guid-1", "In The News: Hunts v2", query_count=305)

    assert sentinel_hunting.resolve_auto_deploy_target(db_conn) == "target-guid-1"


def test_resolve_auto_deploy_target_returns_configured_target_when_no_local_inventory_row(db_conn):
    """The configured target hasn't shown up in sentinel_hunts yet (e.g.
    sentinel_hunt_sync.py hasn't run since it was set) -- must pass it
    through as-is rather than treating "unknown" as "over threshold"."""
    hunt_sync_settings.set_auto_deploy_target(db_conn, "brand-new-guid", "tester")

    assert sentinel_hunting.resolve_auto_deploy_target(db_conn) == "brand-new-guid"


def test_resolve_auto_deploy_target_rotates_when_at_threshold(monkeypatch, db_conn):
    hunt_sync_settings.set_auto_deploy_target(db_conn, "full-target-guid", "tester")
    _seed_sentinel_hunt(db_conn, "full-target-guid", "In The News: Hunts v2", query_count=975)

    calls = {"hunts": []}

    class _FakeClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def upsert_hunt(self, hunt_id, **kwargs):
            calls["hunts"].append((hunt_id, kwargs))
            return f"/hunts/{hunt_id}"

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _FakeClient)

    result = sentinel_hunting.resolve_auto_deploy_target(db_conn)

    assert len(calls["hunts"]) == 1
    expected_id = sentinel_hunting.arm_safe_id("auto-deploy-target", "In The News: Hunts v3")
    assert result == expected_id
    assert calls["hunts"][0][0] == expected_id
    assert calls["hunts"][0][1]["display_name"] == "In The News: Hunts v3"

    settings = hunt_sync_settings.get_settings(db_conn)
    assert settings["auto_deploy_target_sentinel_hunt_id"] == expected_id
    assert settings["updated_by"] == "system:rollover"


def test_resolve_auto_deploy_target_above_threshold_also_rotates(monkeypatch, db_conn):
    """query_count already past 975 (not just exactly at it, e.g. the next
    orchestrator run after the threshold was first crossed) must still
    trigger a rollover, not just an exact-equality match."""
    hunt_sync_settings.set_auto_deploy_target(db_conn, "full-target-guid", "tester")
    _seed_sentinel_hunt(db_conn, "full-target-guid", "In The News: Hunts v2", query_count=990)

    class _FakeClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def upsert_hunt(self, hunt_id, **kwargs):
            return f"/hunts/{hunt_id}"

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _FakeClient)

    result = sentinel_hunting.resolve_auto_deploy_target(db_conn)
    assert result != "full-target-guid"


def test_next_auto_deploy_title_treats_bare_title_as_v1(monkeypatch, db_conn):
    """The real, pre-existing "In The News: Hunts" (no " vN" suffix) is v1
    -- confirmed live 2026-09-01 (974 queries before someone manually
    created v2). Only a bare or versioned title matching that exact base
    counts; an unrelated hunt name must never influence the next number."""
    hunt_sync_settings.set_auto_deploy_target(db_conn, "full-target-guid", "tester")
    _seed_sentinel_hunt(db_conn, "full-target-guid", "In The News: Hunts", query_count=974)
    _seed_sentinel_hunt(db_conn, "unrelated-guid", "Some Analyst's Own Hunt", query_count=5)

    calls = {"hunts": []}

    class _FakeClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def upsert_hunt(self, hunt_id, **kwargs):
            calls["hunts"].append(kwargs["display_name"])
            return f"/hunts/{hunt_id}"

    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _FakeClient)

    # 974 < 975 so this alone wouldn't roll over -- bump it to force one,
    # isolating this test's actual claim (naming), not the threshold math.
    db_conn.execute("UPDATE sentinel_hunts SET query_count = 975 WHERE sentinel_hunt_id = ?",
                    ("full-target-guid",))
    db_conn.commit()

    sentinel_hunting.resolve_auto_deploy_target(db_conn)

    assert calls["hunts"] == ["In The News: Hunts v2"]


def test_resolve_auto_deploy_target_falls_back_to_stale_target_on_rollover_failure(monkeypatch, db_conn):
    """Never raises -- a rollover failure (ARM error, client construction)
    must fall back to the original (over-threshold but still valid)
    target, matching sync_hunt()'s own never-raise discipline, and must
    not have persisted any partial change to hunt_sync_settings."""
    hunt_sync_settings.set_auto_deploy_target(db_conn, "full-target-guid", "tester")
    _seed_sentinel_hunt(db_conn, "full-target-guid", "In The News: Hunts v2", query_count=1000)

    def _boom(*a, **k):
        raise sentinel_hunting.SentinelHuntingError("simulated ARM failure")
    monkeypatch.setattr(sentinel_hunting, "SentinelHuntingClient", _boom)

    result = sentinel_hunting.resolve_auto_deploy_target(db_conn)

    assert result == "full-target-guid"
    settings = hunt_sync_settings.get_settings(db_conn)
    assert settings["auto_deploy_target_sentinel_hunt_id"] == "full-target-guid"
