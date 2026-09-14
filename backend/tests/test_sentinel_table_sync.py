"""Tests for sentinel_table_sync.py -- the read-only ARM client that caches
the real Sentinel/MDE table catalog for static_gate.py's table-recognition
check. HTTP is mocked via httpx.MockTransport, same convention as
test_sentinel_hunt_sync.py."""

import sys
import types
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import sentinel_table_sync

_RealSentinelTableReadClient = sentinel_table_sync.SentinelTableReadClient


class _FakeCredential:
    def get_token(self, scope):
        return types.SimpleNamespace(token="fake-arm-token", expires_on=9999999999)


def _client_with_transport(handler, **kwargs):
    client = _RealSentinelTableReadClient(
        subscription_id="sub-1", resource_group="rg-1", workspace_name="ws-1",
        credential=_FakeCredential(), **kwargs,
    )
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


# --- is_enabled() ------------------------------------------------------------

def test_is_enabled_false_by_default(monkeypatch):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)
    assert sentinel_table_sync.is_enabled() is False


def test_is_enabled_true_when_set(monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    assert sentinel_table_sync.is_enabled() is True


# --- SentinelTableReadClient config validation -------------------------------

def test_client_requires_subscription_resource_group_and_workspace(monkeypatch):
    for var in ("AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP", "SENTINEL_WORKSPACE_NAME"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(sentinel_table_sync.SentinelTableSyncError, match="AZURE_SUBSCRIPTION_ID"):
        sentinel_table_sync.SentinelTableReadClient(credential=_FakeCredential())


# --- list_tables() / pagination ----------------------------------------------

def test_list_tables_returns_the_value_array():
    def handler(request):
        assert request.url.path.endswith("/tables")
        return httpx.Response(200, json={"value": [
            {"name": "AzureActivity", "properties": {}},
            {"name": "CustomTable_CL", "properties": {}},
        ]})

    client = _client_with_transport(handler)
    tables = client.list_tables()
    assert [t["name"] for t in tables] == ["AzureActivity", "CustomTable_CL"]


def test_list_tables_follows_next_link():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if len(calls) == 1:
            return httpx.Response(200, json={
                "value": [{"name": "AzureActivity"}],
                "nextLink": "https://management.azure.com/next-page",
            })
        return httpx.Response(200, json={"value": [{"name": "SecurityEvent"}]})

    client = _client_with_transport(handler)
    tables = client.list_tables()
    assert [t["name"] for t in tables] == ["AzureActivity", "SecurityEvent"]
    assert len(calls) == 2


def test_list_tables_raises_on_error_response():
    def handler(request):
        return httpx.Response(403, text="Forbidden")

    client = _client_with_transport(handler)
    with pytest.raises(sentinel_table_sync.SentinelTableSyncError, match="403"):
        client.list_tables()


# --- get_cached_tables() ------------------------------------------------------

def test_get_cached_tables_empty_when_never_synced(db_conn):
    assert sentinel_table_sync.get_cached_tables(db_conn) == set()


def test_get_cached_tables_returns_synced_names(db_conn):
    db_conn.execute("INSERT INTO sentinel_workspace_tables (name) VALUES (?)", ("AzureActivity",))
    db_conn.commit()
    assert sentinel_table_sync.get_cached_tables(db_conn) == {"AzureActivity"}


# --- sync_all() ---------------------------------------------------------------

def test_sync_all_disabled_is_noop(monkeypatch, db_conn):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)
    result = sentinel_table_sync.sync_all(db_conn)
    assert result == {"enabled": False, "tables_synced": 0, "error": None}
    assert sentinel_table_sync.get_cached_tables(db_conn) == set()


def test_sync_all_upserts_every_table_name(monkeypatch, db_conn):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")

    def handler(request):
        return httpx.Response(200, json={"value": [
            {"name": "AzureActivity"}, {"name": "SecurityEvent"}, {"name": "DeviceProcessEvents"},
        ]})

    monkeypatch.setattr(
        sentinel_table_sync, "SentinelTableReadClient",
        lambda *a, **kw: _client_with_transport(handler),
    )

    result = sentinel_table_sync.sync_all(db_conn)
    assert result == {"enabled": True, "tables_synced": 3, "error": None}
    assert sentinel_table_sync.get_cached_tables(db_conn) == {
        "AzureActivity", "SecurityEvent", "DeviceProcessEvents",
    }


def test_sync_all_reupsert_does_not_duplicate(monkeypatch, db_conn):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")

    def handler(request):
        return httpx.Response(200, json={"value": [{"name": "AzureActivity"}]})

    monkeypatch.setattr(
        sentinel_table_sync, "SentinelTableReadClient",
        lambda *a, **kw: _client_with_transport(handler),
    )

    sentinel_table_sync.sync_all(db_conn)
    sentinel_table_sync.sync_all(db_conn)

    count = db_conn.execute("SELECT COUNT(*) FROM sentinel_workspace_tables").fetchone()[0]
    assert count == 1


# --- get_tables_for_gate() ----------------------------------------------------

def test_get_tables_for_gate_auto_syncs_when_never_synced(monkeypatch, db_conn):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")

    def handler(request):
        return httpx.Response(200, json={"value": [{"name": "AzureActivity"}]})

    monkeypatch.setattr(
        sentinel_table_sync, "SentinelTableReadClient",
        lambda *a, **kw: _client_with_transport(handler),
    )

    assert sentinel_table_sync.get_tables_for_gate(db_conn) == {"AzureActivity"}


def test_get_tables_for_gate_does_not_resync_once_populated(monkeypatch, db_conn):
    db_conn.execute("INSERT INTO sentinel_workspace_tables (name) VALUES (?)", ("SecurityEvent",))
    db_conn.commit()

    def _should_not_be_called(*a, **kw):
        raise AssertionError("sync_all should not run once the cache has data")

    monkeypatch.setattr(sentinel_table_sync, "SentinelTableReadClient", _should_not_be_called)
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    assert sentinel_table_sync.get_tables_for_gate(db_conn) == {"SecurityEvent"}


def test_get_tables_for_gate_stays_a_cheap_noop_when_disabled(monkeypatch, db_conn):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)
    assert sentinel_table_sync.get_tables_for_gate(db_conn) == set()


def test_sync_all_returns_error_on_client_failure(monkeypatch, db_conn):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    def _raise(*a, **kw):
        raise sentinel_table_sync.SentinelTableSyncError("missing required config")

    monkeypatch.setattr(sentinel_table_sync, "SentinelTableReadClient", _raise)

    result = sentinel_table_sync.sync_all(db_conn)
    assert result["enabled"] is True
    assert result["tables_synced"] == 0
    assert "missing required config" in result["error"]
