"""Tests for sentinel_analytics_rules_sync.py -- the read-only ARM client
that pulls Sentinel's actual Analytics Rules (Microsoft.SecurityInsights/
alertRules) into sentinel_analytics_rules. HTTP mocked via
httpx.MockTransport, same convention as test_sentinel_hunt_sync.py."""

import json
import sys
import types
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import sentinel_analytics_rules_sync as sync_mod

_RealClient = sync_mod.SentinelAnalyticsRulesReadClient


class _FakeCredential:
    def get_token(self, scope):
        return types.SimpleNamespace(token="fake-arm-token", expires_on=9999999999)


def _client_with_transport(handler, **kwargs):
    client = _RealClient(
        subscription_id="sub-1", resource_group="rg-1", workspace_name="ws-1",
        credential=_FakeCredential(), **kwargs,
    )
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


SCHEDULED_RULE = {
    "id": "/subscriptions/sub-1/.../alertRules/rule-1",
    "name": "rule-1",
    "type": "Microsoft.SecurityInsights/alertRules",
    "kind": "Scheduled",
    "properties": {
        "displayName": "Suspicious PowerShell Download",
        "description": "Detects PowerShell downloading and executing content.",
        "severity": "High",
        "enabled": True,
        "query": "DeviceProcessEvents | where ProcessCommandLine has \"DownloadString\"",
        "tactics": ["Execution", "DefenseEvasion"],
        "techniques": ["T1059.001"],
    },
}

FUSION_RULE = {
    "id": "/subscriptions/sub-1/.../alertRules/fusion-1",
    "name": "fusion-1",
    "type": "Microsoft.SecurityInsights/alertRules",
    "kind": "Fusion",
    "properties": {"displayName": "Advanced Multistage Attack Detection", "enabled": False},
}


def test_is_enabled_false_by_default(monkeypatch):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)
    assert sync_mod.is_enabled() is False


def test_is_enabled_true_when_set(monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    assert sync_mod.is_enabled() is True


def test_client_requires_subscription_resource_group_and_workspace(monkeypatch):
    for var in ("AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP", "SENTINEL_WORKSPACE_NAME"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(sync_mod.SentinelAnalyticsRulesSyncError, match="AZURE_SUBSCRIPTION_ID"):
        sync_mod.SentinelAnalyticsRulesReadClient(credential=_FakeCredential())


def test_list_alert_rules_follows_next_link():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if "nextpage" not in str(request.url):
            return httpx.Response(200, json={
                "value": [SCHEDULED_RULE],
                "nextLink": "https://management.azure.com/nextpage?api-version=2023-12-01-preview",
            })
        return httpx.Response(200, json={"value": [FUSION_RULE]})

    client = _client_with_transport(handler)
    rules = client.list_alert_rules()

    assert len(rules) == 2
    assert len(calls) == 2
    assert "alertRules" in calls[0]
    assert "api-version=2023-12-01-preview" in calls[0]


def test_list_alert_rules_raises_on_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="Forbidden")

    client = _client_with_transport(handler)
    with pytest.raises(sync_mod.SentinelAnalyticsRulesSyncError, match="403"):
        client.list_alert_rules()


# --- sync_all() --------------------------------------------------------------

def test_sync_all_is_a_noop_when_disabled(monkeypatch, db_conn):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)
    result = sync_mod.sync_all(db_conn)
    assert result == {"enabled": False, "rules_synced": 0, "skipped_kinds": 0, "errors": []}


def test_sync_all_upserts_scheduled_rules_and_skips_other_kinds(monkeypatch, db_conn):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": [SCHEDULED_RULE, FUSION_RULE]})

    monkeypatch.setattr(
        sync_mod, "SentinelAnalyticsRulesReadClient",
        lambda *a, **k: _client_with_transport(handler),
    )

    result = sync_mod.sync_all(db_conn)
    assert result["enabled"] is True
    assert result["rules_synced"] == 1
    assert result["skipped_kinds"] == 1
    assert result["errors"] == []

    row = db_conn.execute(
        "SELECT display_name, kql_body, severity, enabled, tactics, techniques "
        "FROM sentinel_analytics_rules WHERE sentinel_rule_id = ?", ("rule-1",),
    ).fetchone()
    assert row["display_name"] == "Suspicious PowerShell Download"
    assert "DownloadString" in row["kql_body"]
    assert row["severity"] == "High"
    assert row["enabled"] is True

    # The Fusion rule (no `query` property at all) must not have been stored.
    fusion_row = db_conn.execute(
        "SELECT id FROM sentinel_analytics_rules WHERE sentinel_rule_id = ?", ("fusion-1",),
    ).fetchone()
    assert fusion_row is None


def test_sync_all_upsert_is_idempotent(monkeypatch, db_conn):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": [SCHEDULED_RULE]})

    monkeypatch.setattr(
        sync_mod, "SentinelAnalyticsRulesReadClient",
        lambda *a, **k: _client_with_transport(handler),
    )

    sync_mod.sync_all(db_conn)
    sync_mod.sync_all(db_conn)

    count = db_conn.execute(
        "SELECT COUNT(*) FROM sentinel_analytics_rules WHERE sentinel_rule_id = ?", ("rule-1",),
    ).fetchone()[0]
    assert count == 1


# --- get_alert_rule() / update_alert_rule_query() ---------------------------

def test_get_alert_rule_returns_full_body():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert "alertRules/rule-1" in str(request.url)
        return httpx.Response(200, json=SCHEDULED_RULE)

    client = _client_with_transport(handler)
    rule = client.get_alert_rule("rule-1")
    assert rule["kind"] == "Scheduled"
    assert rule["properties"]["displayName"] == "Suspicious PowerShell Download"


def test_get_alert_rule_raises_on_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="Not Found")

    client = _client_with_transport(handler)
    with pytest.raises(sync_mod.SentinelAnalyticsRulesSyncError, match="404"):
        client.get_alert_rule("rule-1")


def test_update_alert_rule_query_reads_then_writes_mutating_only_query():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "GET":
            body = dict(SCHEDULED_RULE)
            body["etag"] = "\"an-etag\""
            return httpx.Response(200, json=body)
        assert request.method == "PUT"
        sent = json.loads(request.content)
        # id/name/type/systemData must never be sent back on the PUT.
        assert "id" not in sent and "name" not in sent and "type" not in sent
        assert sent["kind"] == "Scheduled"
        assert sent["etag"] == "\"an-etag\""
        assert sent["properties"]["query"] == "DeviceProcessEvents | where 1 == 0"
        # Every other property from the live GET must be carried through
        # untouched -- e.g. severity/tactics/techniques, none of which this
        # app stores enough of locally to safely reconstruct.
        assert sent["properties"]["severity"] == "High"
        assert sent["properties"]["tactics"] == ["Execution", "DefenseEvasion"]
        return httpx.Response(200, json=sent)

    client = _client_with_transport(handler)
    result = client.update_alert_rule_query("rule-1", "DeviceProcessEvents | where 1 == 0")
    assert calls == ["GET", "PUT"]
    assert result["properties"]["query"] == "DeviceProcessEvents | where 1 == 0"


def test_update_alert_rule_query_rejects_non_scheduled_kind():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=FUSION_RULE)

    client = _client_with_transport(handler)
    with pytest.raises(sync_mod.SentinelAnalyticsRulesSyncError, match="not a rule this app can tune"):
        client.update_alert_rule_query("fusion-1", "T | take 1")


def test_update_alert_rule_query_raises_on_put_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=SCHEDULED_RULE)
        return httpx.Response(400, text="BadRequest")

    client = _client_with_transport(handler)
    with pytest.raises(sync_mod.SentinelAnalyticsRulesSyncError, match="400"):
        client.update_alert_rule_query("rule-1", "T | take 1")


def test_sync_all_records_error_and_does_not_raise_on_failure(monkeypatch, db_conn):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")

    def _boom(*a, **k):
        raise sync_mod.SentinelAnalyticsRulesSyncError("ARM 403 Forbidden")
    monkeypatch.setattr(sync_mod, "SentinelAnalyticsRulesReadClient", _boom)

    result = sync_mod.sync_all(db_conn)
    assert result["enabled"] is True
    assert result["rules_synced"] == 0
    assert any("403" in e for e in result["errors"])
