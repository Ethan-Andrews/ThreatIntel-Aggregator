"""Tests for sentinel_analytics_rules_tuning.py -- the apply/dismiss
orchestration behind POST /api/sentinel-analytics-rules/{id}/tuning-
suggestion/{apply,dismiss}. HTTP to Sentinel is mocked via
httpx.MockTransport (same technique as test_sentinel_hunt_tuning.py), and
Apply exercises the real read-modify-write path (a GET before the PUT)."""

import json
import sys
import types
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import sentinel_analytics_rules as rules_mod
import sentinel_analytics_rules_tuning as tuning_mod
from sentinel_analytics_rules_sync import SentinelAnalyticsRulesReadClient


class _FakeCredential:
    def get_token(self, scope):
        return types.SimpleNamespace(token="fake-arm-token", expires_on=9999999999)


def _client_factory(handler=None):
    def factory():
        client = SentinelAnalyticsRulesReadClient(
            subscription_id="sub-1", resource_group="rg-1", workspace_name="ws-1",
            credential=_FakeCredential(),
        )
        client._client = httpx.Client(
            transport=httpx.MockTransport(handler or (lambda req: httpx.Response(200, json={})))
        )
        return client
    return factory


def _seed_rule(conn, sentinel_rule_id="rule-1", display_name="Rule 1",
               kql_body="T | take 1", tune_history=None):
    row = conn.execute(
        "INSERT INTO sentinel_analytics_rules "
        "(sentinel_rule_id, display_name, kql_body, tune_history) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (sentinel_rule_id, display_name, kql_body,
         json.dumps(tune_history) if tune_history is not None else None),
    ).fetchone()
    conn.commit()
    return row["id"]


_TUNE_HISTORY = {"disposition": "tuned", "final_body": "T | take 1 | where X != @\"bob\""}

_LIVE_RULE_BODY = {
    "id": "/subscriptions/sub-1/.../alertRules/rule-1",
    "name": "rule-1",
    "type": "Microsoft.SecurityInsights/alertRules",
    "kind": "Scheduled",
    "etag": "\"an-etag\"",
    "properties": {
        "displayName": "Rule 1",
        "severity": "High",
        "enabled": True,
        "query": "T | take 1",
        "queryFrequency": "PT1H",
        "queryPeriod": "PT1H",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionEnabled": False,
        "suppressionDuration": "PT5H",
    },
}


def test_apply_rule_tune_suggestion_missing_rule(db_conn):
    result = tuning_mod.apply_rule_tune_suggestion(db_conn, 999999)
    assert result == {"rule_id": 999999, "success": False, "reason": "rule not found"}


def test_apply_rule_tune_suggestion_no_suggestion_available(db_conn):
    rule_id = _seed_rule(db_conn)  # no tune_history at all
    result = tuning_mod.apply_rule_tune_suggestion(db_conn, rule_id)
    assert result["success"] is False
    assert "no tuning suggestion" in result["reason"]


def test_apply_rule_tune_suggestion_sync_disabled(db_conn, monkeypatch):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)
    rule_id = _seed_rule(db_conn, tune_history=_TUNE_HISTORY)

    result = tuning_mod.apply_rule_tune_suggestion(db_conn, rule_id)
    assert result["success"] is False
    assert "Sentinel Hunting sync is off" in result["reason"]


def test_apply_rule_tune_suggestion_success_reads_then_writes_only_query(db_conn, monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    rule_id = _seed_rule(
        db_conn, sentinel_rule_id="real-rule-id", tune_history=_TUNE_HISTORY,
    )

    calls = []
    captured = {}

    def handler(request):
        calls.append(request.method)
        if request.method == "GET":
            return httpx.Response(200, json=_LIVE_RULE_BODY)
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=captured["body"])

    result = tuning_mod.apply_rule_tune_suggestion(
        db_conn, rule_id, performed_by="alice@example.com",
        client_factory=_client_factory(handler),
    )

    assert result == {"rule_id": rule_id, "success": True, "reason": None}
    assert calls == ["GET", "PUT"]
    assert "real-rule-id" in captured["url"]
    assert captured["body"]["properties"]["query"] == "T | take 1 | where X != @\"bob\""
    # Every field this app doesn't store locally must survive untouched.
    assert captured["body"]["properties"]["queryFrequency"] == "PT1H"
    assert captured["body"]["properties"]["triggerThreshold"] == 0
    assert "id" not in captured["body"] and "name" not in captured["body"]

    detail = rules_mod.get_rule_detail(db_conn, rule_id)
    assert detail["tuning_suggestion"]["action"] == "applied"
    assert detail["tuning_suggestion"]["pending"] is False
    assert detail["tuning_suggestion"]["performed_by"] == "alice@example.com"


def test_apply_rule_tune_suggestion_sentinel_failure_recorded_as_apply_failed(db_conn, monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    rule_id = _seed_rule(db_conn, tune_history=_TUNE_HISTORY)

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json=_LIVE_RULE_BODY)
        return httpx.Response(400, text="BadRequest")

    result = tuning_mod.apply_rule_tune_suggestion(
        db_conn, rule_id, client_factory=_client_factory(handler),
    )
    assert result["success"] is False

    detail = rules_mod.get_rule_detail(db_conn, rule_id)
    assert detail["tuning_suggestion"]["action"] == "apply_failed"
    assert detail["tuning_suggestion"]["pending"] is True


def test_dismiss_rule_tune_suggestion(db_conn):
    rule_id = _seed_rule(db_conn, tune_history=_TUNE_HISTORY)

    result = tuning_mod.dismiss_rule_tune_suggestion(db_conn, rule_id, performed_by="bob@example.com")
    assert result == {"rule_id": rule_id, "success": True, "reason": None}

    detail = rules_mod.get_rule_detail(db_conn, rule_id)
    assert detail["tuning_suggestion"]["action"] == "dismissed"
    assert detail["tuning_suggestion"]["pending"] is False
    assert detail["tuning_suggestion"]["performed_by"] == "bob@example.com"


def test_dismiss_rule_tune_suggestion_no_suggestion_available(db_conn):
    rule_id = _seed_rule(db_conn)
    result = tuning_mod.dismiss_rule_tune_suggestion(db_conn, rule_id)
    assert result["success"] is False


def test_get_rule_detail_tuning_suggestion_is_none_when_never_tuned(db_conn):
    rule_id = _seed_rule(db_conn)
    detail = rules_mod.get_rule_detail(db_conn, rule_id)
    assert detail["tuning_suggestion"] is None
