"""Tests for sentinel_hunt_tuning.py -- the apply/dismiss orchestration
behind POST /api/sentinel-hunts/queries/{id}/tuning-suggestion/{apply,
dismiss}. HTTP to Sentinel is mocked via httpx.MockTransport (same
technique as test_sentinel_hunting.py/test_tuning_suggestions.py) so this
runs without real Azure credentials."""

import json
import sys
import types
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import sentinel_hunting
import sentinel_hunt_queries
import sentinel_hunt_tuning


class _FakeCredential:
    def get_token(self, scope):
        return types.SimpleNamespace(token="fake-arm-token", expires_on=9999999999)


def _client_factory(handler=None):
    def factory():
        client = sentinel_hunting.SentinelHuntingClient(
            subscription_id="sub-1", resource_group="rg-1", workspace_name="ws-1",
            credential=_FakeCredential(),
        )
        client._client = httpx.Client(
            transport=httpx.MockTransport(handler or (lambda req: httpx.Response(200, json={})))
        )
        return client
    return factory


def _seed_hunt(conn, sentinel_hunt_id="hunt-1", display_name="Test Hunt"):
    row = conn.execute(
        "INSERT INTO sentinel_hunts (sentinel_hunt_id, display_name, query_count) "
        "VALUES (?, ?, ?) RETURNING id",
        (sentinel_hunt_id, display_name, 1),
    ).fetchone()
    conn.commit()
    return row["id"]


def _seed_query(conn, hunt_id, sentinel_saved_search_id="q-1", display_name="Query 1",
                kql_body="T | take 1", tune_history=None, tags=None):
    row = conn.execute(
        "INSERT INTO sentinel_hunt_queries "
        "(hunt_id, sentinel_saved_search_id, display_name, kql_body, description, "
        " tags, tune_history) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
        (hunt_id, sentinel_saved_search_id, display_name, kql_body, "desc",
         json.dumps(tags or []), json.dumps(tune_history) if tune_history is not None else None),
    ).fetchone()
    conn.commit()
    return row["id"]


_TUNE_HISTORY = {"disposition": "tuned", "final_body": "T | take 1 | where X != @\"bob\""}


def test_apply_query_tune_suggestion_missing_query(db_conn):
    result = sentinel_hunt_tuning.apply_query_tune_suggestion(db_conn, 999999)
    assert result == {"query_id": 999999, "success": False, "reason": "query not found"}


def test_apply_query_tune_suggestion_no_suggestion_available(db_conn):
    hunt_id = _seed_hunt(db_conn)
    query_id = _seed_query(db_conn, hunt_id)  # no tune_history at all
    result = sentinel_hunt_tuning.apply_query_tune_suggestion(db_conn, query_id)
    assert result["success"] is False
    assert "no tuning suggestion" in result["reason"]


def test_apply_query_tune_suggestion_sync_disabled(db_conn, monkeypatch):
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)
    hunt_id = _seed_hunt(db_conn)
    query_id = _seed_query(db_conn, hunt_id, tune_history=_TUNE_HISTORY)

    result = sentinel_hunt_tuning.apply_query_tune_suggestion(db_conn, query_id)
    assert result["success"] is False
    assert "Sentinel Hunting sync is off" in result["reason"]


def test_apply_query_tune_suggestion_success_pushes_tuned_body_and_records_action(db_conn, monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    hunt_id = _seed_hunt(db_conn)
    query_id = _seed_query(
        db_conn, hunt_id, sentinel_saved_search_id="real-saved-search-id",
        tune_history=_TUNE_HISTORY,
        tags=[{"Name": "tactics", "Value": "Persistence"}, {"Name": "techniques", "Value": "T1053.005"}],
    )

    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        body = json.loads(request.content)
        captured["body"] = body
        return httpx.Response(200, json={})

    result = sentinel_hunt_tuning.apply_query_tune_suggestion(
        db_conn, query_id, performed_by="alice@example.com",
        client_factory=_client_factory(handler),
    )

    assert result == {"query_id": query_id, "success": True, "reason": None}
    assert "real-saved-search-id" in captured["url"]
    assert captured["body"]["properties"]["query"] == "T | take 1 | where X != @\"bob\""
    tags = {t["Name"]: t["Value"] for t in captured["body"]["properties"]["tags"]}
    assert tags["tactics"] == "Persistence"
    assert tags["techniques"] == "T1053.005"

    detail = sentinel_hunt_queries.get_query_detail(db_conn, query_id)
    assert detail["tuning_suggestion"]["action"] == "applied"
    assert detail["tuning_suggestion"]["pending"] is False
    assert detail["tuning_suggestion"]["performed_by"] == "alice@example.com"


def test_apply_query_tune_suggestion_sentinel_failure_recorded_as_apply_failed(db_conn, monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    hunt_id = _seed_hunt(db_conn)
    query_id = _seed_query(db_conn, hunt_id, tune_history=_TUNE_HISTORY)

    def handler(request):
        return httpx.Response(400, text="BadRequest")

    result = sentinel_hunt_tuning.apply_query_tune_suggestion(
        db_conn, query_id, client_factory=_client_factory(handler),
    )
    assert result["success"] is False

    detail = sentinel_hunt_queries.get_query_detail(db_conn, query_id)
    # apply_failed, not applied -- so the suggestion stays retryable, same
    # convention as tuning_actions.suggestion_view()'s own apply_failed path.
    assert detail["tuning_suggestion"]["action"] == "apply_failed"
    assert detail["tuning_suggestion"]["pending"] is True


def test_dismiss_query_tune_suggestion(db_conn):
    hunt_id = _seed_hunt(db_conn)
    query_id = _seed_query(db_conn, hunt_id, tune_history=_TUNE_HISTORY)

    result = sentinel_hunt_tuning.dismiss_query_tune_suggestion(db_conn, query_id, performed_by="bob@example.com")
    assert result == {"query_id": query_id, "success": True, "reason": None}

    detail = sentinel_hunt_queries.get_query_detail(db_conn, query_id)
    assert detail["tuning_suggestion"]["action"] == "dismissed"
    assert detail["tuning_suggestion"]["pending"] is False
    assert detail["tuning_suggestion"]["performed_by"] == "bob@example.com"


def test_dismiss_query_tune_suggestion_no_suggestion_available(db_conn):
    hunt_id = _seed_hunt(db_conn)
    query_id = _seed_query(db_conn, hunt_id)
    result = sentinel_hunt_tuning.dismiss_query_tune_suggestion(db_conn, query_id)
    assert result["success"] is False


def test_get_query_detail_tuning_suggestion_is_none_when_never_tuned(db_conn):
    hunt_id = _seed_hunt(db_conn)
    query_id = _seed_query(db_conn, hunt_id)
    detail = sentinel_hunt_queries.get_query_detail(db_conn, query_id)
    assert detail["tuning_suggestion"] is None
