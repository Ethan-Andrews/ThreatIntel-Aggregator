"""Tests for connections_status.py -- the Sentinel/Defender/RunZero
connector-status aggregation behind GET /api/integrations/connections."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import connections_status as status_mod


def _clear_sentinel_env(monkeypatch):
    for var in ("AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP",
                "SENTINEL_WORKSPACE_NAME", "SENTINEL_HUNTING_SYNC_ENABLED"):
        monkeypatch.delenv(var, raising=False)


def test_sentinel_status_not_configured_by_default(db_conn, monkeypatch):
    _clear_sentinel_env(monkeypatch)
    status = status_mod.get_sentinel_status(db_conn)
    assert status["configured"] is False
    assert status["enabled"] is False
    assert status["hunts_last_sync"] is None
    assert status["analytics_rules_last_sync"] is None
    assert status["hunt_query_count"] == 0
    assert status["analytics_rule_count"] == 0


def test_sentinel_status_configured_and_enabled(db_conn, monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    hunt_row = db_conn.execute(
        "INSERT INTO sentinel_hunts (sentinel_hunt_id, display_name, query_count) "
        "VALUES (?, ?, ?) RETURNING id",
        ("hunt-1", "Hunt 1", 1),
    ).fetchone()
    db_conn.execute(
        "INSERT INTO sentinel_hunt_queries "
        "(hunt_id, sentinel_saved_search_id, display_name, kql_body) "
        "VALUES (?, ?, ?, ?)",
        (hunt_row["id"], "q-1", "Query 1", "T | take 1"),
    )
    db_conn.execute(
        "INSERT INTO sentinel_analytics_rules (sentinel_rule_id, display_name, kql_body) "
        "VALUES (?, ?, ?)",
        ("rule-1", "Rule 1", "T | take 1"),
    )
    db_conn.commit()

    status = status_mod.get_sentinel_status(db_conn)
    assert status["configured"] is True
    assert status["enabled"] is True
    assert status["hunt_query_count"] == 1
    assert status["analytics_rule_count"] == 1
    assert status["hunts_last_sync"] is not None
    assert status["analytics_rules_last_sync"] is not None


def test_defender_status_counts_mde_targeted_analytics(db_conn, monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", "rg-1")
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", "ws-1")
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")

    strategy_row = db_conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective) "
        "VALUES (?, ?, ?) RETURNING id",
        ("T1059.001", "PowerShell", "Detect PowerShell abuse"),
    ).fetchone()
    db_conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, control_probe_result) "
        "VALUES (?, ?, ?, ?)",
        (strategy_row["id"], "hash-mde", "T | take 1", json.dumps({"target": "mde"})),
    )
    db_conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, control_probe_result) "
        "VALUES (?, ?, ?, ?)",
        (strategy_row["id"], "hash-sentinel", "T | take 1", json.dumps({"target": "sentinel"})),
    )
    db_conn.commit()

    status = status_mod.get_defender_status(db_conn)
    assert status["configured"] is True
    assert status["enabled"] is True
    assert status["custom_detection_count"] == 1


def test_get_connections_status_includes_all_three(db_conn, monkeypatch):
    _clear_sentinel_env(monkeypatch)
    result = status_mod.get_connections_status(db_conn)
    assert set(result.keys()) == {"sentinel", "defender", "runzero"}
    assert "configured" in result["runzero"]
