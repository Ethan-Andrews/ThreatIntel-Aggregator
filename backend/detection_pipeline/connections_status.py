"""Aggregated connector status for the Integrations tab overview: Sentinel,
Defender, and RunZero. One endpoint so the overview cards don't need three
separate round trips.

Defender custom detections ride the *same* Sentinel/Log Analytics ARM
connection as everything else this app talks to Sentinel over -- Device*
tables are Defender XDR data ingested into the same workspace (see
telemetry_resolver.py's SentinelTelemetryResolver, which resolves MDE
tables through this identical connection), not a separate credential. So
Defender's configured/enabled flags mirror Sentinel's; only the detection
count below is Defender-specific.
"""

from __future__ import annotations

import os

from db import get_runzero_status
from detection_pipeline import sentinel_hunting


def _sentinel_configured() -> bool:
    return bool(
        os.environ.get("AZURE_SUBSCRIPTION_ID")
        and os.environ.get("AZURE_RESOURCE_GROUP")
        and os.environ.get("SENTINEL_WORKSPACE_NAME")
    )


def get_sentinel_status(conn) -> dict:
    hunts_last_sync = conn.execute(
        "SELECT MAX(synced_at) FROM sentinel_hunt_queries"
    ).fetchone()[0]
    analytics_rules_last_sync = conn.execute(
        "SELECT MAX(synced_at) FROM sentinel_analytics_rules"
    ).fetchone()[0]
    hunt_query_count = conn.execute(
        "SELECT COUNT(*) FROM sentinel_hunt_queries"
    ).fetchone()[0]
    analytics_rule_count = conn.execute(
        "SELECT COUNT(*) FROM sentinel_analytics_rules"
    ).fetchone()[0]
    return {
        "configured": _sentinel_configured(),
        "enabled": sentinel_hunting.is_enabled(),
        "hunts_last_sync": hunts_last_sync,
        "analytics_rules_last_sync": analytics_rules_last_sync,
        "hunt_query_count": hunt_query_count,
        "analytics_rule_count": analytics_rule_count,
    }


def get_defender_status(conn) -> dict:
    custom_detection_count = conn.execute(
        "SELECT COUNT(*) FROM analytics WHERE control_probe_result->>'target' = 'mde'"
    ).fetchone()[0]
    return {
        "configured": _sentinel_configured(),
        "enabled": sentinel_hunting.is_enabled(),
        "custom_detection_count": custom_detection_count,
    }


def get_connections_status(conn) -> dict:
    return {
        "sentinel": get_sentinel_status(conn),
        "defender": get_defender_status(conn),
        "runzero": get_runzero_status(),
    }
