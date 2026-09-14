"""Apply/dismiss actions on a Sentinel Analytics Rule's tune suggestion
(tune.py's run_tune_loop() output via sentinel_hunt_test.run_query_tune(),
persisted as sentinel_analytics_rules.tune_history.final_body).

Backs POST /api/sentinel-analytics-rules/{id}/tuning-suggestion/apply and
.../dismiss in main.py. Structurally close to sentinel_hunt_tuning.py, but
Apply here can't just re-PUT a small, fully-owned resource the way a
savedSearches hunting query can: an alertRules PUT body carries several
required fields (queryFrequency, queryPeriod, triggerOperator,
triggerThreshold, suppressionDuration, suppressionEnabled, and more)
pg_sentinel_analytics_rules.sql never stores locally, so a locally-
reconstructed PUT risks silently reverting whatever those are set to live.
Instead this calls SentinelAnalyticsRulesReadClient.update_alert_rule_
query(), which does its own read-modify-write immediately before writing --
see that method's docstring in sentinel_analytics_rules_sync.py. Still
gated on sentinel_hunting.is_enabled(), same shared master kill switch
every Sentinel write in this app respects (see that module's own docstring
for why Analytics Rules sync reuses Hunting's flag rather than adding a
second one).
"""

from __future__ import annotations

from detection_pipeline import sentinel_analytics_rules, sentinel_hunting
from detection_pipeline.sentinel_analytics_rules_sync import SentinelAnalyticsRulesReadClient


def apply_rule_tune_suggestion(
    conn, rule_id: int, performed_by: str | None = None,
    client_factory=SentinelAnalyticsRulesReadClient,
) -> dict:
    """Push this one rule's tuned KQL back to the exact Sentinel alert rule
    it was synced from, via a fresh read-modify-write (not a locally-
    reconstructed PUT -- see module docstring)."""
    row = sentinel_analytics_rules.get_rule_detail(conn, rule_id)
    if row is None:
        return {"rule_id": rule_id, "success": False, "reason": "rule not found"}

    final_body = (row.get("tune_history") or {}).get("final_body")
    if not final_body:
        return {
            "rule_id": rule_id, "success": False,
            "reason": "no tuning suggestion available for this rule",
        }

    if not sentinel_hunting.is_enabled():
        return {
            "rule_id": rule_id, "success": False,
            "reason": "Sentinel Hunting sync is off -- set SENTINEL_HUNTING_SYNC_ENABLED first",
        }

    try:
        client = client_factory()
    except Exception as exc:  # noqa: BLE001 -- credential/config errors vary too much to narrow
        sentinel_analytics_rules.record_rule_tune_action(
            conn, rule_id, action="applied",
            sentinel_push_result={"status": "error", "detail": str(exc)},
            performed_by=performed_by,
        )
        return {"rule_id": rule_id, "success": False, "reason": str(exc)}

    try:
        client.update_alert_rule_query(row["sentinel_rule_id"], final_body)
    except Exception as exc:  # noqa: BLE001 -- ARM failure modes vary too much to narrow
        sentinel_analytics_rules.record_rule_tune_action(
            conn, rule_id, action="applied",
            sentinel_push_result={"status": "error", "detail": str(exc)},
            performed_by=performed_by,
        )
        return {"rule_id": rule_id, "success": False, "reason": str(exc)}
    finally:
        client.close()

    sentinel_analytics_rules.record_rule_tune_action(
        conn, rule_id, action="applied",
        sentinel_push_result={"status": "success"},
        performed_by=performed_by,
    )
    return {"rule_id": rule_id, "success": True, "reason": None}


def dismiss_rule_tune_suggestion(conn, rule_id: int, performed_by: str | None = None) -> dict:
    """Record "reviewed, not applying" -- no Sentinel call."""
    row = sentinel_analytics_rules.get_rule_detail(conn, rule_id)
    if row is None:
        return {"rule_id": rule_id, "success": False, "reason": "rule not found"}
    final_body = (row.get("tune_history") or {}).get("final_body")
    if not final_body:
        return {
            "rule_id": rule_id, "success": False,
            "reason": "no tuning suggestion available for this rule",
        }
    sentinel_analytics_rules.record_rule_tune_action(
        conn, rule_id, action="dismissed", performed_by=performed_by,
    )
    return {"rule_id": rule_id, "success": True, "reason": None}
