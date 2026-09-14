"""Apply/dismiss actions on a Sentinel Hunts query's tune suggestion
(tune.py's run_tune_loop() output via sentinel_hunt_test.run_query_tune(),
persisted as sentinel_hunt_queries.tune_history.final_body).

Backs POST /api/sentinel-hunts/queries/{id}/tuning-suggestion/apply and
.../dismiss in main.py. Deliberately simpler than tuning_suggestions.py
(the equivalent for the AI-generated `analytics` table): a Sentinel Hunts
query already exists natively in the workspace with a real
sentinel_saved_search_id from its own read-sync, so applying just re-PUTs
that same resource with the tuned query text -- no arm_safe_id derivation,
no hunt-linkage check (hunt_id is NOT NULL by schema), and no
hunt_sync_settings mode gate (that setting only governs auto/manual sync
of THIS app's own AI-generated hunts, not a read-only-synced Sentinel-
native query). Still gated on sentinel_hunting.is_enabled() -- the shared
master kill switch every Sentinel write in this app respects.
"""

from __future__ import annotations

from datetime import datetime, timezone

from detection_pipeline import sentinel_hunt_queries, sentinel_hunting


def _now_iso_ms() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def apply_query_tune_suggestion(
    conn, query_id: int, performed_by: str | None = None,
    client_factory=sentinel_hunting.SentinelHuntingClient,
) -> dict:
    """Push this one query's tuned KQL back to the exact Sentinel saved
    search it was synced from. Not batched (unlike tuning_suggestions.py's
    apply_suggestions()) -- the Sentinel Hunts UI acts on one query at a
    time, same as its existing Test/Tune/Review actions."""
    row = sentinel_hunt_queries.get_query_detail(conn, query_id)
    if row is None:
        return {"query_id": query_id, "success": False, "reason": "query not found"}

    final_body = (row.get("tune_history") or {}).get("final_body")
    if not final_body:
        return {
            "query_id": query_id, "success": False,
            "reason": "no tuning suggestion available for this query",
        }

    if not sentinel_hunting.is_enabled():
        return {
            "query_id": query_id, "success": False,
            "reason": "Sentinel Hunting sync is off -- set SENTINEL_HUNTING_SYNC_ENABLED first",
        }

    try:
        client = client_factory()
    except Exception as exc:  # noqa: BLE001 -- credential/config errors vary too much to narrow
        sentinel_hunt_queries.record_query_tune_action(
            conn, query_id, action="applied",
            sentinel_push_result={"status": "error", "detail": str(exc)},
            performed_by=performed_by,
        )
        return {"query_id": query_id, "success": False, "reason": str(exc)}

    # row["tags"] is the exact raw ARM tags array from this query's own
    # last sync (sentinel_hunt_sync.py stores `props.get("tags")` verbatim
    # -- see _upsert_query()) -- the same [{"Name": ..., "Value": ...}]
    # shape upsert_saved_search() itself writes, so tactics/techniques can
    # be read back out of it directly. upsert_saved_search() always does a
    # full PUT, never a partial one: omitting these here would silently
    # drop them from the live resource, not just leave them unchanged.
    raw_tags = row.get("tags") or []

    def _tag_value(name):
        return next((t.get("Value") for t in raw_tags if t.get("Name") == name), None)

    tactics_raw = _tag_value("tactics")
    techniques_raw = _tag_value("techniques")

    try:
        client.upsert_saved_search(
            row["sentinel_saved_search_id"],
            display_name=row.get("display_name") or row["sentinel_saved_search_id"],
            query=sentinel_hunting.append_entity_mapping_extends(final_body),
            description=row.get("description") or "",
            tactics=tactics_raw.split(",") if tactics_raw else None,
            techniques=techniques_raw.split(",") if techniques_raw else None,
            created_by="Threat Intel Aggregator",
            created_time_utc=_now_iso_ms(),
        )
    except Exception as exc:  # noqa: BLE001 -- ARM failure modes vary too much to narrow
        sentinel_hunt_queries.record_query_tune_action(
            conn, query_id, action="applied",
            sentinel_push_result={"status": "error", "detail": str(exc)},
            performed_by=performed_by,
        )
        return {"query_id": query_id, "success": False, "reason": str(exc)}
    finally:
        client.close()

    sentinel_hunt_queries.record_query_tune_action(
        conn, query_id, action="applied",
        sentinel_push_result={"status": "success"},
        performed_by=performed_by,
    )
    return {"query_id": query_id, "success": True, "reason": None}


def dismiss_query_tune_suggestion(conn, query_id: int, performed_by: str | None = None) -> dict:
    """Record "reviewed, not applying" -- no Sentinel call."""
    row = sentinel_hunt_queries.get_query_detail(conn, query_id)
    if row is None:
        return {"query_id": query_id, "success": False, "reason": "query not found"}
    final_body = (row.get("tune_history") or {}).get("final_body")
    if not final_body:
        return {
            "query_id": query_id, "success": False,
            "reason": "no tuning suggestion available for this query",
        }
    sentinel_hunt_queries.record_query_tune_action(
        conn, query_id, action="dismissed", performed_by=performed_by,
    )
    return {"query_id": query_id, "success": True, "reason": None}
