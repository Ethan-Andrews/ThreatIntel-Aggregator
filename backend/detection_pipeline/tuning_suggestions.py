"""Apply/dismiss actions on stage-7 tuning suggestions (tune.py's
run_tune_loop() output, persisted as analytics.tune_history.final_body).

Backs POST /api/detections/tuning-suggestions/apply and .../dismiss in
main.py. Applying re-issues sentinel_hunting.py's upsert_saved_search()
with every attribute re-sent (name/description/tactics/techniques) and only
the query text replaced by the tuned body -- never a partial PUT, matching
that function's own contract. It targets the SAME Sentinel saved-search
resource sync_hunt() would have created (the identical
arm_safe_id("query", hunt_id, analytic_id) formula), so this updates the
query Sentinel already has instead of creating a duplicate.

A batch of N ids is never all-or-nothing: each id is evaluated and its
outcome recorded independently via tuning_actions.record_tuning_action(), so
a batch of 20 with 2 failures still shows which 18 succeeded.
"""

from __future__ import annotations

from datetime import datetime, timezone

from detection_pipeline import (
    analytics_catalog,
    hunt_sync_settings,
    mitre_tactics,
    sentinel_hunting,
    tuning_actions,
)


def _now_iso_ms() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def apply_suggestions(
    conn,
    analytic_ids: list[int],
    performed_by: str | None = None,
    client_factory=sentinel_hunting.SentinelHuntingClient,
) -> list[dict]:
    """Push each id's tuned KQL to Sentinel, independently.

    client_factory is injected (defaulting to the real ARM client) so tests
    can supply a fake without needing real Azure credentials -- same
    dependency-injection convention tune.py uses for CountFn/
    FieldPopulationFn.

    Only one client is constructed for the whole batch (not one per item):
    a config/credential failure is a single, batch-wide condition, not a
    per-analytic one, so every id in the batch reports the identical
    failure reason rather than retrying a doomed construction N times.
    """
    rows = analytics_catalog.get_analytics_for_tuning(conn, analytic_ids)
    settings = hunt_sync_settings.get_settings(conn)
    # Both the admin-facing mode toggle AND the master kill switch must be
    # on: mode != 'off' alone is not enough to prove a push will actually
    # reach Sentinel (see sentinel_hunting.is_enabled()'s own no-op-when-
    # disabled behavior) -- reporting "success" here when the underlying
    # sync is silently disabled is exactly the "true diff, false content"
    # kind of lie this endpoint must not produce.
    sync_ready = settings["mode"] != "off" and sentinel_hunting.is_enabled()

    client = None
    client_error: str | None = None
    if sync_ready:
        try:
            client = client_factory()
        except Exception as exc:  # noqa: BLE001 -- credential/config errors vary too much to narrow
            client_error = str(exc)

    try:
        return [
            _apply_one(conn, analytic_id, rows.get(analytic_id), sync_ready,
                      client, client_error, performed_by)
            for analytic_id in analytic_ids
        ]
    finally:
        if client is not None:
            client.close()


def _apply_one(conn, analytic_id, row, sync_ready, client, client_error, performed_by) -> dict:
    if row is None:
        return {"analytic_id": analytic_id, "success": False, "reason": "analytic not found"}

    final_body = (row.get("tune_history") or {}).get("final_body")
    if not final_body:
        return {
            "analytic_id": analytic_id, "success": False,
            "reason": "no tuning suggestion available for this analytic",
        }

    if row.get("hunt_id") is None:
        return {
            "analytic_id": analytic_id, "success": False,
            "reason": "analytic does not belong to a hunt",
        }

    if not sync_ready:
        return {
            "analytic_id": analytic_id, "success": False,
            "reason": "Hunt Sentinel sync is off -- enable manual or auto mode in Settings first",
        }

    if client is None:
        tuning_actions.record_tuning_action(
            conn, analytic_id, suggested_kql_body=final_body, action="applied",
            applied_kql_body=None,
            sentinel_push_result={"status": "error", "detail": client_error},
            performed_by=performed_by,
        )
        return {"analytic_id": analytic_id, "success": False, "reason": client_error}

    technique_id = row.get("technique_id")
    tactics = mitre_tactics.tactics_for_techniques([technique_id])[1] if technique_id else []
    techniques = [mitre_tactics.base_technique(technique_id)] if technique_id else None
    saved_search_id = sentinel_hunting.arm_safe_id(
        "query", str(row["hunt_id"]), str(analytic_id)
    )

    try:
        client.upsert_saved_search(
            saved_search_id,
            display_name=row.get("name") or technique_id or saved_search_id,
            query=sentinel_hunting.append_entity_mapping_extends(final_body),
            description=row.get("description") or "",
            tactics=tactics,
            techniques=techniques,
            created_by="Threat Intel Aggregator",
            created_time_utc=_now_iso_ms(),
        )
    except Exception as exc:  # noqa: BLE001 -- ARM failure modes vary too much to narrow
        tuning_actions.record_tuning_action(
            conn, analytic_id, suggested_kql_body=final_body, action="applied",
            applied_kql_body=None,
            sentinel_push_result={"status": "error", "detail": str(exc)},
            performed_by=performed_by,
        )
        return {"analytic_id": analytic_id, "success": False, "reason": str(exc)}

    tuning_actions.record_tuning_action(
        conn, analytic_id, suggested_kql_body=final_body, action="applied",
        applied_kql_body=final_body,
        sentinel_push_result={"status": "success"},
        performed_by=performed_by,
    )
    return {"analytic_id": analytic_id, "success": True, "reason": None}


def dismiss_suggestions(conn, analytic_ids: list[int], performed_by: str | None = None) -> list[dict]:
    """Record "reviewed, not applying" for each id -- no Sentinel call, no
    hunt/sync-eligibility requirement, since dismissing never pushes
    anywhere. Distinguishes "never looked at" (absent from
    tuning_suggestion_actions) from "looked at, declined" (a dismissed row)
    for the audit trail."""
    rows = analytics_catalog.get_analytics_for_tuning(conn, analytic_ids)
    results = []
    for analytic_id in analytic_ids:
        row = rows.get(analytic_id)
        if row is None:
            results.append({"analytic_id": analytic_id, "success": False, "reason": "analytic not found"})
            continue
        final_body = (row.get("tune_history") or {}).get("final_body")
        if not final_body:
            results.append({
                "analytic_id": analytic_id, "success": False,
                "reason": "no tuning suggestion available for this analytic",
            })
            continue
        tuning_actions.record_tuning_action(
            conn, analytic_id, suggested_kql_body=final_body, action="dismissed",
            applied_kql_body=None, sentinel_push_result=None, performed_by=performed_by,
        )
        results.append({"analytic_id": analytic_id, "success": True, "reason": None})
    return results
