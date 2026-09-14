"""Audit trail for admin actions (apply/dismiss) on stage-7 tuning
suggestions -- tune.py's run_tune_loop() output, persisted as
analytics.tune_history.final_body. See pg_tuning_suggestion_actions.sql for
the schema and the append-only rationale.

Deliberately decoupled from both UI groupings that render `analytics` rows
(Hunts view, and the flat Detections/Analytics-Rules catalog): this module
only records what happened to one analytic id, independent of which panel
triggered it, so both surfaces -- and any future consumer, e.g. a
tune-quality dashboard -- can read the same audit trail without caring
where in the UI the action came from.

Kept separate from the apply/dismiss orchestration itself
(tuning_suggestions.py, which decides WHETHER an action can proceed and
talks to Sentinel) -- this module is the narrower, reusable piece: just
reading and writing tuning_suggestion_actions rows.
"""

from __future__ import annotations

import json

_VALID_ACTIONS = ("applied", "dismissed")


def record_tuning_action(
    conn,
    analytic_id: int,
    suggested_kql_body: str,
    action: str,
    applied_kql_body: str | None = None,
    sentinel_push_result: dict | None = None,
    performed_by: str | None = None,
) -> int:
    """Insert one immutable audit row. Never an UPDATE -- a later action on
    the same analytic (e.g. dismissing after an earlier failed apply) is a
    NEW row, so the point-in-time history survives, not just the latest
    state (see get_tuning_action_status() for "latest" as a read-time
    concept, not a storage one).

    suggested_kql_body must be the snapshot taken at action time -- callers
    must not re-read analytics.tune_history here, since it can have been
    overwritten by a later tuning pass by the time this is called.
    """
    if action not in _VALID_ACTIONS:
        raise ValueError(f"action must be one of {_VALID_ACTIONS}, got {action!r}")
    row = conn.execute(
        "INSERT INTO tuning_suggestion_actions "
        "(analytic_id, suggested_kql_body, action, applied_kql_body, "
        " sentinel_push_result, performed_by) "
        "VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
        (
            analytic_id, suggested_kql_body, action, applied_kql_body,
            json.dumps(sentinel_push_result) if sentinel_push_result is not None else None,
            performed_by or None,
        ),
    ).fetchone()
    conn.commit()
    return row["id"]


def get_tuning_action_status(conn, analytic_ids: list[int]) -> dict[int, dict]:
    """Most recent tuning-suggestion action per analytic id, keyed by id.

    An id with no recorded action is simply absent from the result -- callers
    must treat "absent" as "never reviewed", distinct from a dismissed one,
    not assume every requested id comes back.
    """
    if not analytic_ids:
        return {}
    placeholders = ",".join("?" * len(analytic_ids))
    rows = conn.execute(
        f"SELECT DISTINCT ON (analytic_id) analytic_id, action, "
        f"applied_kql_body, sentinel_push_result, performed_by, performed_at "
        f"FROM tuning_suggestion_actions WHERE analytic_id IN ({placeholders}) "
        f"ORDER BY analytic_id, performed_at DESC",
        tuple(analytic_ids),
    ).fetchall()
    return {
        r["analytic_id"]: {
            "action": r["action"],
            "applied_kql_body": r["applied_kql_body"],
            "sentinel_push_result": r["sentinel_push_result"],
            "performed_by": r["performed_by"],
            "performed_at": r["performed_at"],
        }
        for r in rows
    }


def suggestion_view(tune_history: dict | None, action_entry: dict | None) -> dict | None:
    """Shape returned to the frontend for one analytic's tuning-suggestion
    state -- lets the UI show/hide the "Tuning suggestion available" badge
    and the apply/dismiss controls from the same list/detail response,
    without a second round-trip to check action status.

    None means tune.py never ran (or ran and found nothing narrowable) for
    this analytic -- there is no tune_history at all. A non-None result with
    pending=False and final_body=None means tuning ran but landed on a
    disposition with no real suggestion to show (needs_human_tuning,
    ineffective, not_narrowable) -- see tune.py's TuneResult.to_row().

    A recorded action of 'applied' whose sentinel_push_result actually
    failed is surfaced as action='apply_failed', with pending=True -- found
    via a mass-data stress test (2026-09-01): tuning_suggestions.py
    correctly records a failed push with sentinel_push_result={"status":
    "error", ...} (see apply_suggestions()'s per-item POST response, which
    already reports success=false), but this function was reading only the
    bare 'applied'/'dismissed' action string, so a failed apply attempt
    rendered identically to a successful one on every subsequent read --
    the frontend badge showed a green "TUNING APPLIED" pill for a
    suggestion that never reached Sentinel. Treating it as still-pending
    (rather than a dead end) also lets an admin retry the apply, which a
    push failure should always allow.
    """
    if not tune_history:
        return None
    final_body = tune_history.get("final_body")
    disposition = tune_history.get("disposition")
    if not final_body:
        return {
            "disposition": disposition, "pending": False, "final_body": None,
            "action": None, "performed_by": None, "performed_at": None,
            "error": None,
        }
    action_entry = action_entry or {}
    action = action_entry.get("action")
    push_result = action_entry.get("sentinel_push_result") or {}
    apply_failed = action == "applied" and push_result.get("status") == "error"
    return {
        "disposition": disposition,
        "pending": action is None or apply_failed,
        "final_body": final_body,
        "action": "apply_failed" if apply_failed else action,
        "performed_by": action_entry.get("performed_by"),
        "performed_at": action_entry.get("performed_at"),
        "error": push_result.get("detail") if apply_failed else None,
    }
