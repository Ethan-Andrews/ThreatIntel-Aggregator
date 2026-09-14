"""App-facing read/write for the Sentinel-native hunt/query inventory
(pg_sentinel_hunt_inventory.sql, populated by sentinel_hunt_sync.py).

Mirrors hunts.py's list/detail shape deliberately -- same list-with-rollup,
drill-into-one-hunt pattern -- but a hunt's query list is its OWN paginated
endpoint here, never embedded in the hunt-detail payload: hunts.py's
get_hunt_detail() returns every child detection inline because an AI-
generated hunt typically has a handful, but a real Sentinel hunt can carry
800+ queries, so query listing has to be paginated independently of hunt
listing (see the design doc's pagination section).
"""

from __future__ import annotations

import json

from detection_pipeline import tuning_actions


_HUNT_LIST_COLUMNS = (
    "id, sentinel_hunt_id, display_name, description, status, hypothesis_status, "
    "attack_tactics, attack_techniques, query_count, synced_at, created_at"
)


def _parse_jsonb(value):
    if value is None:
        return []
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return []


def _hunt_row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "sentinel_hunt_id": row["sentinel_hunt_id"],
        "display_name": row["display_name"],
        "description": row["description"],
        "status": row["status"],
        "hypothesis_status": row["hypothesis_status"],
        "attack_tactics": _parse_jsonb(row["attack_tactics"]),
        "attack_techniques": _parse_jsonb(row["attack_techniques"]),
        "query_count": row["query_count"],
        "synced_at": row["synced_at"],
        "created_at": row["created_at"],
    }


def list_sentinel_hunts(conn, limit: int = 50, offset: int = 0,
                        search: str | None = None) -> dict:
    """List Sentinel-native hunts with a review-state rollup over their
    queries, same shape as hunts.list_hunts() -- enough for a list view
    without fetching any query body. search: case-insensitive substring
    match on display_name."""
    clauses = []
    params: list = []
    if search:
        clauses.append("display_name ILIKE ?")
        params.append(f"%{search}%")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    total = conn.execute(
        f"SELECT COUNT(*) FROM sentinel_hunts {where}", tuple(params)
    ).fetchone()[0]
    rows = conn.execute(
        f"SELECT {_HUNT_LIST_COLUMNS} FROM sentinel_hunts {where} "
        f"ORDER BY display_name ASC LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset),
    ).fetchall()

    items = []
    for row in rows:
        item = _hunt_row_to_dict(row)
        rollup = conn.execute(
            "SELECT review_state, COUNT(*) AS n FROM sentinel_hunt_queries "
            "WHERE hunt_id = ? GROUP BY review_state",
            (item["id"],),
        ).fetchall()
        item["review_state_counts"] = {r["review_state"]: r["n"] for r in rollup}
        # How many of this hunt's queries the Tune button is actually
        # enabled for right now (backtest_disposition == 'needs_tuning',
        # same gate the query-list view's own Tune button checks) -- lets
        # a hunt card surface "N tunable" without drilling in first.
        tunable = conn.execute(
            "SELECT COUNT(*) FROM sentinel_hunt_queries "
            "WHERE hunt_id = ? AND backtest_disposition = 'needs_tuning'",
            (item["id"],),
        ).fetchone()[0]
        item["tunable_count"] = tunable
        items.append(item)

    return {"total": total, "items": items}


def get_sentinel_hunt(conn, hunt_id: int) -> dict | None:
    """Hunt metadata only -- deliberately no query list here, see module
    docstring. Use list_hunt_queries() for the (paginated) query list."""
    row = conn.execute(
        f"SELECT {_HUNT_LIST_COLUMNS} FROM sentinel_hunts WHERE id = ?", (hunt_id,)
    ).fetchone()
    return _hunt_row_to_dict(row) if row else None


_QUERY_LIST_COLUMNS = (
    "id, hunt_id, sentinel_saved_search_id, display_name, description, "
    "review_state, backtest_disposition, last_tested_at, created_at"
)


def _query_list_row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "hunt_id": row["hunt_id"],
        "sentinel_saved_search_id": row["sentinel_saved_search_id"],
        "display_name": row["display_name"],
        "description": row["description"],
        "review_state": row["review_state"],
        "backtest_disposition": row["backtest_disposition"],
        "last_tested_at": row["last_tested_at"],
        "created_at": row["created_at"],
    }


def list_hunt_queries(conn, hunt_id: int, limit: int = 50, offset: int = 0,
                      review_state: str | None = None,
                      disposition: str | None = None,
                      search: str | None = None) -> dict:
    """Paginated query list within one hunt -- the actual pagination the
    original ask named (some hunts carry 800+ queries). Deliberately
    excludes kql_body/control_probe_result/tune_history from the list rows
    (fetch those via get_query_detail() for one query at a time) so a page
    of 50 rows doesn't drag along up to 50 full KQL bodies and JSON blobs
    it won't render until expanded. disposition: backtest.BacktestOutcome.
    disposition value -- same 'needs_tuning' shortcut as
    sentinel_analytics_rules.list_analytics_rules(). search: case-
    insensitive substring match on display_name."""
    clauses = ["hunt_id = ?"]
    params: list = [hunt_id]
    if review_state:
        clauses.append("review_state = ?")
        params.append(review_state)
    if disposition:
        clauses.append("backtest_disposition = ?")
        params.append(disposition)
    if search:
        clauses.append("display_name ILIKE ?")
        params.append(f"%{search}%")
    where = " AND ".join(clauses)

    total = conn.execute(
        f"SELECT COUNT(*) FROM sentinel_hunt_queries WHERE {where}", tuple(params)
    ).fetchone()[0]
    rows = conn.execute(
        f"SELECT {_QUERY_LIST_COLUMNS} FROM sentinel_hunt_queries WHERE {where} "
        f"ORDER BY display_name ASC LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset),
    ).fetchall()
    return {"total": total, "items": [_query_list_row_to_dict(r) for r in rows]}


def get_query_detail(conn, query_id: int) -> dict | None:
    """One query's full detail, including kql_body and every pipeline
    result -- the drill-down behind expanding a row in the paginated list."""
    row = conn.execute(
        "SELECT id, hunt_id, sentinel_saved_search_id, display_name, kql_body, "
        "description, tags, review_state, control_probe_result, "
        "backtest_disposition, tune_history, last_tested_at, created_at, "
        "tune_action, tune_action_by, tune_action_at, tune_push_result "
        "FROM sentinel_hunt_queries WHERE id = ?",
        (query_id,),
    ).fetchone()
    if row is None:
        return None
    tune_history = _parse_jsonb(row["tune_history"]) or None
    return {
        "id": row["id"],
        "hunt_id": row["hunt_id"],
        "sentinel_saved_search_id": row["sentinel_saved_search_id"],
        "display_name": row["display_name"],
        "kql_body": row["kql_body"],
        "description": row["description"],
        "tags": _parse_jsonb(row["tags"]),
        "review_state": row["review_state"],
        "control_probe_result": _parse_jsonb(row["control_probe_result"]) or None,
        "backtest_disposition": row["backtest_disposition"],
        "tune_history": tune_history,
        "last_tested_at": row["last_tested_at"],
        "created_at": row["created_at"],
        # Reuses tuning_actions.suggestion_view() as-is -- it only ever
        # reads tune_history plus an {action, sentinel_push_result,
        # performed_by, performed_at} shape, never touching the
        # analytics-table-specific tuning_suggestion_actions storage that
        # backs it for the AI-generated-detections case, so it's equally
        # valid reshaping this row's own tune_action*/tune_push_result
        # columns instead.
        "tuning_suggestion": tuning_actions.suggestion_view(tune_history, {
            "action": row["tune_action"],
            "sentinel_push_result": _parse_jsonb(row["tune_push_result"]) or None,
            "performed_by": row["tune_action_by"],
            "performed_at": row["tune_action_at"],
        }),
    }


_VALID_REVIEW_STATES = ("pending", "approved", "rejected")


def set_query_review_state(conn, query_id: int, review_state: str) -> bool:
    """Human review decision -- same vocabulary as analytics.review_state.
    Returns False if the query doesn't exist or the state isn't valid,
    True on success, so the endpoint can 404/400 appropriately."""
    if review_state not in _VALID_REVIEW_STATES:
        return False
    result = conn.execute(
        "UPDATE sentinel_hunt_queries SET review_state = ? WHERE id = ?",
        (review_state, query_id),
    )
    conn.commit()
    return result.rowcount > 0


def record_query_test_result(conn, query_id: int, control_probe_result: dict,
                             backtest_disposition: str | None) -> None:
    """Persist stage 7/8's output (control probe + backtest) against one
    query -- called by sentinel_hunt_test.run_query_check()."""
    conn.execute(
        "UPDATE sentinel_hunt_queries SET control_probe_result = ?, "
        "backtest_disposition = ?, last_tested_at = now() WHERE id = ?",
        (json.dumps(control_probe_result), backtest_disposition, query_id),
    )
    conn.commit()


def record_query_tune_result(conn, query_id: int, tune_history: dict) -> None:
    """Persist stage 9's output (tune.TuneResult.to_row()) against one
    query -- called by sentinel_hunt_test.run_query_tune()."""
    conn.execute(
        "UPDATE sentinel_hunt_queries SET tune_history = ? WHERE id = ?",
        (json.dumps(tune_history), query_id),
    )
    conn.commit()


_VALID_TUNE_ACTIONS = ("applied", "dismissed")


def record_query_tune_action(conn, query_id: int, action: str,
                             sentinel_push_result: dict | None = None,
                             performed_by: str | None = None) -> None:
    """Record the outcome of an admin's Apply/Dismiss decision on this
    query's tuning suggestion. Overwrites any prior action on the same
    query (unlike tuning_suggestion_actions' append-only audit rows for the
    analytics-table case) -- see pg_sentinel_hunt_queries_tune_action.sql
    for why that tradeoff is fine here."""
    if action not in _VALID_TUNE_ACTIONS:
        raise ValueError(f"action must be one of {_VALID_TUNE_ACTIONS}, got {action!r}")
    conn.execute(
        "UPDATE sentinel_hunt_queries SET tune_action = ?, tune_action_by = ?, "
        "tune_action_at = now(), tune_push_result = ? WHERE id = ?",
        (action, performed_by or None,
         json.dumps(sentinel_push_result) if sentinel_push_result is not None else None,
         query_id),
    )
    conn.commit()
