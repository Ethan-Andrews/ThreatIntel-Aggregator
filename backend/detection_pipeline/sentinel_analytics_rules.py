"""App-facing read/write for the Sentinel Analytics Rules inventory
(pg_sentinel_analytics_rules.sql, populated by sentinel_analytics_rules_sync.py).

Flat, unlike sentinel_hunt_queries.py's hunt-scoped list -- analytics rules
have no parent container in Sentinel, so this is a single paginated list/
detail pair, closer in shape to analytics_catalog.py's list_analytics()
than to the two-level hunts/queries model.
"""

from __future__ import annotations

import json

from detection_pipeline import tuning_actions


def _parse_jsonb(value):
    if value is None:
        return []
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return []


_LIST_COLUMNS = (
    "id, sentinel_rule_id, display_name, description, severity, enabled, "
    "tactics, techniques, review_state, backtest_disposition, last_tested_at, created_at"
)


def _list_row_to_dict(row) -> dict:
    return {
        "id":                   row["id"],
        "sentinel_rule_id":     row["sentinel_rule_id"],
        "display_name":         row["display_name"],
        "description":          row["description"],
        "severity":             row["severity"],
        "enabled":              row["enabled"],
        "tactics":              _parse_jsonb(row["tactics"]),
        "techniques":           _parse_jsonb(row["techniques"]),
        "review_state":         row["review_state"],
        "backtest_disposition": row["backtest_disposition"],
        "last_tested_at":       row["last_tested_at"],
        "created_at":           row["created_at"],
    }


def list_analytics_rules(conn, limit: int = 50, offset: int = 0,
                         review_state: str | None = None,
                         disposition: str | None = None,
                         search: str | None = None) -> dict:
    """Paginated list, deliberately excluding kql_body/control_probe_result/
    tune_history (fetch via get_rule_detail() for one rule at a time) --
    same scale rationale as sentinel_hunt_queries.list_hunt_queries().
    disposition: backtest.BacktestOutcome.disposition value (e.g.
    'needs_tuning') -- lets an admin jump straight to the rules the Tune
    button is actually enabled for, out of a workspace that can carry
    hundreds of rules. search: case-insensitive substring match on
    display_name."""
    clauses = []
    params: list = []
    if review_state:
        clauses.append("review_state = ?")
        params.append(review_state)
    if disposition:
        clauses.append("backtest_disposition = ?")
        params.append(disposition)
    if search:
        clauses.append("display_name ILIKE ?")
        params.append(f"%{search}%")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    total = conn.execute(
        f"SELECT COUNT(*) FROM sentinel_analytics_rules {where}", tuple(params)
    ).fetchone()[0]
    rows = conn.execute(
        f"SELECT {_LIST_COLUMNS} FROM sentinel_analytics_rules {where} "
        f"ORDER BY display_name ASC LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset),
    ).fetchall()
    return {"total": total, "items": [_list_row_to_dict(r) for r in rows]}


def get_rule_detail(conn, rule_id: int) -> dict | None:
    row = conn.execute(
        "SELECT id, sentinel_rule_id, display_name, description, severity, enabled, "
        "kql_body, tactics, techniques, review_state, control_probe_result, "
        "backtest_disposition, tune_history, last_tested_at, created_at, "
        "tune_action, tune_action_by, tune_action_at, tune_push_result "
        "FROM sentinel_analytics_rules WHERE id = ?",
        (rule_id,),
    ).fetchone()
    if row is None:
        return None
    tune_history = _parse_jsonb(row["tune_history"]) or None
    return {
        "id":                   row["id"],
        "sentinel_rule_id":     row["sentinel_rule_id"],
        "display_name":         row["display_name"],
        "description":          row["description"],
        "severity":             row["severity"],
        "enabled":              row["enabled"],
        "kql_body":             row["kql_body"],
        "tactics":              _parse_jsonb(row["tactics"]),
        "techniques":           _parse_jsonb(row["techniques"]),
        "review_state":         row["review_state"],
        "control_probe_result": _parse_jsonb(row["control_probe_result"]) or None,
        "backtest_disposition": row["backtest_disposition"],
        "tune_history":         tune_history,
        "last_tested_at":       row["last_tested_at"],
        "created_at":           row["created_at"],
        # Same reuse of tuning_actions.suggestion_view() as
        # sentinel_hunt_queries.get_query_detail() -- pure shaping function
        # over tune_history + an {action, sentinel_push_result,
        # performed_by, performed_at} shape, equally valid against this
        # table's own tune_action*/tune_push_result columns.
        "tuning_suggestion": tuning_actions.suggestion_view(tune_history, {
            "action": row["tune_action"],
            "sentinel_push_result": _parse_jsonb(row["tune_push_result"]) or None,
            "performed_by": row["tune_action_by"],
            "performed_at": row["tune_action_at"],
        }),
    }


_VALID_REVIEW_STATES = ("pending", "approved", "rejected")


def set_rule_review_state(conn, rule_id: int, review_state: str) -> bool:
    if review_state not in _VALID_REVIEW_STATES:
        return False
    result = conn.execute(
        "UPDATE sentinel_analytics_rules SET review_state = ? WHERE id = ?",
        (review_state, rule_id),
    )
    conn.commit()
    return result.rowcount > 0


def record_rule_test_result(conn, rule_id: int, control_probe_result: dict,
                            backtest_disposition: str | None) -> None:
    conn.execute(
        "UPDATE sentinel_analytics_rules SET control_probe_result = ?, "
        "backtest_disposition = ?, last_tested_at = now() WHERE id = ?",
        (json.dumps(control_probe_result), backtest_disposition, rule_id),
    )
    conn.commit()


def record_rule_tune_result(conn, rule_id: int, tune_history: dict) -> None:
    conn.execute(
        "UPDATE sentinel_analytics_rules SET tune_history = ? WHERE id = ?",
        (json.dumps(tune_history), rule_id),
    )
    conn.commit()


_VALID_TUNE_ACTIONS = ("applied", "dismissed")


def record_rule_tune_action(conn, rule_id: int, action: str,
                            sentinel_push_result: dict | None = None,
                            performed_by: str | None = None) -> None:
    """Record the outcome of an admin's Apply/Dismiss decision on this
    rule's tuning suggestion -- mirrors sentinel_hunt_queries.
    record_query_tune_action() exactly, same overwrite-in-place tradeoff,
    see pg_sentinel_analytics_rules_tune_action.sql."""
    if action not in _VALID_TUNE_ACTIONS:
        raise ValueError(f"action must be one of {_VALID_TUNE_ACTIONS}, got {action!r}")
    conn.execute(
        "UPDATE sentinel_analytics_rules SET tune_action = ?, tune_action_by = ?, "
        "tune_action_at = now(), tune_push_result = ? WHERE id = ?",
        (action, performed_by or None,
         json.dumps(sentinel_push_result) if sentinel_push_result is not None else None,
         rule_id),
    )
    conn.commit()
