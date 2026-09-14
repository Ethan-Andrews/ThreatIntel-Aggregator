"""Dashboard-facing, read-only queries over detection_strategies/analytics
generally -- not just the alignment_reviews subset alignment_reviews.py
serves. Backs GET /api/detections and GET /api/detections/disposition-alerts
in main.py.
"""

from __future__ import annotations

from detection_pipeline import tuning_actions

_LIST_COLUMNS = (
    "a.id, a.strategy_id, ds.technique_id, ds.technique_name, ds.objective, "
    "a.artifact_id, a.name, a.description, a.kql_body, a.tune_history, "
    "a.static_gate_verdict, a.static_gate_durability, "
    "a.backtest_disposition, a.review_state, a.created_at, a.hunt_id, "
    "a.control_probe_result->>'target' AS detection_type"
)

# The values control_probe.ControlPlan.target actually produces (see
# control_query.py) -- "sentinel" means the rule as written executes
# against Sentinel/Log Analytics tables (a Sentinel Analytics Rule),
# "mde" means it executes against Microsoft Defender for Endpoint's own
# schema (a Defender custom detection). "hunt" isn't a target value at
# all -- it's a separate, orthogonal filter (this analytic belongs to a
# hunt, hunt_id IS NOT NULL) that only the alignment-review/disposition-
# alert callers expose, since "which hunt grouped this" and "which
# backend does this run against" are independent questions.
_VALID_DETECTION_TYPES = ("sentinel", "mde", "unbounded", "hunt")


def _detection_type_clause(detection_type: str) -> tuple[str, list]:
    if detection_type == "hunt":
        return "a.hunt_id IS NOT NULL", []
    return "a.control_probe_result->>'target' = ?", [detection_type]


def objective_is_fallback(objective: str | None, technique_name: str | None) -> bool:
    """True when `objective` carries no real MITRE-published Detection
    Strategy content of its own -- it's either exactly the bare technique
    name, or the technique name plus MITRE-cached-objective logic's own
    length-cap truncation (register_strategy() in coverage_ledger.py
    stores `(mitre.objective or technique_name)[:500]`, so a technique
    name that's an exact prefix of objective, not just an exact match, is
    the same "no real objective" case). Same condition Round 4's own
    confirmation query used to split the 154 checked technique_ids into
    "genuinely no MITRE coverage" vs. "corrupted." Used to render a
    clearer fallback label instead of silently repeating the technique
    name as if it were a real, informative objective."""
    if not objective or not technique_name:
        return not objective
    return objective == technique_name or objective.startswith(technique_name)


def _row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "strategy_id": row["strategy_id"],
        "technique_id": row["technique_id"],
        "technique_name": row["technique_name"],
        "objective": row["objective"],
        "objective_is_fallback": objective_is_fallback(row["objective"], row["technique_name"]),
        "artifact_id": row["artifact_id"],
        # name/description are None for analytics registered before
        # pg_analytics_name_description.sql -- callers must fall back to
        # technique_id/technique_name for display, not assume every row
        # has a name.
        "name": row["name"],
        "description": row["description"],
        "kql_body": row["kql_body"],
        "static_gate_verdict": row["static_gate_verdict"],
        "static_gate_durability": (
            float(row["static_gate_durability"])
            if row["static_gate_durability"] is not None else None
        ),
        "backtest_disposition": row["backtest_disposition"],
        "review_state": row["review_state"],
        "created_at": row["created_at"],
        "hunt_id": row["hunt_id"],
        # None until control_probe has actually run at least once -- a
        # still-pending detection has no target yet, not "unbounded".
        "detection_type": row["detection_type"],
    }


def list_analytics(conn, technique_id: str | None = None,
                   disposition: str | None = None,
                   review_state: str | None = None,
                   detection_type: str | None = None,
                   search: str | None = None,
                   limit: int = 50, offset: int = 0) -> dict:
    """General listing of every registered analytic, filterable by
    technique/disposition/review_state/detection_type -- unlike
    alignment_reviews.py's queries, not scoped to divergence review at all.
    detection_type: 'sentinel' | 'mde' | 'unbounded' | 'hunt' (see
    _VALID_DETECTION_TYPES). search: case-insensitive substring match on
    either the technique ID or the stored detection name (same convention
    as sentinel_analytics_rules.list_rules()'s `search` param) -- a row
    with no stored name (pre-pg_analytics_name_description.sql) simply
    can't match on name, only technique_id, same as the UI's own
    "Unnamed -- <technique_id>" fallback label implies."""
    clauses = []
    params: list = []
    if technique_id:
        clauses.append("ds.technique_id = ?")
        params.append(technique_id)
    if search:
        clauses.append("(ds.technique_id ILIKE ? OR a.name ILIKE ?)")
        params.append(f"%{search}%")
        params.append(f"%{search}%")
    if disposition:
        clauses.append("a.backtest_disposition = ?")
        params.append(disposition)
    if review_state:
        clauses.append("a.review_state = ?")
        params.append(review_state)
    if detection_type in _VALID_DETECTION_TYPES:
        clause, clause_params = _detection_type_clause(detection_type)
        clauses.append(clause)
        params.extend(clause_params)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    total = conn.execute(
        f"SELECT COUNT(*) FROM analytics a "
        f"JOIN detection_strategies ds ON ds.id = a.strategy_id {where}",
        tuple(params),
    ).fetchone()[0]
    rows = conn.execute(
        f"SELECT {_LIST_COLUMNS} FROM analytics a "
        f"JOIN detection_strategies ds ON ds.id = a.strategy_id {where} "
        f"ORDER BY a.created_at DESC LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset),
    ).fetchall()
    items = [_row_to_dict(r) for r in rows]
    action_status = tuning_actions.get_tuning_action_status(conn, [i["id"] for i in items])
    for item, row in zip(items, rows):
        item["tuning_suggestion"] = tuning_actions.suggestion_view(
            row["tune_history"], action_status.get(item["id"])
        )
    return {"total": total, "items": items}


def get_analytics_for_tuning(conn, analytic_ids: list[int]) -> dict[int, dict]:
    """The fields a tuning-suggestion apply/dismiss action needs for a batch
    of analytic ids, keyed by id -- current stored name/description/hunt/
    tune_history plus the parent strategy's technique, so
    tuning_suggestions.py can re-send every attribute to Sentinel rather
    than a partial PUT. Missing ids are simply absent from the result."""
    if not analytic_ids:
        return {}
    placeholders = ",".join("?" * len(analytic_ids))
    rows = conn.execute(
        f"SELECT a.id, a.name, a.description, a.hunt_id, a.tune_history, "
        f"ds.technique_id, ds.technique_name "
        f"FROM analytics a JOIN detection_strategies ds ON ds.id = a.strategy_id "
        f"WHERE a.id IN ({placeholders})",
        tuple(analytic_ids),
    ).fetchall()
    return {r["id"]: dict(r) for r in rows}


def get_disposition_alerts(conn, detection_type: str | None = None,
                           limit: int = 50, offset: int = 0) -> dict:
    """Stage 9's surfacing queue: disposition_checks rows flagging that a
    previously-clean analytic started firing or lost its telemetry, most
    recent first. detection_type: see list_analytics()'s docstring."""
    clauses = ["dc.outcome IN ('now_firing', 'telemetry_decayed')"]
    params: list = []
    if detection_type in _VALID_DETECTION_TYPES:
        clause, clause_params = _detection_type_clause(detection_type)
        clauses.append(clause)
        params.extend(clause_params)
    where = " AND ".join(clauses)

    total = conn.execute(
        f"SELECT COUNT(*) FROM disposition_checks dc "
        f"JOIN analytics a ON a.id = dc.analytic_id "
        f"WHERE {where}",
        tuple(params),
    ).fetchone()[0]
    rows = conn.execute(
        f"SELECT dc.id, dc.analytic_id, ds.technique_id, ds.technique_name, "
        f"a.name, a.description, a.kql_body, a.hunt_id, "
        f"a.control_probe_result->>'target' AS detection_type, "
        f"dc.checked_at, dc.hits, dc.window_hours, dc.control_probe_disposition, "
        f"dc.backtest_disposition, dc.outcome, dc.detail "
        f"FROM disposition_checks dc "
        f"JOIN analytics a ON a.id = dc.analytic_id "
        f"JOIN detection_strategies ds ON ds.id = a.strategy_id "
        f"WHERE {where} "
        f"ORDER BY dc.checked_at DESC LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset),
    ).fetchall()
    items = [
        {
            "id": r["id"],
            "analytic_id": r["analytic_id"],
            "technique_id": r["technique_id"],
            "technique_name": r["technique_name"],
            # None for analytics registered before the name/description
            # migration -- caller must fall back to technique_name.
            "name": r["name"],
            "description": r["description"],
            "kql_body": r["kql_body"],
            "hunt_id": r["hunt_id"],
            "detection_type": r["detection_type"],
            "checked_at": r["checked_at"],
            "hits": r["hits"],
            "window_hours": (
                float(r["window_hours"]) if r["window_hours"] is not None else None
            ),
            "control_probe_disposition": r["control_probe_disposition"],
            "backtest_disposition": r["backtest_disposition"],
            "outcome": r["outcome"],
            "detail": r["detail"],
        }
        for r in rows
    ]
    return {"total": total, "items": items}
