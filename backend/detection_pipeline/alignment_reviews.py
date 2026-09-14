"""Dashboard-facing queries and human actions on alignment_reviews rows.

Separate from alignment_check.py, which only ever writes these rows from
the pipeline (generation time, periodic revalidation, the re-review sweep).
This module is what main.py's /api/detections/alignment/* endpoints call.

validation_result is passed through opaquely (jsonb in, jsonb out) -- this
module doesn't need to know its internal shape (log_source_checks,
telemetry_probes, gap_reason, static_gate, backtest -- see
alignment_check.py's _write_diverges) to serve or act on a review.
"""

from __future__ import annotations

from detection_pipeline.analytics_catalog import objective_is_fallback

_LIST_COLUMNS = (
    "ar.id, ar.strategy_id, ar.analytic_id, ds.technique_id, ds.technique_name, "
    "ds.objective AS our_objective, ar.verdict, ar.ai_reasoning, ar.suggested_kql, "
    "ar.validation_result, ar.status, ar.created_at, "
    "a.name AS detection_name, a.description AS detection_description, "
    "a.kql_body AS deployed_kql_body, a.hunt_id, "
    "a.control_probe_result->>'target' AS detection_type"
)

# Same vocabulary as analytics_catalog._VALID_DETECTION_TYPES -- 'sentinel'/
# 'mde'/'unbounded' from the linked analytic's own control_probe_result.target,
# plus 'hunt' as an orthogonal hunt_id-not-null filter. A review with no
# linked analytic (analytic_id is nullable -- a fresh divergence with no
# prior analytic) has neither and is excluded by any of these filters,
# same as an unchecked item is excluded from the audit log.
_VALID_DETECTION_TYPES = ("sentinel", "mde", "unbounded", "hunt")


def _detection_type_clause(detection_type: str) -> tuple[str, list]:
    if detection_type == "hunt":
        return "a.hunt_id IS NOT NULL", []
    return "a.control_probe_result->>'target' = ?", [detection_type]


def _row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "strategy_id": row["strategy_id"],
        "analytic_id": row["analytic_id"],
        "technique_id": row["technique_id"],
        "technique_name": row["technique_name"],
        "our_objective": row["our_objective"],
        "our_objective_is_fallback": objective_is_fallback(row["our_objective"], row["technique_name"]),
        "verdict": row["verdict"],
        "ai_reasoning": row["ai_reasoning"],
        "suggested_kql": row["suggested_kql"],
        "validation_result": row["validation_result"],
        "status": row["status"],
        "created_at": row["created_at"],
        # The currently-deployed analytic's own name/description/KQL, when
        # this review is linked to one (analytic_id is nullable -- a fresh
        # divergence on a strategy with no prior analytic has none). Distinct
        # from ai_reasoning/suggested_kql, which describe the AI's proposed
        # *replacement*, not what's live today.
        "detection_name": row["detection_name"],
        "detection_description": row["detection_description"],
        "deployed_kql_body": row["deployed_kql_body"],
        "hunt_id": row["hunt_id"],
        "detection_type": row["detection_type"],
    }


def _list_by_status(conn, status: str, detection_type: str | None,
                    limit: int, offset: int, ready_only: bool = False) -> dict:
    clauses = ["ar.status = ?"]
    params: list = [status]
    if detection_type in _VALID_DETECTION_TYPES:
        clause, clause_params = _detection_type_clause(detection_type)
        clauses.append(clause)
        params.extend(clause_params)
    if ready_only:
        # "Ready to accept": the same actionability check accept_review()
        # itself enforces before it will act on a review. In practice this
        # is only ever meaningful on the pending_review bucket -- every
        # queued_for_rereview ('partial') row is written by _write_partial()
        # in alignment_check.py, which never populates suggested_kql at all
        # (the two "unassessable" cases named in the round-4 design spec --
        # "AI response was not valid JSON" and "MITRE has no published
        # Detection Strategy" -- both force verdict='partial' by
        # construction), so this clause naturally excludes both without
        # needing a separate reasoning-text check. Applying it to the
        # partial bucket too (rather than only wiring it into the pending
        # endpoint) costs nothing and keeps both endpoints symmetric.
        clauses.append("ar.suggested_kql IS NOT NULL AND ar.suggested_kql != ''")
    where = " AND ".join(clauses)

    total = conn.execute(
        f"SELECT COUNT(*) FROM alignment_reviews ar "
        f"LEFT JOIN analytics a ON a.id = ar.analytic_id "
        f"WHERE {where}",
        tuple(params),
    ).fetchone()[0]
    rows = conn.execute(
        f"SELECT {_LIST_COLUMNS} FROM alignment_reviews ar "
        f"JOIN detection_strategies ds ON ds.id = ar.strategy_id "
        f"LEFT JOIN analytics a ON a.id = ar.analytic_id "
        f"WHERE {where} ORDER BY ar.created_at ASC LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset),
    ).fetchall()
    return {"total": total, "items": [_row_to_dict(r) for r in rows]}


def get_pending_reviews(conn, detection_type: str | None = None,
                        limit: int = 50, offset: int = 0,
                        ready_only: bool = False) -> dict:
    return _list_by_status(conn, "pending_review", detection_type, limit, offset,
                           ready_only=ready_only)


def get_partial_reviews(conn, detection_type: str | None = None,
                        limit: int = 50, offset: int = 0,
                        ready_only: bool = False) -> dict:
    return _list_by_status(conn, "queued_for_rereview", detection_type, limit, offset,
                           ready_only=ready_only)


def accept_review(conn, review_id: int, reviewed_by: str) -> dict:
    """Approve a diverges review: registers suggested_kql as a new,
    pre-approved analytic on the strategy (the prior analytic is left in
    place -- history, not replaced), then marks the review accepted."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from coverage_ledger import register_analytic

    row = conn.execute(
        "SELECT strategy_id, analytic_id, verdict, suggested_kql, validation_result, status "
        "FROM alignment_reviews WHERE id = ?",
        (review_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"no alignment_reviews row for id={review_id}")
    if row["status"] != "pending_review":
        raise ValueError(f"review {review_id} is '{row['status']}', not pending_review")
    if row["verdict"] != "diverges" or not row["suggested_kql"]:
        raise ValueError(f"review {review_id} has no suggested_kql to accept")

    import json
    validation = row["validation_result"] or {}
    if isinstance(validation, str):
        validation = json.loads(validation)
    static_gate = validation.get("static_gate", {})

    # The suggested_kql is a fix FOR the analytic this review is linked to
    # (when one exists -- analytic_id is nullable, a fresh divergence with
    # no prior analytic has none) -- inheriting its name/description/
    # hunt_id keeps the accepted replacement identifiable and correctly
    # grouped, matching what register_analytic()'s own docstring already
    # promises ("history, not replaced"). Confirmed live 2026-09-02: this
    # call never passed name/description/hunt_id at all, so every analytic
    # created by accepting a review showed as permanently "Unnamed" no
    # matter how recently it was created -- unlike orchestrator.py's own
    # register_analytic() call, which always has det.title/description/
    # hunt_id to pass.
    name = description = None
    hunt_id = None
    if row["analytic_id"] is not None:
        prior = conn.execute(
            "SELECT name, description, hunt_id FROM analytics WHERE id = ?",
            (row["analytic_id"],),
        ).fetchone()
        if prior is not None:
            name, description, hunt_id = prior["name"], prior["description"], prior["hunt_id"]

    analytic_id = register_analytic(
        conn, row["strategy_id"], source_entry_hash=f"alignment-review-{review_id}",
        kql_body=row["suggested_kql"], durability=static_gate.get("durability"),
        disposition=validation.get("backtest", {}).get("disposition"),
        name=name, description=description, hunt_id=hunt_id,
    )
    conn.execute("UPDATE analytics SET review_state = 'approved' WHERE id = ?", (analytic_id,))
    conn.execute(
        "UPDATE alignment_reviews SET status = 'accepted', reviewed_at = now(), "
        "reviewed_by = ? WHERE id = ?",
        (reviewed_by, review_id),
    )
    conn.commit()
    return {"review_id": review_id, "status": "accepted", "new_analytic_id": analytic_id}


def reject_review(conn, review_id: int, reviewed_by: str) -> dict:
    row = conn.execute(
        "SELECT status FROM alignment_reviews WHERE id = ?", (review_id,)
    ).fetchone()
    if row is None:
        raise ValueError(f"no alignment_reviews row for id={review_id}")
    if row["status"] != "pending_review":
        raise ValueError(f"review {review_id} is '{row['status']}', not pending_review")

    conn.execute(
        "UPDATE alignment_reviews SET status = 'rejected', reviewed_at = now(), "
        "reviewed_by = ? WHERE id = ?",
        (reviewed_by, review_id),
    )
    conn.commit()
    return {"review_id": review_id, "status": "rejected"}
