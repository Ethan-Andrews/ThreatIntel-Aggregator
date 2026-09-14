"""Hunts: the grouping concept over `analytics` rows that Sentinel's own
"Hunts" feature (Microsoft.SecurityInsights/hunts, public preview) also
uses natively -- one hunt per originating TI article/detections.ai project,
containing every KQL detection/query generated from it.

Every `analytics` row already carried `source_entry_hash` (the originating
article's hash) with nothing to group it by; `pg_hunts.sql` adds the `hunts`
table and an `analytics.hunt_id` FK, backfilling existing rows from
`source_entry_hash` alone. `get_or_create_hunt()` is the write path used by
orchestrator.py at generation time; `list_hunts()`/`get_hunt_detail()` back
the dashboard's Hunts tab (list view + drill-into-one-hunt detail view).

See sentinel_hunting.py for the (feature-flagged, non-fatal) ARM sync that
turns a hunt row into a real Sentinel Hunt once RBAC is granted -- this
module only manages our own database, never talks to Azure.
"""

from __future__ import annotations

from detection_pipeline import tuning_actions
from detection_pipeline.analytics_catalog import objective_is_fallback


def get_or_create_hunt(conn, source_entry_hash: str, title: str,
                       description: str = "", source_title: str = "",
                       source_link: str = "", source_name: str = "",
                       source_severity: str = "",
                       origin: str = "ai_generated") -> int:
    """Get the hunt for this article, creating it on first sight.

    Idempotent by `source_entry_hash` (one hunt per article, enforced by a
    UNIQUE constraint) -- a retried candidate on the same article reuses the
    same hunt rather than creating a duplicate, mirroring how
    `_get_saved_project`/`_save_project` already dedupe detections.ai
    projects by the same key. `origin` is only set on first creation (the
    ON CONFLICT branch never touches it) -- a hunt's origin reflects how it
    was first created, not whatever the most recent caller happened to be.
    """
    row = conn.execute(
        "SELECT id FROM hunts WHERE source_entry_hash = ?", (source_entry_hash,)
    ).fetchone()
    if row:
        return row["id"]
    row = conn.execute(
        "INSERT INTO hunts "
        "(source_entry_hash, title, description, source_title, source_link, "
        " source_name, source_severity, origin) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (source_entry_hash) DO UPDATE SET source_entry_hash = EXCLUDED.source_entry_hash "
        "RETURNING id",
        (source_entry_hash, title, description or None, source_title or None,
         source_link or None, source_name or None, source_severity or None,
         origin),
    ).fetchone()
    conn.commit()
    return row["id"]


def mark_hunt_synced(conn, hunt_id: int, sentinel_hunt_id: str | None,
                     error: str | None = None) -> None:
    """Record the outcome of a sentinel_hunting sync attempt. Never raises --
    called from a best-effort sync path that must not affect pipeline state
    either way."""
    conn.execute(
        "UPDATE hunts SET sentinel_hunt_id = ?, sentinel_synced_at = now(), "
        "sentinel_sync_error = ?, updated_at = now() "
        "WHERE id = ?",
        (sentinel_hunt_id, error, hunt_id),
    )
    conn.commit()


_HUNT_LIST_COLUMNS = (
    "h.id, h.title, h.description, h.source_title, h.source_link, "
    "h.source_name, h.source_severity, h.sentinel_hunt_id, h.sentinel_synced_at, "
    "h.target_sentinel_hunt_id, h.created_at"
)


def _hunt_row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "source_title": row["source_title"],
        "source_link": row["source_link"],
        "source_name": row["source_name"],
        "source_severity": row["source_severity"],
        "sentinel_hunt_id": row["sentinel_hunt_id"],
        "sentinel_synced_at": row["sentinel_synced_at"],
        # NULL (the default) means "create/manage our own dedicated
        # Sentinel Hunt for this row" (sentinel_hunting.sync_hunt()'s
        # historical behavior). Set via set_hunt_target() to instead link
        # this hunt's queries into an existing Sentinel Hunt (e.g. "In the
        # News V2") without ever touching that hunt's own metadata.
        "target_sentinel_hunt_id": row["target_sentinel_hunt_id"],
        "created_at": row["created_at"],
    }


def set_hunt_target(conn, hunt_id: int, target_sentinel_hunt_id: str | None) -> None:
    """Point this hunt at an existing Sentinel Hunt (by ARM resource name/
    GUID, from SentinelHuntingClient.list_hunts()) instead of the default
    dedicated-per-hunt sync target. Pass None to go back to the default."""
    # Deliberately doesn't touch updated_at -- list_hunts_needing_deploy()'s
    # own docstring documents mark_hunt_synced() as the column's only
    # writer, and that invariant isn't needed here (this setter doesn't
    # feed any "needs resync" computation).
    conn.execute(
        "UPDATE hunts SET target_sentinel_hunt_id = ? WHERE id = ?",
        (target_sentinel_hunt_id or None, hunt_id),
    )
    conn.commit()


_READY_TO_DEPLOY_CLAUSE = (
    "h.id IN (SELECT a.hunt_id FROM analytics a "
    "WHERE a.static_gate_verdict = 'pass' AND a.backtest_disposition = 'clean' "
    "AND a.hunt_id IS NOT NULL)"
)


def list_hunts(conn, technique_id: str | None = None, ready_only: bool = False,
              search: str | None = None,
              limit: int = 50, offset: int = 0) -> dict:
    """List hunts with a rollup of their child detections: count, MITRE
    techniques covered, a review-state breakdown, and how many detections
    are ready to deploy -- enough for a list view without fetching every
    detection's full KQL body.

    ready_only=True restricts to hunts with at least one detection meeting
    the same base eligibility bar as get_sync_eligible_detections()
    (static gate pass + clean backtest, no alignment requirement -- a human
    reviewing the list is the alignment check here). search: case-
    insensitive substring match on the hunt's own title -- unlike an
    individual detection's `name`, a hunt's title is always populated at
    creation time (get_or_create_hunt() requires it), so this never needs
    an "Unnamed" fallback the way the detections catalog's name search
    does."""
    clauses = []
    params: list = []
    if technique_id:
        clauses.append(
            "h.id IN (SELECT a.hunt_id FROM analytics a "
            "JOIN detection_strategies ds ON ds.id = a.strategy_id "
            "WHERE ds.technique_id = ? AND a.hunt_id IS NOT NULL)"
        )
        params.append(technique_id)
    if search:
        clauses.append("h.title ILIKE ?")
        params.append(f"%{search}%")
    if ready_only:
        clauses.append(_READY_TO_DEPLOY_CLAUSE)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    total = conn.execute(
        f"SELECT COUNT(*) FROM hunts h {where}", tuple(params)
    ).fetchone()[0]

    rows = conn.execute(
        f"SELECT {_HUNT_LIST_COLUMNS} FROM hunts h {where} "
        f"ORDER BY h.created_at DESC LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset),
    ).fetchall()

    items = []
    for row in rows:
        item = _hunt_row_to_dict(row)
        rollup = conn.execute(
            "SELECT ds.technique_id, ds.technique_name, a.review_state, "
            "a.static_gate_verdict, a.backtest_disposition "
            "FROM analytics a JOIN detection_strategies ds ON ds.id = a.strategy_id "
            "WHERE a.hunt_id = ?",
            (item["id"],),
        ).fetchall()
        techniques = {}
        review_counts: dict = {}
        eligible_count = 0
        for r in rollup:
            techniques[r["technique_id"]] = r["technique_name"]
            review_counts[r["review_state"]] = review_counts.get(r["review_state"], 0) + 1
            if r["static_gate_verdict"] == "pass" and r["backtest_disposition"] == "clean":
                eligible_count += 1
        item["detection_count"] = len(rollup)
        item["techniques"] = [
            {"technique_id": tid, "technique_name": tname}
            for tid, tname in techniques.items()
        ]
        item["review_state_counts"] = review_counts
        item["eligible_count"] = eligible_count
        items.append(item)

    return {"total": total, "items": items}


_NEEDS_DEPLOY_CLAUSE = (
    "(h.sentinel_hunt_id IS NULL "
    " OR h.sentinel_sync_error IS NOT NULL "
    " OR EXISTS (SELECT 1 FROM analytics a WHERE a.hunt_id = h.id "
    "            AND a.created_at > h.sentinel_synced_at))"
)


def list_hunts_needing_deploy(conn) -> list[dict]:
    """Hunts that "Deploy All" should push: never synced, the last sync
    attempt failed, or a detection was added to the hunt since its last
    successful sync.

    There is no separate "hunt content changed" timestamp on `hunts` itself
    (mark_hunt_synced() is the only writer of updated_at, so it always
    trails sentinel_synced_at, not leads it) -- a child `analytics` row
    newer than sentinel_synced_at is the only signal this schema actually
    supports for "needs resyncing," so that's what this uses. A hunt with
    no detections newer than its last sync and no recorded error is
    considered already up to date and excluded.
    """
    rows = conn.execute(
        f"SELECT h.id, h.title, h.source_title, h.description, "
        f"h.target_sentinel_hunt_id FROM hunts h "
        f"WHERE {_NEEDS_DEPLOY_CLAUSE}"
    ).fetchall()
    return [
        {
            "id": r["id"],
            "title": r["title"],
            "source_title": r["source_title"],
            "description": r["description"],
            "target_sentinel_hunt_id": r["target_sentinel_hunt_id"],
        }
        for r in rows
    ]


def get_sync_eligible_detections(conn, hunt_id: int, require_alignment: bool = True) -> list[dict]:
    """Detections under this hunt that have cleared enough validation to be
    pushed to Sentinel: a passing static gate and a clean 90-day backtest,
    plus (when require_alignment) a MITRE-aligned parent strategy.

    Used by both the auto-sync path (orchestrator.py, gated by
    hunt_sync_settings.mode == 'auto') and the manual "Deploy to Sentinel"
    action (POST /api/detections/hunts/{id}/deploy in main.py, which always
    passes require_alignment=False -- a human has already looked at the
    hunt before clicking deploy, so alignment status is informative to them
    rather than a hard gate). Returns dicts already shaped for
    sentinel_hunting.sync_hunt()'s `detections` param.

    At most one row per artifact_id, keeping the lowest `id` (the original
    registration). Workstream A, docs/superpowers/specs/2026-09-04-live-
    feedback-round-6-design.md -- confirmed live 2026-09-04 against prod
    hunt_id=12 (analytic ids {610,632,644} and {611,633,645}, two
    artifact_ids, three rows each, all static_gate_verdict='pass'/
    backtest_disposition='clean') that register_analytic()'s 2026-09-01
    artifact_id-idempotency fix doesn't retroactively clean up: this
    function was the one place that still fanned every pre-existing
    duplicate row out to Sentinel as its own ARM saved search (arm_safe_
    id() is deterministic per (hunt_id, analytic_id), so three distinct
    analytic_ids sharing one artifact_id always produced three distinct,
    individually-valid ARM PUTs -- the duplication was never an ARM-side
    idempotency bug, it was this query handing sync_hunt() three
    detections that were really one).

    Grouping key is `COALESCE(NULLIF(a.artifact_id, ''), 'row-' ||
    a.id::text)`, NOT a bare `DISTINCT ON (a.artifact_id)` -- confirmed
    live against this exact schema that plain DISTINCT ON collapses every
    NULL-artifact_id row down to a single survivor (Postgres DISTINCT/
    GROUP BY treat NULL as equal to NULL for grouping, unlike a `= `
    comparison or a unique index's own per-NULL-is-distinct behavior),
    which would have silently dropped every legitimate pre-artifact_id-
    era detection but the first one under a hunt. The COALESCE/NULLIF
    fallback gives every NULL/empty-artifact_id row its own unique
    per-row group key (via its own id), so those rows are never deduped
    against each other or against anything else -- only rows sharing a
    real, non-empty artifact_id collapse.
    """
    clauses = [
        "a.hunt_id = ?",
        "a.static_gate_verdict = 'pass'",
        "a.backtest_disposition = 'clean'",
    ]
    params: list = [hunt_id]
    if require_alignment:
        clauses.append("ds.mitre_alignment_status = 'aligned'")
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"SELECT DISTINCT ON (COALESCE(NULLIF(a.artifact_id, ''), 'row-' || a.id::text)) "
        f"a.id, a.name, a.description, a.kql_body, "
        f"ds.technique_id, ds.technique_name "
        f"FROM analytics a JOIN detection_strategies ds ON ds.id = a.strategy_id "
        f"WHERE {where} "
        f"ORDER BY COALESCE(NULLIF(a.artifact_id, ''), 'row-' || a.id::text), a.id",
        tuple(params),
    ).fetchall()
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "description": r["description"],
            "kql_body": r["kql_body"],
            "technique_id": r["technique_id"],
            "technique_name": r["technique_name"],
        }
        for r in rows
    ]


def get_hunt_detail(conn, hunt_id: int) -> dict | None:
    """One hunt plus every detection/query registered under it -- the
    drill-down view behind clicking a hunt in the Hunts tab."""
    row = conn.execute(
        f"SELECT {_HUNT_LIST_COLUMNS} FROM hunts h WHERE h.id = ?", (hunt_id,)
    ).fetchone()
    if not row:
        return None
    hunt = _hunt_row_to_dict(row)

    detection_rows = conn.execute(
        "SELECT a.id, a.strategy_id, ds.technique_id, ds.technique_name, ds.objective, "
        "a.artifact_id, a.name, a.description, a.kql_body, a.tune_history, "
        "a.static_gate_verdict, a.static_gate_durability, a.backtest_disposition, "
        "a.review_state, a.created_at "
        "FROM analytics a JOIN detection_strategies ds ON ds.id = a.strategy_id "
        "WHERE a.hunt_id = ? ORDER BY a.created_at ASC",
        (hunt_id,),
    ).fetchall()
    action_status = tuning_actions.get_tuning_action_status(
        conn, [r["id"] for r in detection_rows]
    )
    hunt["detections"] = [
        {
            "id": r["id"],
            "strategy_id": r["strategy_id"],
            "technique_id": r["technique_id"],
            "technique_name": r["technique_name"],
            "objective": r["objective"],
            "objective_is_fallback": objective_is_fallback(r["objective"], r["technique_name"]),
            "artifact_id": r["artifact_id"],
            "name": r["name"],
            "description": r["description"],
            "kql_body": r["kql_body"],
            "static_gate_verdict": r["static_gate_verdict"],
            "static_gate_durability": (
                float(r["static_gate_durability"])
                if r["static_gate_durability"] is not None else None
            ),
            "backtest_disposition": r["backtest_disposition"],
            "review_state": r["review_state"],
            "created_at": r["created_at"],
            "tuning_suggestion": tuning_actions.suggestion_view(
                r["tune_history"], action_status.get(r["id"])
            ),
        }
        for r in detection_rows
    ]
    return hunt
