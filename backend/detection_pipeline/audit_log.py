"""Admin-only cross-pipeline audit view: every check this app has actually
run -- AI-generated detection gate/control-probe results, Sentinel hunt
sync attempts, Sentinel-native hunt query tests, and Sentinel Analytics
Rule tests -- combined into one paginated, filterable list.

Deliberately covers what no single existing tab does: DetectionsCatalogPanel
filters by review_state, not gate/probe outcome; DispositionAlertsPanel only
covers stage-9 rot on already-approved analytics; SentinelHuntsPanel shows a
query's own test result only when you expand that one row. None of them
answer "how many things have actually failed a check, across the whole
pipeline, right now" -- this does.

Only items that have actually been checked at least once are included --
a detection still pending static_gate, or a hunt that's never attempted a
Sentinel sync, is neither passing nor failing, it's simply not audited yet,
and including it would swamp the failing/passing counts with noise.
"""

from __future__ import annotations

import json
from datetime import datetime

_VALID_OUTCOMES = ("failing", "passing")
# 'unannotated' (default, the actionable queue) or 'all' aren't real
# audit_annotations.status values -- they're list_audit_entries()'s own
# filter vocabulary, handled separately from this allowlist.
_VALID_ANNOTATION_STATUSES = ("acknowledged", "not_applicable", "fixed")
_VALID_STATUS_FILTERS = _VALID_ANNOTATION_STATUSES + ("unannotated", "all")
# Matches _BASE_QUERY's four UNION ALL arms exactly -- the only values
# record_annotation()/clear_annotation() may ever see as `source`, since
# an annotation on any other value could never join back onto a real row.
_VALID_SOURCES = ("detection", "hunt_sync", "sentinel_query", "analytics_rule")


def _parse_jsonb(value):
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return None


# One CTE per failure surface, normalized to the same columns so they can be
# UNION ALL'd and paginated together. `is_failing` is computed once here
# (not re-derived per-row in Python) so the WHERE/ORDER BY below can filter
# on it directly.
#
# Deliberately avoids the jsonb `?` (key-exists) operator: pgcompat's query
# translator (see pgcompat.translate()) rewrites every bare `?` outside
# quotes into a `%s` bind placeholder for psycopg, which would collide with
# the jsonb operator's own `?` and misalign parameter binding. `->>'error'
# IS NOT NULL` is the equivalent, translate()-safe check.
_BASE_QUERY = """
WITH combined AS (
    SELECT
        'detection'      AS source,
        a.id             AS source_id,
        COALESCE(a.name, 'Unnamed — ' || ds.technique_id) AS title,
        'static_gate/control_probe' AS check_type,
        CASE
            WHEN ann.status IS NOT NULL THEN false
            WHEN a.static_gate_verdict = 'reject' THEN true
            WHEN a.control_probe_result->>'error' IS NOT NULL THEN true
            ELSE false
        END              AS is_failing,
        CASE
            WHEN a.static_gate_verdict = 'reject'
                THEN 'Static gate rejected: ' || COALESCE(a.static_gate_findings::text, '')
            WHEN a.control_probe_result->>'error' IS NOT NULL
                THEN a.control_probe_result->>'error'
            ELSE 'Passed static gate and control probe'
        END              AS detail,
        a.created_at     AS checked_at,
        ann.status       AS annotation_status,
        ann.notes        AS annotation_notes,
        ann.updated_by   AS annotation_updated_by,
        ann.updated_at   AS annotation_updated_at
    FROM analytics a
    JOIN detection_strategies ds ON ds.id = a.strategy_id
    LEFT JOIN audit_annotations ann ON ann.source = 'detection' AND ann.source_id = a.id
    WHERE a.static_gate_verdict IS NOT NULL

    UNION ALL

    SELECT
        'hunt_sync'       AS source,
        h.id              AS source_id,
        h.title           AS title,
        'sentinel_sync'   AS check_type,
        CASE WHEN ann.status IS NOT NULL THEN false ELSE (h.sentinel_sync_error IS NOT NULL) END AS is_failing,
        COALESCE(h.sentinel_sync_error, 'Synced to Sentinel successfully') AS detail,
        COALESCE(h.sentinel_synced_at, h.updated_at) AS checked_at,
        ann.status       AS annotation_status,
        ann.notes        AS annotation_notes,
        ann.updated_by   AS annotation_updated_by,
        ann.updated_at   AS annotation_updated_at
    FROM hunts h
    LEFT JOIN audit_annotations ann ON ann.source = 'hunt_sync' AND ann.source_id = h.id
    WHERE h.sentinel_hunt_id IS NOT NULL OR h.sentinel_sync_error IS NOT NULL

    UNION ALL

    SELECT
        'sentinel_query'  AS source,
        q.id              AS source_id,
        q.display_name    AS title,
        'gate/control_probe' AS check_type,
        CASE
            WHEN ann.status IS NOT NULL THEN false
            WHEN q.control_probe_result->>'gate_verdict' = 'reject' THEN true
            WHEN q.control_probe_result->>'error' IS NOT NULL THEN true
            ELSE false
        END               AS is_failing,
        CASE
            WHEN q.control_probe_result->>'gate_verdict' = 'reject'
                THEN 'Static gate rejected: ' || COALESCE((q.control_probe_result->'gate_findings')::text, '')
            WHEN q.control_probe_result->>'error' IS NOT NULL
                THEN q.control_probe_result->>'error'
            ELSE 'Passed gate and control probe'
        END               AS detail,
        q.last_tested_at  AS checked_at,
        ann.status        AS annotation_status,
        ann.notes         AS annotation_notes,
        ann.updated_by    AS annotation_updated_by,
        ann.updated_at    AS annotation_updated_at
    FROM sentinel_hunt_queries q
    LEFT JOIN audit_annotations ann ON ann.source = 'sentinel_query' AND ann.source_id = q.id
    WHERE q.control_probe_result IS NOT NULL

    UNION ALL

    SELECT
        'analytics_rule'   AS source,
        r.id              AS source_id,
        r.display_name    AS title,
        'gate/control_probe' AS check_type,
        CASE
            WHEN ann.status IS NOT NULL THEN false
            WHEN r.control_probe_result->>'gate_verdict' = 'reject' THEN true
            WHEN r.control_probe_result->>'error' IS NOT NULL THEN true
            ELSE false
        END               AS is_failing,
        CASE
            WHEN r.control_probe_result->>'gate_verdict' = 'reject'
                THEN 'Static gate rejected: ' || COALESCE((r.control_probe_result->'gate_findings')::text, '')
            WHEN r.control_probe_result->>'error' IS NOT NULL
                THEN r.control_probe_result->>'error'
            ELSE 'Passed gate and control probe'
        END               AS detail,
        r.last_tested_at  AS checked_at,
        ann.status        AS annotation_status,
        ann.notes         AS annotation_notes,
        ann.updated_by    AS annotation_updated_by,
        ann.updated_at    AS annotation_updated_at
    FROM sentinel_analytics_rules r
    LEFT JOIN audit_annotations ann ON ann.source = 'analytics_rule' AND ann.source_id = r.id
    WHERE r.control_probe_result IS NOT NULL
)
"""


_ITEM_COLUMNS = (
    "source, source_id, title, check_type, is_failing, detail, checked_at, "
    "annotation_status, annotation_notes, annotation_updated_by, annotation_updated_at"
)


def _row_to_item(r) -> dict:
    return {
        "source":                r["source"],
        "source_id":             r["source_id"],
        "title":                 r["title"],
        "check_type":            r["check_type"],
        "is_failing":            r["is_failing"],
        "detail":                r["detail"],
        "checked_at":            r["checked_at"],
        "annotation_status":     r["annotation_status"],
        "annotation_notes":      r["annotation_notes"],
        "annotation_updated_by": r["annotation_updated_by"],
        "annotation_updated_at": r["annotation_updated_at"],
    }


def list_audit_entries(
    conn, outcome: str | None = None, category: str | None = None,
    status: str | None = None, since: str | None = None, until: str | None = None,
    limit: int = 50, offset: int = 0,
) -> dict:
    """Paginated, optionally outcome/category/status-filtered list across
    every checked detection/hunt-sync/sentinel-query row. outcome:
    'failing', 'passing', or None for all checked items. status:
    'unannotated' (default -- the actionable queue), one of
    _VALID_ANNOTATION_STATUSES, 'all' (no status filter), or None (treated
    as 'unannotated' -- matches this endpoint's pre-annotations behavior,
    since every row was implicitly unannotated before this feature
    existed).

    category isn't a stored column -- it's derived from `detail` text by
    _categorize(), the same helper get_audit_failure_breakdown() uses for
    the bubbles, so the two views can never disagree about what a category
    means. That means this can't be a SQL WHERE clause the way outcome is:
    fetch the failing set (categories only ever exist among failing rows,
    so a category filter implies outcome='failing' regardless of what was
    passed), categorize each row in Python, filter, then paginate the
    filtered list. Fine at this app's actual data volume -- the FAILURE
    BREAKDOWN bubbles' own categories top out in the low hundreds, nowhere
    near a size where Python-side filtering costs anything that matters.
    Passing `since`/`until` (None preserves today's all-time behavior
    exactly -- no default-view regression) adds `checked_at >= ?
    [AND checked_at <= ?]`. This is deliberately a distribution of
    last-checked-when results, not a real historical pass/fail curve --
    see get_audit_trend()'s own docstring and the design doc's UI-honesty
    requirement for why that distinction matters here.
    """
    status_clause = ""
    status_params: list = []
    if status is None or status == "unannotated":
        status_clause = "annotation_status IS NULL"
    elif status in _VALID_ANNOTATION_STATUSES:
        status_clause = "annotation_status = ?"
        status_params.append(status)
    # else 'all' (or any unrecognized value -- callers validate against
    # _VALID_STATUS_FILTERS before this point): no status filter at all.

    time_clause, time_params = _time_clause(since, until)

    if category:
        where_clauses = ["is_failing"]
        if status_clause:
            where_clauses.append(status_clause)
        where_clauses.extend(time_clause)
        rows = conn.execute(
            f"{_BASE_QUERY} SELECT {_ITEM_COLUMNS} "
            f"FROM combined WHERE {' AND '.join(where_clauses)} ORDER BY checked_at DESC NULLS LAST",
            tuple(status_params) + tuple(time_params),
        ).fetchall()
        matched = [r for r in rows if category in _categorize(r["detail"])]
        total = len(matched)
        items = [_row_to_item(r) for r in matched[offset:offset + limit]]
        return {"total": total, "items": items}

    where_clauses = []
    params: list = []
    if outcome in _VALID_OUTCOMES:
        where_clauses.append("is_failing = ?")
        params.append(outcome == "failing")
    if status_clause:
        where_clauses.append(status_clause)
        params.extend(status_params)
    where_clauses.extend(time_clause)
    params.extend(time_params)
    where = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    total = conn.execute(
        f"{_BASE_QUERY} SELECT COUNT(*) FROM combined {where}", tuple(params)
    ).fetchone()[0]

    rows = conn.execute(
        f"{_BASE_QUERY} SELECT {_ITEM_COLUMNS} "
        f"FROM combined {where} ORDER BY checked_at DESC NULLS LAST LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset),
    ).fetchall()

    items = [_row_to_item(r) for r in rows]
    return {"total": total, "items": items}


def record_annotation(conn, source: str, source_id: int, status: str,
                      notes: str, updated_by: str) -> dict:
    """Set (or replace) the annotation on one audit row. `source` must be
    one of _VALID_SOURCES -- an unrecognized source could never join back
    onto a real row in _BASE_QUERY, so it's rejected here rather than
    silently creating an orphan annotation nothing will ever surface.
    Callers (main.py) should already have validated both `source` and
    `status` and turned a bad value into a 400 before reaching here; this
    check is defense in depth, not the only gate."""
    if source not in _VALID_SOURCES:
        raise ValueError(f"source must be one of {_VALID_SOURCES}, got {source!r}")
    if status not in _VALID_ANNOTATION_STATUSES:
        raise ValueError(f"status must be one of {_VALID_ANNOTATION_STATUSES}, got {status!r}")
    conn.execute(
        "INSERT INTO audit_annotations (source, source_id, status, notes, updated_by, updated_at) "
        "VALUES (?, ?, ?, ?, ?, now()) "
        "ON CONFLICT (source, source_id) DO UPDATE SET "
        "status = ?, notes = ?, updated_by = ?, updated_at = now()",
        (source, source_id, status, notes, updated_by, status, notes, updated_by),
    )
    conn.commit()
    return {"source": source, "source_id": source_id, "status": status, "notes": notes}


def clear_annotation(conn, source: str, source_id: int) -> None:
    """Remove an annotation, restoring the row to whatever its real check
    outcome says. A no-op (not an error) if no annotation exists."""
    conn.execute(
        "DELETE FROM audit_annotations WHERE source = ? AND source_id = ?",
        (source, source_id),
    )
    conn.commit()


def _time_clause(since: str | None, until: str | None) -> tuple[list[str], list[str]]:
    """WHERE-clause fragments + bind params for an optional checked_at
    window, shared by every combined-CTE query below. Both None (the
    default, all-time) contributes nothing -- exact pre-window behavior,
    no default-view regression."""
    clauses: list[str] = []
    params: list[str] = []
    if since is not None:
        clauses.append("checked_at >= ?")
        params.append(since)
    if until is not None:
        clauses.append("checked_at <= ?")
        params.append(until)
    return clauses, params


def get_audit_summary(conn, since: str | None = None, until: str | None = None) -> dict:
    """Failing/passing counts across the whole combined set -- backs the
    tab's header counts without fetching every row."""
    time_clause, time_params = _time_clause(since, until)
    where = f"WHERE {' AND '.join(time_clause)}" if time_clause else ""
    row = conn.execute(
        f"{_BASE_QUERY} SELECT "
        f"COUNT(*) FILTER (WHERE is_failing) AS failing, "
        f"COUNT(*) FILTER (WHERE NOT is_failing) AS passing "
        f"FROM combined {where}",
        tuple(time_params),
    ).fetchone()
    return {"failing": row["failing"] or 0, "passing": row["passing"] or 0}


_GATE_REJECT_PREFIX = "Static gate rejected:"


def _categorize(detail: str | None) -> list[str]:
    """Map one failing row's `detail` text to the category label(s) it
    contributes -- shared by get_audit_failure_breakdown() (the bubbles)
    and list_audit_entries()'s category filter, so the two views can never
    disagree about what a category means.

    A static-gate rejection (recognizable by its 'Static gate rejected:
    [...]' prefix -- the same JSON-findings-array shape static_gate.py's
    own to_row() produces) maps to one category per finding code: a row
    can carry multiple findings (e.g. both enumerated_literals and
    memory_risk on the same rule), and each is a real, independent reason
    a reviewer would want its own count for. Everything else -- a Sentinel/
    ARM sync error, a control probe's own error text -- maps to exactly one
    category keyed by its own message, already short and specific, rather
    than a taxonomy this module would have to guess at ahead of time. An
    empty/passing detail maps to no category at all.
    """
    detail = (detail or "").strip()
    if not detail:
        return []
    if detail.startswith(_GATE_REJECT_PREFIX):
        findings = _parse_jsonb(detail[len(_GATE_REJECT_PREFIX):].strip()) or []
        codes = [f.get("code") for f in findings if isinstance(f, dict) and f.get("code")]
        if not codes:
            return ["Static gate rejected"]
        return [f"Static gate: {code}" for code in codes]
    return [detail[:120]]


def get_audit_failure_breakdown(conn, since: str | None = None, until: str | None = None) -> list[dict]:
    """Groups every currently-failing audited item (the same 'combined' set
    list_audit_entries() serves) into named categories with counts, for the
    Audit Log tab's summary bubbles. See _categorize() for how a row maps
    to its category/categories."""
    time_clause, time_params = _time_clause(since, until)
    where = " AND ".join(["is_failing"] + time_clause)
    rows = conn.execute(
        f"{_BASE_QUERY} SELECT detail FROM combined WHERE {where}", tuple(time_params),
    ).fetchall()

    counts: dict[str, int] = {}
    for row in rows:
        for category in _categorize(row["detail"]):
            counts[category] = counts.get(category, 0) + 1

    return [
        {"category": category, "count": count}
        for category, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


# A window spanning more than this many days buckets by week instead of by
# day -- a judgment call on readability (90 daily bars is a lot of noise,
# 13 weekly bars reads cleanly), not derived from anything. Document here
# since it's the one place this threshold is decided.
_TREND_WEEKLY_BUCKET_THRESHOLD_DAYS = 30


def get_audit_trend(
    conn, since: str | None, until: str | None, bucket: str | None = None,
) -> list[dict]:
    """Buckets every checked item (the same 'combined' set list_audit_
    entries() serves) by its own checked_at, into {date, failing, passing}
    rows -- Workstream B's "rolling window trend."

    This is NOT a real historical pass/fail curve and must be labeled as
    such wherever it's rendered (see the design doc's UI-honesty
    requirement): every source table in _BASE_QUERY stores only the
    LATEST check result per item, not a log of past checks. For the
    'detection' source specifically, checked_at is really created_at
    (analytics has no UPDATE grant -- a row's gate/probe result is fixed
    forever at creation time), so a bucket's counts mean "how many
    detections were generated in this period and what did their one-time
    check say," not "how many failed on this day." The other three
    sources (hunt_sync, sentinel_query, analytics_rule) do have a genuine
    last-checked-at that updates on re-test, but this function does not
    distinguish sources in its bucketing -- it answers "results by
    last-checked date" across the whole combined set, uniformly.

    `bucket`: 'day' or 'week', explicit override. When None, chosen from
    the window span -- day for anything <= _TREND_WEEKLY_BUCKET_THRESHOLD_
    DAYS, week otherwise. A None/None (all-time) window always buckets by
    week, since day-granularity over an unbounded span would be unusable.
    """
    if bucket not in ("day", "week", None):
        raise ValueError(f"bucket must be 'day', 'week', or None, got {bucket!r}")
    if bucket is None:
        if since is None or until is None:
            bucket = "week"
        else:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            until_dt = datetime.fromisoformat(until.replace("Z", "+00:00"))
            span_days = (until_dt - since_dt).days
            bucket = "day" if span_days <= _TREND_WEEKLY_BUCKET_THRESHOLD_DAYS else "week"

    time_clause, time_params = _time_clause(since, until)
    where = f"WHERE {' AND '.join(time_clause)}" if time_clause else ""
    rows = conn.execute(
        f"{_BASE_QUERY} SELECT date_trunc(?, checked_at) AS bucket, "
        f"COUNT(*) FILTER (WHERE is_failing) AS failing, "
        f"COUNT(*) FILTER (WHERE NOT is_failing) AS passing "
        f"FROM combined {where} "
        f"GROUP BY bucket ORDER BY bucket",
        (bucket,) + tuple(time_params),
    ).fetchall()
    return [
        {"date": r["bucket"], "failing": r["failing"] or 0, "passing": r["passing"] or 0}
        for r in rows
    ]
