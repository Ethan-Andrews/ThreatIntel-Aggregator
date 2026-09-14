import json
import re
import os
import logging
from collections import defaultdict

from pgcompat import connect as _pg_connect, close_pool  # noqa: F401

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
_logger = logging.getLogger("app")

# Schema is applied out of band by pg_schema.sql, never by the application.
REQUIRED_TABLES = [
    "entries", "sources", "stack_items", "users", "ioc_ledger",
    "runzero_assets", "runzero_vulns", "runzero_matches",
    "runzero_sync_log", "feed_fetch_log",
    # Added by the exposure remediation tracking feature.
    "exposure_items", "exposure_audit_log",
]


class DbReadinessError(RuntimeError):
    """Raised when Postgres is unreachable or the schema is incomplete."""
    pass


def _connect_db(db_path=None):
    """Check out a pooled Postgres connection.

    db_path is accepted and ignored so the existing call sites keep working
    unchanged. See pgcompat.py for the placeholder translation and the
    sqlite3-shaped row/cursor facade.
    """
    return _pg_connect()


def ensure_db_ready(db_path=None):
    """Verify the database is reachable. Raises DbReadinessError if not."""
    try:
        conn = _connect_db()
    except Exception as exc:
        raise DbReadinessError(f"cannot reach Postgres: {exc}") from exc
    try:
        conn.execute("SELECT 1").fetchone()
    except Exception as exc:
        raise DbReadinessError(f"Postgres connectivity check failed: {exc}") from exc
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Durability shims.
#
# Postgres owns durability now. These three functions previously copied the
# SQLite file to Azure Files or Blob Storage. They are kept as no-ops so the
# ~20 existing call sites keep working; deleting those call sites is a
# follow-up cleanup commit, deliberately not bundled with the engine swap.
# ---------------------------------------------------------------------------

def prepare_runtime_db(runtime_db_path=None, persist_db_path=None):
    """No-op. There is no runtime database file to restore."""
    return False


def persist_runtime_db(runtime_db_path=None, persist_db_path=None, force=False):
    """No-op. Postgres handles durability."""
    return True


def check_persist_mount() -> bool:
    """No-op. There is no persistence mount; report healthy."""
    return True


TIER_DEFAULT_SCORES = {1: 80, 2: 65, 3: 50}
DATE_WINDOW_HOURS = {
    "24h": 24,
    "48h": 48,
    "7d": 7 * 24,
    "30d": 30 * 24,
    "90d": 90 * 24,
    "all": None,
}


def init_db():
    """Verify the Postgres schema is present.

    Schema changes are applied out of band by pg_schema.sql. The application
    deliberately does not create or alter tables: an app that can DDL its own
    schema is an app that can corrupt it during a rolling revision.
    """
    conn = _connect_db()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_name = ANY(?)",
            (REQUIRED_TABLES,),
        ).fetchone()
        found = row["n"]
        if found != len(REQUIRED_TABLES):
            present = conn.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = current_schema() AND table_name = ANY(?)",
                (REQUIRED_TABLES,),
            ).fetchall()
            names = {r["table_name"] for r in present}
            missing = [t for t in REQUIRED_TABLES if t not in names]
            raise DbReadinessError(
                f"schema incomplete: {found}/{len(REQUIRED_TABLES)} tables present, "
                f"missing {missing}. Apply pg_schema.sql before starting the app."
            )
        _logger.info("SCHEMA_OK tables=%d", found)
    finally:
        conn.close()

    # Retained from the SQLite init path: this is a data backfill, not DDL, so
    # it still belongs at startup.
    run_ioc_backfill()


def seed_sources(feed_list):
    conn = _connect_db()
    for feed in feed_list:
        tier  = feed.get("tier", 3)
        score = TIER_DEFAULT_SCORES.get(tier, 50)
        conn.execute(
            "INSERT INTO sources (name, score, tier) VALUES (?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET tier = excluded.tier",
            (feed["name"], score, tier)
        )
    conn.commit()
    conn.close()
    persist_runtime_db()


def get_sources():
    conn = _connect_db()
    rows = conn.execute(
        "SELECT name, score, tier FROM sources ORDER BY tier ASC, score DESC, name ASC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_source_score(name, score):
    score = max(0, min(100, score))
    conn = _connect_db()
    conn.execute("UPDATE sources SET score = ? WHERE name = ?", (score, name))
    conn.commit()
    conn.close()
    persist_runtime_db()


# ── Stack items ───────────────────────────────────────────────────────────────

def get_stack_items() -> list:
    """Return all stack items grouped by category."""
    conn = _connect_db()
    rows = conn.execute(
        "SELECT id, category, name, keywords FROM stack_items ORDER BY category, name"
    ).fetchall()
    conn.close()
    items = [dict(r) for r in rows]
    grouped = {}
    for item in items:
        cat = item["category"]
        if cat not in grouped:
            grouped[cat] = []
        grouped[cat].append({
            "id":       item["id"],
            "name":     item["name"],
            "keywords": json.loads(item["keywords"]),
        })
    return [{"category": cat, "items": grp} for cat, grp in grouped.items()]


def add_stack_item(category: str, name: str, keywords: list) -> int:
    """Add a stack item. Raises ValueError on duplicate name+category."""
    conn = _connect_db()
    existing = conn.execute(
        "SELECT id FROM stack_items WHERE category = ? AND name = ?", (category, name)
    ).fetchone()
    if existing:
        conn.close()
        raise ValueError(f"Stack item '{name}' already exists in category '{category}'")
    # Postgres has no lastrowid; RETURNING is the equivalent and is atomic.
    cur = conn.execute(
        "INSERT INTO stack_items (category, name, keywords) VALUES (?, ?, ?) "
        "RETURNING id",
        (category, name, json.dumps(keywords)),
    )
    new_id = cur.fetchone()["id"]
    conn.commit()
    conn.close()
    persist_runtime_db()
    return new_id


def delete_stack_item(item_id: int) -> bool:
    """Delete stack item by id. Returns True if deleted, False if not found."""
    conn = _connect_db()
    cur = conn.execute("DELETE FROM stack_items WHERE id = ?", (item_id,))
    deleted = cur.rowcount > 0
    conn.commit()
    conn.close()
    if deleted:
        persist_runtime_db()
    return deleted


def get_all_stack_items_flat() -> list:
    """Return all stack items as a flat list of dicts with parsed keywords."""
    conn = _connect_db()
    rows = conn.execute("SELECT id, category, name, keywords FROM stack_items").fetchall()
    conn.close()
    return [
        {"id": r["id"], "category": r["category"], "name": r["name"],
         "keywords": json.loads(r["keywords"])}
        for r in rows
    ]


def match_entry_against_stack(entry: dict, stack_items: list) -> list:
    """Return list of matched stack item names for an entry.

    Matching order:
    1. Tag match: check entry tags JSON for values against each keyword.
    2. Keyword fallback: search title + ai_summary text for each keyword.
    Both comparisons are case-insensitive.
    """
    if not stack_items:
        return []

    try:
        tags_raw = entry.get("tags", "{}")
        tags = json.loads(tags_raw) if isinstance(tags_raw, str) else (tags_raw or {})
        tag_values = [str(v).lower() for v in tags.values() if v]
    except Exception:
        tag_values = []

    text = ((entry.get("title") or "") + " " + (entry.get("ai_summary") or "")).lower()

    matched = []
    for item in stack_items:
        found = False
        for kw in item["keywords"]:
            kw_lower = kw.lower()
            if kw_lower in tag_values:
                found = True
                break
            if kw_lower in text:
                found = True
                break
        if found:
            matched.append(item["name"])
    return matched


def write_stack_match(entry_hash: str, matched_items: list, priority_score: float):
    """Persist stack match results and updated priority score for an entry."""
    conn = _connect_db()
    conn.execute(
        "UPDATE entries SET stack_match = ?, stack_matched_items = ?, priority_score = ? WHERE hash = ?",
        (1 if matched_items else 0, json.dumps(matched_items), priority_score, entry_hash),
    )
    conn.commit()
    conn.close()
    persist_runtime_db()


def get_entry_by_hash(hash):
    conn = _connect_db()
    row = conn.execute(
        "SELECT hash, title, summary FROM entries WHERE hash = ?", (hash,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_entries_by_hashes(hashes):
    if not hashes:
        return []
    conn = _connect_db()
    placeholders = ",".join("?" * len(hashes))
    rows = conn.execute(
        "SELECT hash, source, title, summary, COALESCE(content, '') AS content, link FROM entries WHERE hash IN (" + placeholders + ")",
        list(hashes)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_triaged_for_retriage(count, order="newest"):
    order_sql = "DESC" if order == "newest" else "ASC"
    conn = _connect_db()
    rows = conn.execute(
        "SELECT hash, source, title, summary, COALESCE(content, '') AS content, link FROM entries "
        "WHERE triaged=1 AND archived=0 AND is_duplicate=0 "
        "ORDER BY ingested " + order_sql + " LIMIT ?",
        (count,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_failed_triage(batch_size=100):
    """Return entries that were triaged but have Unknown severity and no TTPs (failed AI triage)."""
    conn = _connect_db()
    rows = conn.execute(
        "SELECT hash, source, title, summary, COALESCE(content, '') AS content, link FROM entries "
        "WHERE triaged=1 AND severity='Unknown' AND (ttps='' OR ttps IS NULL) "
        "AND archived=0 AND is_duplicate=0 "
        "ORDER BY ingested DESC LIMIT ?",
        (batch_size,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_pending_triage(batch_size=20):
    conn = _connect_db()
    rows = conn.execute(
        "SELECT hash, source, title, summary, COALESCE(content, '') AS content, link FROM entries "
        "WHERE triaged = 0 AND archived = 0 "
        "ORDER BY ingested ASC LIMIT ?",
        (batch_size,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def apply_triage(hash, severity, ttps, ai_summary, tags="{}", iocs="{}", persist=True):
    conn = _connect_db()
    try:
        row = conn.execute(
            "SELECT ingested FROM entries WHERE hash = ?", (hash,)
        ).fetchone()
        ingested = row[0] if row else ""
        conn.execute(
            "UPDATE entries "
            "SET triaged=1, severity=?, ttps=?, ai_summary=?, tags=?, iocs=?, enriched=0 "
            "WHERE hash=?",
            (severity, ttps, ai_summary, tags, iocs, hash),
        )
        conn.commit()
    finally:
        conn.close()
    try:
        upsert_ioc_ledger(json.loads(iocs), hash, ingested or "")
    except Exception:
        _logger.warning("IOC_LEDGER_UPDATE_FAILED hash=%s", hash)
    if persist:
        persist_runtime_db()


def _build_where(sources=None, severities=None, tag_filters=None,
                 ttps=None, search=None, include_duplicates=False, ioc_filters=None,
                 date_window="24h"):
    """Return (where_clause, params) for filtering active non-archived entries."""
    clauses = ["archived = 0"]
    params  = []

    if not include_duplicates:
        clauses.append("is_duplicate = 0")

    hours = DATE_WINDOW_HOURS.get(date_window)
    if hours is not None:  # None means "all" — no date restriction
        # Use ingested for the window; published can have Z-suffix ISO dates that
        # SQLite's datetime() does not parse, so ingested (CURRENT_TIMESTAMP format)
        # is always safe and reflects when data entered the system.
        clauses.append("ingested >= to_char(now() AT TIME ZONE 'utc' + (?)::interval, 'YYYY-MM-DD HH24:MI:SS')")
        params.append(f"-{hours} hours")

    if sources:
        placeholders = ",".join("?" * len(sources))
        clauses.append("source IN (" + placeholders + ")")
        params.extend(sources)

    if severities:
        placeholders = ",".join("?" * len(severities))
        clauses.append("severity IN (" + placeholders + ")")
        params.extend(severities)

    if search:
        clauses.append("(title LIKE ? OR summary LIKE ?)")
        params.extend(["%" + search + "%", "%" + search + "%"])

    if tag_filters:
        by_cat = defaultdict(list)
        for cat, val in tag_filters:
            by_cat[cat].append(val)
        for cat, values in by_cat.items():
            cat_clauses = ["tags LIKE ?" for _ in values]
            clauses.append("(" + " OR ".join(cat_clauses) + ")")
            params.extend(["%" + v + "%" for v in values])

    if ttps:
        ttp_clauses = []
        for ttp in ttps:
            ttp_clauses.append("(ttps = ? OR ttps LIKE ? OR ttps LIKE ? OR ttps LIKE ?)")
            params.extend([ttp, ttp + ",%", "%," + ttp, "%" + ttp + ".%"])
        clauses.append("(" + " OR ".join(ttp_clauses) + ")")

    if ioc_filters:
        by_cat = defaultdict(list)
        for cat, val in ioc_filters:
            by_cat[cat].append(val)
        for cat, values in by_cat.items():
            cat_clauses = ["iocs LIKE ?" for _ in values]
            clauses.append("(" + " OR ".join(cat_clauses) + ")")
            params.extend(["%" + v + "%" for v in values])

    return " AND ".join(clauses), params


_SORT_COL_MAP = {
    "ingested":       "ingested",
    "published":      "COALESCE(NULLIF(published, ''), ingested)",
    "priority_score": "COALESCE(priority_score, 0)",
    "source":         "source",
}


def get_entries(sources=None, severities=None, tag_filters=None,
                ttps=None, search=None, limit=100, offset=0,
                include_duplicates=False, ioc_filters=None, date_window="24h",
                sort_by="ingested", sort_dir="desc"):
    where, params = _build_where(
        sources=sources, severities=severities, tag_filters=tag_filters,
        ttps=ttps, search=search, include_duplicates=include_duplicates,
        ioc_filters=ioc_filters, date_window=date_window,
    )
    col       = _SORT_COL_MAP.get(sort_by, "ingested")
    direction = "ASC" if sort_dir == "asc" else "DESC"
    conn = _connect_db()
    q = f"""
        WITH ranked AS (
            SELECT e.*,
                (SELECT MIN(confidence)
                 FROM runzero_matches rm WHERE rm.entry_hash = e.hash) AS runzero_confidence,
                (SELECT COUNT(DISTINCT asset_id)
                 FROM runzero_matches rm2 WHERE rm2.entry_hash = e.hash) AS runzero_asset_count,
                ROW_NUMBER() OVER (
                    PARTITION BY COALESCE(group_id, hash)
                    ORDER BY
                        CASE severity
                            WHEN 'Critical'      THEN 0
                            WHEN 'High'          THEN 1
                            WHEN 'Medium'        THEN 2
                            WHEN 'Low'           THEN 3
                            WHEN 'Informational' THEN 4
                            ELSE 5
                        END,
                        COALESCE(priority_score, 0) DESC
                ) AS rn,
                COUNT(*) OVER (
                    PARTITION BY COALESCE(group_id, hash)
                ) - 1 AS duplicate_count
            FROM entries e
            WHERE {where}
        )
        SELECT * FROM ranked WHERE rn = 1
        ORDER BY {col} {direction}
        LIMIT ? OFFSET ?
    """
    rows = conn.execute(q, params + [limit, offset]).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_entries(sources=None, severities=None, tag_filters=None,
                  ttps=None, search=None, include_duplicates=False, ioc_filters=None,
                  date_window="24h"):
    where, params = _build_where(
        sources=sources, severities=severities, tag_filters=tag_filters,
        ttps=ttps, search=search, include_duplicates=include_duplicates,
        ioc_filters=ioc_filters, date_window=date_window,
    )
    conn = _connect_db()
    q = f"""
        SELECT COUNT(*) FROM (
            SELECT ROW_NUMBER() OVER (
                PARTITION BY COALESCE(group_id, hash)
                ORDER BY
                    CASE severity
                        WHEN 'Critical'      THEN 0
                        WHEN 'High'          THEN 1
                        WHEN 'Medium'        THEN 2
                        WHEN 'Low'           THEN 3
                        WHEN 'Informational' THEN 4
                        ELSE 5
                    END,
                    COALESCE(priority_score, 0) DESC
            ) AS rn
            FROM entries
            WHERE {where}
        ) WHERE rn = 1
    """
    row = conn.execute(q, params).fetchone()
    conn.close()
    return row[0]


def get_entry_group(entry_hash: str) -> list:
    """Return all entries sharing the same group_id as `entry_hash`, canonical-first."""
    conn = _connect_db()
    row = conn.execute(
        "SELECT group_id FROM entries WHERE hash = ?", (entry_hash,)
    ).fetchone()
    if not row or not row["group_id"]:
        conn.close()
        return []
    gid = row["group_id"]
    rows = conn.execute(
        """SELECT hash, source, title, published, link, severity,
                  COALESCE(priority_score, 0) AS score
           FROM entries
           WHERE group_id = ?
           ORDER BY
               CASE severity
                   WHEN 'Critical'      THEN 0
                   WHEN 'High'          THEN 1
                   WHEN 'Medium'        THEN 2
                   WHEN 'Low'           THEN 3
                   WHEN 'Informational' THEN 4
                   ELSE 5
               END,
               COALESCE(priority_score, 0) DESC""",
        (gid,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Archival ──────────────────────────────────────────────────────────────────

def archive_old_entries(days):
    """Mark entries older than `days` days as archived. Returns rows affected."""
    conn = _connect_db()
    cur  = conn.execute(
        "UPDATE entries SET archived=1, archived_at=to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS') "
        "WHERE archived=0 AND ingested < to_char(now() AT TIME ZONE 'utc' + (?)::interval, 'YYYY-MM-DD HH24:MI:SS')",
        (f"-{days} days",)
    )
    count = cur.rowcount
    conn.commit()
    conn.close()
    if count:
        persist_runtime_db()
    return count


def purge_archived_entries():
    """Hard-delete all archived entries. Returns rows deleted."""
    conn  = _connect_db()
    cur   = conn.execute("DELETE FROM entries WHERE archived=1")
    count = cur.rowcount
    conn.commit()
    conn.close()
    if count:
        persist_runtime_db()
    return count


def get_archive_stats():
    conn = _connect_db()
    row  = conn.execute("""
        SELECT
            SUM(CASE WHEN archived     = 1 THEN 1 ELSE 0 END) AS archived_count,
            SUM(CASE WHEN is_duplicate = 1 AND archived = 0 THEN 1 ELSE 0 END) AS duplicate_count,
            MIN(CASE WHEN archived = 0 AND is_duplicate = 0 THEN ingested END) AS oldest_active,
            COUNT(*) AS total_all
        FROM entries
    """).fetchone()
    conn.close()
    return {
        "archived_count":  row[0] or 0,
        "duplicate_count": row[1] or 0,
        "oldest_active":   row[2],
        "total_all":       row[3] or 0,
    }


# ── Cross-feed CVE deduplication ──────────────────────────────────────────────

def deduplicate_cves():
    """
    Scan non-archived, non-duplicate entries whose titles contain a CVE ID.
    The first-seen entry per CVE becomes canonical; later entries from other
    sources are marked is_duplicate=1 and point to the canonical hash.
    Returns the number of entries newly marked as duplicates.
    """
    conn = _connect_db()
    rows = conn.execute(
        "SELECT hash, title FROM entries "
        "WHERE is_duplicate = 0 AND archived = 0 "
        "AND (title LIKE '%CVE-%' OR title LIKE '%cve-%') "
        "ORDER BY ingested ASC"
    ).fetchall()

    cve_to_canonical = {}   # CVE-ID (uppercase) -> canonical hash
    to_mark = []            # (hash_to_mark, canonical_hash)

    for row in rows:
        cves = _CVE_RE.findall(row["title"] or "")
        marked = False
        for cve in cves:
            cve_key = cve.upper()
            if cve_key in cve_to_canonical:
                if not marked:
                    to_mark.append((row["hash"], cve_to_canonical[cve_key]))
                    marked = True
            else:
                cve_to_canonical[cve_key] = row["hash"]

    if not to_mark:
        conn.close()
        return 0

    for hash_dup, canonical_hash in to_mark:
        conn.execute(
            "UPDATE entries SET is_duplicate=1, canonical_id=? "
            "WHERE hash=? AND is_duplicate=0",
            (canonical_hash, hash_dup)
        )
    conn.commit()
    conn.close()
    persist_runtime_db()
    return len(to_mark)


def upsert_ioc_ledger(iocs: dict, entry_hash: str, ingested: str):
    """Upsert all IOCs from one entry into the deduplicated ioc_ledger table."""
    if not iocs:
        return
    rows_to_upsert = []
    for key, ioc_type in [
        ("ips",           "ipv4-addr"),
        ("domains",       "domain-name"),
        ("urls",          "url"),
        ("cves",          "vulnerability"),
        ("threat_actors", "threat-actor"),
    ]:
        for value in (iocs.get(key) or []):
            if isinstance(value, str) and value.strip():
                rows_to_upsert.append((ioc_type, "", value.strip()))

    for value in (iocs.get("hashes") or []):
        if not isinstance(value, str) or not value.strip():
            continue
        v = value.strip()
        if len(v) == 64:
            sub = "SHA-256"
        elif len(v) == 40:
            sub = "SHA-1"
        elif len(v) == 32:
            sub = "MD5"
        else:
            continue
        rows_to_upsert.append(("file", sub, v))

    if not rows_to_upsert:
        return

    conn = _connect_db()
    try:
        for ioc_type, subtype, value in rows_to_upsert:
            # Postgres rewrite of the SQLite JSON1 upsert. Two differences that
            # matter: inside DO UPDATE every unqualified column is ambiguous and
            # must be written ioc_ledger.col, and the "is this hash already
            # recorded" test appears twice because Postgres has no IIF.
            conn.execute("""
                INSERT INTO ioc_ledger
                    (type, subtype, value, first_seen, last_seen, occurrence_count, entry_hashes)
                VALUES (?, ?, ?, ?, ?, 1, jsonb_build_array(?::text)::text)
                ON CONFLICT (type, subtype, value) DO UPDATE SET
                    last_seen        = EXCLUDED.last_seen,
                    occurrence_count = ioc_ledger.occurrence_count + CASE WHEN EXISTS (
                        SELECT 1
                        FROM jsonb_array_elements_text(ioc_ledger.entry_hashes::jsonb) AS t(v)
                        WHERE t.v = (EXCLUDED.entry_hashes::jsonb ->> 0)
                    ) THEN 0 ELSE 1 END,
                    entry_hashes     = CASE WHEN EXISTS (
                        SELECT 1
                        FROM jsonb_array_elements_text(ioc_ledger.entry_hashes::jsonb) AS t(v)
                        WHERE t.v = (EXCLUDED.entry_hashes::jsonb ->> 0)
                    ) THEN ioc_ledger.entry_hashes
                      ELSE (ioc_ledger.entry_hashes::jsonb
                            || jsonb_build_array(EXCLUDED.entry_hashes::jsonb ->> 0))::text
                    END
                WHERE ioc_ledger.benign = 0
            """, (ioc_type, subtype, value, ingested, ingested, entry_hash))
        conn.commit()
    finally:
        conn.close()


_IOC_SORT_MAP = {
    "last_seen":        "last_seen",
    "occurrence_count": "occurrence_count",
    "value":            "value",
}


def get_iocs(type_filter=None, search=None, sort_by="last_seen", sort_dir="desc",
             limit=100, offset=0, include_benign=False):
    col = _IOC_SORT_MAP.get(sort_by, "last_seen")
    direction = "ASC" if sort_dir == "asc" else "DESC"
    clauses, params = [], []
    if not include_benign:
        clauses.append("benign = 0")
    if type_filter:
        clauses.append("type = ?")
        params.append(type_filter)
    if search:
        clauses.append("value LIKE ?")
        params.append("%" + search + "%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = _connect_db()
    rows = conn.execute(
        f"SELECT id, type, subtype, value, first_seen, last_seen, occurrence_count, "
        f"jsonb_array_length(entry_hashes::jsonb) AS entry_count, benign, benign_reason "
        f"FROM ioc_ledger {where} ORDER BY {col} {direction} LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_iocs(type_filter=None, search=None, include_benign=False):
    clauses, params = [], []
    if not include_benign:
        clauses.append("benign = 0")
    if type_filter:
        clauses.append("type = ?")
        params.append(type_filter)
    if search:
        clauses.append("value LIKE ?")
        params.append("%" + search + "%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = _connect_db()
    count = conn.execute(
        f"SELECT COUNT(*) FROM ioc_ledger {where}", params
    ).fetchone()[0]
    conn.close()
    return count


def get_ioc_by_id(ioc_id: int):
    conn = _connect_db()
    row = conn.execute(
        "SELECT id, type, subtype, value, first_seen, last_seen, occurrence_count, "
        "jsonb_array_length(entry_hashes::jsonb) AS entry_count, benign, benign_reason "
        "FROM ioc_ledger WHERE id = ?",
        (ioc_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_ioc_entries(ioc_id: int) -> list:
    conn = _connect_db()
    ioc = conn.execute(
        "SELECT entry_hashes FROM ioc_ledger WHERE id = ?", (ioc_id,)
    ).fetchone()
    if not ioc:
        conn.close()
        return []
    hashes = json.loads(ioc["entry_hashes"] or "[]")
    if not hashes:
        conn.close()
        return []
    placeholders = ",".join("?" * len(hashes))
    rows = conn.execute(
        f"SELECT * FROM entries WHERE hash IN ({placeholders}) ORDER BY ingested DESC",
        hashes,
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def run_ioc_backfill():
    """Populate ioc_ledger from existing entries.iocs if ledger is empty."""
    conn = _connect_db()
    count = conn.execute("SELECT COUNT(*) FROM ioc_ledger").fetchone()[0]
    if count > 0:
        conn.close()
        return
    rows = conn.execute(
        "SELECT hash, iocs, ingested FROM entries "
        "WHERE iocs IS NOT NULL AND iocs NOT IN ('', '{}')"
    ).fetchall()
    conn.close()
    backfilled = 0
    for hash_, iocs_str, ingested in rows:
        try:
            ioc_data = json.loads(iocs_str)
            upsert_ioc_ledger(ioc_data, hash_, ingested or "")
            backfilled += 1
        except Exception:
            pass
    _logger.info("IOC_BACKFILL_COMPLETE entries_processed=%d", backfilled)


def delete_ioc(ioc_id: int) -> bool:
    """Delete an IOC row entirely. Returns True if a row was deleted."""
    conn = _connect_db()
    try:
        cursor = conn.execute("DELETE FROM ioc_ledger WHERE id = ?", (ioc_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def set_ioc_benign(ioc_id: int, benign: bool, reason: str = "") -> bool:
    """Mark or unmark an IOC as benign. Returns True if the row was found."""
    conn = _connect_db()
    try:
        cursor = conn.execute(
            "UPDATE ioc_ledger SET benign = ?, benign_reason = ? WHERE id = ?",
            (1 if benign else 0, reason if benign else None, ioc_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def remove_ioc_entry(ioc_id: int, entry_hash: str) -> dict:
    """Remove one entry association from an IOC.
    Returns {"deleted": True} if the IOC was fully removed (no more entries),
    {"deleted": False} if only the association was removed or nothing changed."""
    conn = _connect_db()
    try:
        row = conn.execute(
            "SELECT entry_hashes, occurrence_count FROM ioc_ledger WHERE id = ?",
            (ioc_id,),
        ).fetchone()
        if not row:
            return {"deleted": False}

        hashes = json.loads(row[0] or "[]")
        if entry_hash not in hashes:
            return {"deleted": False}

        hashes.remove(entry_hash)
        new_count = len(hashes)

        if new_count == 0:
            conn.execute("DELETE FROM ioc_ledger WHERE id = ?", (ioc_id,))
            conn.commit()
            return {"deleted": True}

        conn.execute(
            "UPDATE ioc_ledger SET entry_hashes = ?, occurrence_count = ? WHERE id = ?",
            (json.dumps(hashes), new_count, ioc_id),
        )
        conn.commit()
        return {"deleted": False}
    finally:
        conn.close()


# ── User / Auth helpers ──────────────────────────────────────────────────────

def get_user_by_oid(entra_oid: str):
    """Return user row as dict, or None if not found."""
    conn = _connect_db()
    row = conn.execute(
        "SELECT * FROM users WHERE entra_oid = ?", (entra_oid,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def upsert_user(entra_oid: str, email: str, display_name: str, role: str):
    """Insert new user or update email/display_name on conflict. Does not change role on update."""
    last_error = None
    for attempt in range(5):
        conn = _connect_db()
        try:
            existing = conn.execute(
                "SELECT entra_oid FROM users WHERE entra_oid = ?", (entra_oid,)
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE users
                       SET email = ?, display_name = ?, updated_at = to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
                       WHERE entra_oid = ?""",
                    (email, display_name, entra_oid),
                )
            else:
                conn.execute(
                    """INSERT INTO users (entra_oid, email, display_name, role, is_active, created_at, updated_at)
                       VALUES (?, ?, ?, ?, 1, to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'), to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'))""",
                    (entra_oid, email, display_name, role),
                )
            conn.commit()
            persist_runtime_db()
            return
        except Exception as e:
            last_error = e
            if "database is locked" not in str(e).lower() or attempt == 4:
                raise
            time.sleep(0.25 * (attempt + 1))
        finally:
            conn.close()

    if last_error is not None:
        raise last_error


def list_users():
    """Return all users as list of dicts, ordered by display_name."""
    conn = _connect_db()
    rows = conn.execute(
        "SELECT * FROM users ORDER BY display_name"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_user_role(entra_oid: str, role: str) -> bool:
    """Update a user's role. Caller is responsible for last-admin check. Returns True if user was found."""
    conn = _connect_db()
    cur = conn.execute(
        "UPDATE users SET role = ?, updated_at = to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS') WHERE entra_oid = ?",
        (role, entra_oid),
    )
    updated = cur.rowcount > 0
    conn.commit()
    conn.close()
    if updated:
        persist_runtime_db()
    return updated


def count_active_admins() -> int:
    """Count users with role='admin' and is_active=1."""
    conn = _connect_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1"
    ).fetchone()[0]
    conn.close()
    return count


# ── Triage status / dashboard ─────────────────────────────────────────────────

def get_triage_status():
    conn = _connect_db()
    row  = conn.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN severity != 'Unknown' THEN 1 ELSE 0 END) AS triaged,
            SUM(CASE WHEN severity = 'Unknown'  THEN 1 ELSE 0 END) AS pending,
            SUM(CASE WHEN severity='Critical'      THEN 1 ELSE 0 END) AS critical,
            SUM(CASE WHEN severity='High'          THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN severity='Medium'        THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN severity='Low'           THEN 1 ELSE 0 END) AS low,
            SUM(CASE WHEN severity='Informational' THEN 1 ELSE 0 END) AS informational
        FROM entries WHERE archived = 0
    """).fetchone()
    conn.close()
    return {
        "total":         row["total"]         or 0,
        "triaged":       row["triaged"]       or 0,
        "pending":       row["pending"]       or 0,
        "critical":      row["critical"]      or 0,
        "high":          row["high"]          or 0,
        "medium":        row["medium"]        or 0,
        "low":           row["low"]           or 0,
        "informational": row["informational"] or 0,
        "progress_pct":  round((row["triaged"] or 0) / (row["total"] or 1) * 100, 1),
    }


def _ingested_window_clause(since: str | None, until: str | None) -> tuple[str, list]:
    """`entries.ingested` is a lexically-sortable UTC TEXT timestamp
    ('YYYY-MM-DD HH24:MI:SS') -- a plain string comparison against it
    needs no cast. Returns an '' (no filter) fragment when both bounds
    are None, so every existing call site's behavior is unchanged unless
    it actually passes a window -- Workstream D, docs/superpowers/specs/
    2026-09-04-live-feedback-round-6-design.md."""
    clauses = []
    params: list = []
    if since is not None:
        clauses.append("ingested >= ?")
        params.append(since)
    if until is not None:
        clauses.append("ingested <= ?")
        params.append(until)
    return (" AND " + " AND ".join(clauses)) if clauses else "", params


def get_dashboard_stats(since: str | None = None, until: str | None = None):
    conn = _connect_db()
    window_clause, window_params = _ingested_window_clause(since, until)
    count_rows = conn.execute(f"""
        SELECT
            COUNT(*) FILTER (WHERE archived=0 AND is_duplicate=0)            AS total,
            COUNT(*) FILTER (WHERE severity!='Unknown' AND archived=0 AND is_duplicate=0) AS triaged,
            COUNT(*) FILTER (WHERE severity='Unknown'  AND archived=0 AND is_duplicate=0) AS pending,
            COUNT(*) FILTER (WHERE triaged=1 AND severity='Unknown' AND (ttps='' OR ttps IS NULL)
                             AND archived=0 AND is_duplicate=0)                AS needs_retriage,
            COUNT(*) FILTER (WHERE is_duplicate=1)                             AS dupes,
            COUNT(*) FILTER (WHERE iocs IS NOT NULL AND iocs NOT IN ('','{{}}')
                             AND archived=0 AND is_duplicate=0)                AS ioc_entries
        FROM entries
        WHERE 1=1{window_clause}
    """, tuple(window_params)).fetchone()
    total, triaged, pending, needs_retriage, dupes, ioc_entries = count_rows
    last_poll_row = conn.execute(
        f"SELECT MAX(ingested) FROM entries WHERE 1=1{window_clause}", tuple(window_params)
    ).fetchone()
    last_poll = last_poll_row[0] if last_poll_row else None
    sources_active = conn.execute(
        f"SELECT COUNT(DISTINCT source) FROM entries WHERE archived=0 AND is_duplicate=0{window_clause}",
        tuple(window_params),
    ).fetchone()[0]
    sev_rows = conn.execute(f"""
        SELECT severity, COUNT(*) AS count FROM entries
        WHERE severity != 'Unknown' AND archived = 0 AND is_duplicate = 0{window_clause}
        GROUP BY severity ORDER BY count DESC
    """, tuple(window_params)).fetchall()
    ttp_rows = conn.execute(
        f"SELECT ttps FROM entries "
        f"WHERE severity!='Unknown' AND ttps!='' AND archived=0 AND is_duplicate=0{window_clause}",
        tuple(window_params),
    ).fetchall()
    tag_rows = conn.execute(
        f"SELECT tags FROM entries "
        f"WHERE severity!='Unknown' AND tags!='' AND tags!='{{}}' AND archived=0 AND is_duplicate=0{window_clause}",
        tuple(window_params),
    ).fetchall()
    ioc_rows = conn.execute(
        f"SELECT iocs FROM entries "
        f"WHERE severity!='Unknown' AND iocs IS NOT NULL AND iocs!='' AND iocs!='{{}}' "
        f"AND archived=0 AND is_duplicate=0{window_clause}",
        tuple(window_params),
    ).fetchall()
    conn.close()

    ttp_counts = {}
    for (ttps_str,) in ttp_rows:
        for t in ttps_str.split(","):
            t = t.strip()
            if t and t.startswith("T"):
                ttp_counts[t] = ttp_counts.get(t, 0) + 1
    top_ttps = sorted(ttp_counts.items(), key=lambda x: x[1], reverse=True)[:15]

    tag_distribution = {
        "indicator_types": {}, "malware_types": {},
        "threat_actor_types": {}, "target_sectors": {}, "platforms": {},
    }
    for (tags_str,) in tag_rows:
        try:
            tags = json.loads(tags_str)
            for category, values in tags.items():
                if category in tag_distribution and isinstance(values, list):
                    for v in values:
                        tag_distribution[category][v] = tag_distribution[category].get(v, 0) + 1
        except Exception:
            pass

    tag_distribution = {
        cat: sorted(vals.items(), key=lambda x: x[1], reverse=True)
        for cat, vals in tag_distribution.items()
    }

    ioc_dist = {"threat_actors": {}, "cves": {}}
    for (iocs_str,) in ioc_rows:
        try:
            iocs = json.loads(iocs_str)
            for cat in ["threat_actors", "cves"]:
                for v in (iocs.get(cat) or []):
                    if isinstance(v, str) and v:
                        ioc_dist[cat][v] = ioc_dist[cat].get(v, 0) + 1
        except Exception:
            pass

    return {
        "total":          total,
        "triaged":        triaged,
        "pending":        pending,
        "needs_retriage": needs_retriage,
        "enrichment": {
            "iocs_extracted":   ioc_entries,
            "sources_active":   sources_active,
            "dupes_suppressed": dupes,
            "last_poll":        last_poll,
        },
        "severity": [{"label": r[0], "count": r[1]} for r in sev_rows],
        "ttps":     [{"technique": t, "count": c} for t, c in top_ttps],
        "tag_distribution": {
            cat: [{"value": v, "count": c} for v, c in items]
            for cat, items in tag_distribution.items()
        },
        "ioc_distribution": {
            cat: [{"value": v, "count": c} for v, c in
                  sorted(vals.items(), key=lambda x: x[1], reverse=True)[:30]]
            for cat, vals in ioc_dist.items()
        },
    }


def get_mitre_coverage(since: str | None = None, until: str | None = None):
    conn = _connect_db()
    window_clause, window_params = _ingested_window_clause(since, until)
    rows = conn.execute(
        f"SELECT ttps FROM entries WHERE severity!='Unknown' AND ttps!='' AND archived=0{window_clause}",
        tuple(window_params),
    ).fetchall()
    conn.close()

    counts = {}
    for (ttps_str,) in rows:
        for t in ttps_str.split(","):
            t = t.strip()
            if not t or not t.startswith("T"):
                continue
            counts[t] = counts.get(t, 0) + 1
            parent = t.split(".")[0]
            if parent != t:
                counts[parent] = counts.get(parent, 0) + 1
    return counts


def get_enrichment_stats():
    conn = _connect_db()
    row = conn.execute("""
        SELECT
            SUM(CASE WHEN enriched=1       THEN 1 ELSE 0 END) AS enriched_count,
            SUM(CASE WHEN kev_flag=1        THEN 1 ELSE 0 END) AS kev_count,
            SUM(CASE WHEN enriched=0 AND severity!='Unknown'
                          AND archived=0   THEN 1 ELSE 0 END) AS pending_count,
            AVG(CASE WHEN epss_score IS NOT NULL THEN epss_score END) AS avg_epss,
            MAX(epss_score)                                    AS max_epss,
            AVG(CASE WHEN priority_score IS NOT NULL
                     THEN priority_score END)                  AS avg_priority
        FROM entries
        WHERE archived=0 AND is_duplicate=0
    """).fetchone()
    # Settings' "System Info" panel reads ips_extracted/hashes_extracted/
    # cves_extracted/last_poll from this endpoint's response -- those never
    # existed in it (get_dashboard_stats() computes a *different*, single
    # aggregate iocs_extracted count, and neither hashes nor CVEs were
    # broken out anywhere), so the panel always rendered "--" regardless of
    # how much real data existed. ioc_ledger already tracks the exact
    # per-type breakdown upsert_ioc_ledger() writes (ipv4-addr/file/
    # vulnerability), so pull the three counts from there instead of adding
    # yet another ad-hoc aggregate.
    ioc_type_counts = dict(conn.execute("""
        SELECT type, COUNT(*) FROM ioc_ledger
        WHERE type IN ('ipv4-addr', 'file', 'vulnerability')
        GROUP BY type
    """).fetchall())
    last_poll_row = conn.execute("SELECT MAX(ingested) FROM entries").fetchone()
    conn.close()
    return {
        "enriched_count": row[0] or 0,
        "kev_count":      row[1] or 0,
        "pending_count":  row[2] or 0,
        "avg_epss":       round(row[3] or 0, 4),
        "max_epss":       round(row[4] or 0, 4),
        "avg_priority":   round(row[5] or 0, 4),
        "ips_extracted":    ioc_type_counts.get("ipv4-addr", 0),
        "hashes_extracted": ioc_type_counts.get("file", 0),
        "cves_extracted":   ioc_type_counts.get("vulnerability", 0),
        "last_poll":        last_poll_row[0] if last_poll_row else None,
    }


# ── RunZero helpers ───────────────────────────────────────────────────────────

def get_runzero_status() -> dict:
    """Return the most recent sync log entry plus current match counts."""
    conn = _connect_db()
    row = conn.execute(
        "SELECT synced_at, org_count, asset_count, vuln_count, match_count, status, error "
        "FROM runzero_sync_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    confirmed = conn.execute(
        "SELECT COUNT(DISTINCT entry_hash) FROM runzero_matches WHERE confidence = 'confirmed'"
    ).fetchone()[0]
    possible = conn.execute(
        "SELECT COUNT(DISTINCT entry_hash) FROM runzero_matches WHERE confidence = 'possible'"
    ).fetchone()[0]
    conn.close()
    if not row:
        return {
            "configured": bool(os.environ.get("RUNZERO_API_TOKEN", "")),
            "last_sync": None, "org_count": 0, "asset_count": 0,
            "vuln_count": 0, "match_count": 0, "status": "never_synced",
            "error": "", "confirmed_matches": confirmed, "possible_matches": possible,
        }
    return {
        "configured": bool(os.environ.get("RUNZERO_API_TOKEN", "")),
        "last_sync": row[0], "org_count": row[1], "asset_count": row[2],
        "vuln_count": row[3], "match_count": row[4], "status": row[5],
        "error": row[6], "confirmed_matches": confirmed, "possible_matches": possible,
    }


def get_runzero_matches(
    confidence: str = None,
    limit: int = 50,
    offset: int = 0,
    asset_search: str = None,
    org: str = None,
    severity: list = None,
    date_from: str = None,
    date_to: str = None,
    kev_only: bool = False,
) -> tuple:
    """Return (total, list-of-match-dicts) for entries with RunZero hits.

    asset_search matches against the threat intel entry's own title as well
    as the affected assets' hostname/org -- a match on any of the three
    is enough, not asset identity alone. severity/date_from/date_to filter
    on the entry's own severity/published fields, independent of the
    asset-side search.

    kev_only (Workstream G, docs/superpowers/specs/2026-09-04-live-
    feedback-round-6-design.md): filters to entries whose own
    entries.kev_flag is set -- already computed by enrichment.py's
    compute_priority_score() (`kev_flag = 1 if any(c in _kev_ids for c in
    cves) else 0`) against the same CISA KEV cache refresh_kev_cache()
    maintains. Deliberately reuses this existing column rather than
    parsing the CVE id back out of runzero_matches.match_detail's display
    string ("CVE-xxxx — vuln name") -- kev_flag is already the right
    per-entry signal, computed once at enrichment time, and using it here
    keeps this a normal SQL WHERE clause (correct under LIMIT/OFFSET
    pagination) instead of a post-fetch Python filter that would need its
    own separate counting logic."""
    conn = _connect_db()

    conf_filter = "AND m.confidence = ?" if confidence else ""
    conf_params = [confidence] if confidence else []

    kev_filter = "AND e.kev_flag = 1" if kev_only else ""

    asset_filter = ""
    asset_params = []
    if asset_search:
        asset_filter = """
            AND (
                e.title ILIKE ?
                OR EXISTS (
                    SELECT 1 FROM runzero_matches m2
                    JOIN runzero_assets a2 ON a2.id = m2.asset_id
                    WHERE m2.entry_hash = m.entry_hash
                      AND (a2.hostname ILIKE ? OR a2.org ILIKE ?)
                )
            )
        """
        asset_params = [f"%{asset_search}%", f"%{asset_search}%", f"%{asset_search}%"]

    org_filter = ""
    org_params = []
    if org:
        org_filter = """
            AND EXISTS (
                SELECT 1 FROM runzero_matches m3
                JOIN runzero_assets a3 ON a3.id = m3.asset_id
                WHERE m3.entry_hash = m.entry_hash
                  AND a3.org = ?
            )
        """
        org_params = [org]

    severity_filter = ""
    severity_params = []
    if severity:
        placeholders = ",".join("?" * len(severity))
        severity_filter = f"AND e.severity IN ({placeholders})"
        severity_params = list(severity)

    date_filter = ""
    date_params = []
    if date_from:
        date_filter += "AND e.published >= ? "
        date_params.append(date_from)
    if date_to:
        date_filter += "AND e.published <= ? "
        date_params.append(date_to)

    q = f"""
        SELECT
            e.hash, e.title, e.severity, e.source, e.published,
            COALESCE(e.link, '') AS link,
            COALESCE(e.ai_summary, '') AS ai_summary,
            MAX(m.confidence) AS confidence,
            -- SQLite GROUP_CONCAT defaults to a comma with no space. Keep the
            -- separator byte-identical or the frontend split gains leading
            -- spaces.
            string_agg(DISTINCT m.match_type, ',') AS match_types,
            COUNT(DISTINCT m.asset_id) AS affected_asset_count,
            string_agg(DISTINCT a.org, ',') AS affected_orgs,
            -- The ::text cast is required: without it psycopg returns a Python
            -- list and the caller's json.loads() fails.
            jsonb_agg(jsonb_build_object(
                'asset_id',  m.asset_id,
                'hostname',  COALESCE(a.hostname, ''),
                'org',       COALESCE(a.org, ''),
                'site',      COALESCE(a.site, ''),
                'addresses', COALESCE(a.addresses_json, '[]'),
                'os',        COALESCE(a.os, ''),
                'tags',      COALESCE(a.tags_json, '[]'),
                'match_type', m.match_type,
                'detail',    m.match_detail
            ))::text AS match_details
        FROM runzero_matches m
        JOIN entries e ON e.hash = m.entry_hash
        LEFT JOIN runzero_assets a ON a.id = m.asset_id
        WHERE 1=1 {conf_filter} {asset_filter} {org_filter} {severity_filter} {date_filter} {kev_filter}
        -- Grouped by the entries primary key rather than m.entry_hash so
        -- Postgres can resolve the functional dependency and allow the bare
        -- e.* columns above. SQLite permitted bare columns; Postgres does not.
        GROUP BY e.hash
        ORDER BY
            CASE MAX(m.confidence) WHEN 'confirmed' THEN 0 ELSE 1 END,
            CASE e.severity
                WHEN 'Critical' THEN 0 WHEN 'High' THEN 1
                WHEN 'Medium' THEN 2   WHEN 'Low'  THEN 3
                ELSE 4
            END,
            e.published DESC
        LIMIT ? OFFSET ?
    """
    q_params = conf_params + asset_params + org_params + severity_params + date_params
    rows = conn.execute(q, q_params + [limit, offset]).fetchall()

    # JOINs entries here too (unlike the pre-existing bare `m`-only count),
    # since asset_filter now matches against e.title and severity_filter/
    # date_filter both reference e.* directly.
    count_q = f"""
        SELECT COUNT(DISTINCT m.entry_hash)
        FROM runzero_matches m
        JOIN entries e ON e.hash = m.entry_hash
        WHERE 1=1 {conf_filter} {asset_filter} {org_filter} {severity_filter} {date_filter} {kev_filter}
    """
    total = conn.execute(count_q, q_params).fetchone()[0]
    conn.close()

    results = []
    for r in rows:
        try:
            details = json.loads(r["match_details"])
        except Exception:
            details = []
        results.append({
            "hash":                 r["hash"],
            "title":                r["title"],
            "severity":             r["severity"],
            "source":               r["source"],
            "published":            r["published"],
            "link":                 r["link"],
            "confidence":           r["confidence"],
            "match_types":          [t for t in (r["match_types"] or "").split(",") if t],
            "affected_asset_count": r["affected_asset_count"],
            "affected_orgs":        [o for o in (r["affected_orgs"] or "").split(",") if o],
            "ai_summary":           r["ai_summary"],
            "match_details":        details,
        })
    return total, results


def get_feed_health(feeds: list, conn=None) -> list:
    """Return per-feed health summary.

    `feeds` is the FEEDS list from feed_manager (list of {name, tier, url} dicts).
    Accepts an optional conn for testing; opens DB_PATH when not provided.

    Consecutive failures are computed in Python by walking recent log rows
    (newest first) until the first success=1 row.
    """
    owned = conn is None
    if owned:
        conn = _connect_db()
    try:
        results = []
        for feed in feeds:
            name = feed["name"]
            tier = feed.get("tier", 3)

            # Last poll time and last success time
            log_row = conn.execute(
                "SELECT polled_at, success, error_msg FROM feed_fetch_log "
                "WHERE feed_name = ? ORDER BY polled_at DESC LIMIT 20",
                (name,),
            ).fetchall()

            last_polled  = log_row[0][0] if log_row else None
            last_success = next((r[0] for r in log_row if r[1] == 1), None)
            # Only surface an error while the feed is actually in a failing
            # streak -- a stale error from before the feed recovered would
            # be misleading to show as if it were current.
            last_error = log_row[0][2] if log_row and log_row[0][1] == 0 else None

            # Consecutive failures: count rows from newest until first success
            consecutive_failures = 0
            for _, success, _error in log_row:
                if success == 0:
                    consecutive_failures += 1
                else:
                    break

            # Items ingested in last 7 days (active, non-duplicate)
            items_7d = conn.execute(
                "SELECT COUNT(*) FROM entries "
                "WHERE source = ? AND archived = 0 AND is_duplicate = 0 "
                "AND ingested >= to_char(now() AT TIME ZONE 'utc' - interval '7 days', 'YYYY-MM-DD HH24:MI:SS')",
                (name,),
            ).fetchone()[0]

            # Total active entries for this feed
            total_active = conn.execute(
                "SELECT COUNT(*) FROM entries "
                "WHERE source = ? AND archived = 0 AND is_duplicate = 0",
                (name,),
            ).fetchone()[0]

            results.append({
                "name":                 name,
                "tier":                 tier,
                "last_polled":          last_polled,
                "last_success":         last_success,
                "last_error":           last_error,
                "consecutive_failures": consecutive_failures,
                "items_last_7d":        items_7d,
                "total_active":         total_active,
            })
    finally:
        if owned:
            conn.close()
    return results


def get_org_exposure(conn=None) -> list:
    """Return per-org exposure summary ranked by confirmed matches descending.

    Accepts an optional conn for testing; opens DB_PATH when not provided.
    """
    owned = conn is None
    if owned:
        conn = _connect_db()
    try:
        rows = conn.execute("""
            SELECT
                ra.org,
                COUNT(DISTINCT rm.entry_hash)
                    FILTER (WHERE rm.confidence = 'confirmed')   AS confirmed,
                COUNT(DISTINCT rm.entry_hash)
                    FILTER (WHERE rm.confidence = 'possible')    AS possible,
                COUNT(DISTINCT rm.entry_hash)                     AS total,
                COUNT(DISTINCT rm.entry_hash)
                    FILTER (WHERE e.severity = 'Critical')       AS critical,
                COUNT(DISTINCT rm.entry_hash)
                    FILTER (WHERE e.severity = 'High')           AS high,
                COUNT(DISTINCT rm.entry_hash)
                    FILTER (WHERE e.severity = 'Medium')         AS medium,
                COUNT(DISTINCT rm.entry_hash)
                    FILTER (WHERE e.severity = 'Low')            AS low
            FROM runzero_matches rm
            JOIN runzero_assets ra ON ra.id = rm.asset_id
            JOIN entries e ON e.hash = rm.entry_hash
            GROUP BY ra.org
            ORDER BY confirmed DESC, possible DESC, total DESC
        """).fetchall()
    finally:
        if owned:
            conn.close()
    return [
        {
            "org":       r[0],
            "confirmed": r[1] or 0,
            "possible":  r[2] or 0,
            "total":     r[3] or 0,
            "critical":  r[4] or 0,
            "high":      r[5] or 0,
            "medium":    r[6] or 0,
            "low":       r[7] or 0,
        }
        for r in rows
    ]


def reconcile_exposure(conn) -> dict:
    """Compare runzero_matches against tracked exposure_items and sync lifecycle state.

    Commits the connection before returning. Caller must not hold this connection
    in an outer transaction that needs to remain open.
    Returns counts: new, updated, remediated, reopened.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()

    current_rows = conn.execute(
        "SELECT asset_id, entry_hash FROM runzero_matches"
    ).fetchall()
    current_pairs = {(r[0], r[1]) for r in current_rows}

    existing_rows = conn.execute(
        "SELECT id, asset_id, entry_hash, status FROM exposure_items "
        "WHERE status IN ('active', 'acknowledged')"
    ).fetchall()
    existing_map = {(r[1], r[2]): (r[0], r[3]) for r in existing_rows}
    existing_pairs = set(existing_map.keys())

    remediated_rows = conn.execute(
        "SELECT id, asset_id, entry_hash FROM exposure_items WHERE status = 'remediated'"
    ).fetchall()
    remediated_map = {(r[1], r[2]): r[0] for r in remediated_rows}
    remediated_pairs = set(remediated_map.keys())

    new_count = updated_count = remediated_count = reopened_count = 0

    # 1. Brand-new pairs
    new_pairs = current_pairs - existing_pairs - remediated_pairs
    if new_pairs:
        conn.executemany(
            "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen) "
            "VALUES (?, ?, 'active', ?, ?)",
            [(p[0], p[1], now, now) for p in new_pairs],
        )
        new_count = len(new_pairs)

    # 2. Reappeared (previously remediated)
    for pair in current_pairs & remediated_pairs:
        item_id = remediated_map[pair]
        conn.execute(
            "UPDATE exposure_items SET status='active', remediated_at=NULL, last_seen=? WHERE id=?",
            (now, item_id),
        )
        conn.execute(
            "INSERT INTO exposure_audit_log "
            "(exposure_item_id, actor, action, detail, created_at) "
            "VALUES (?, 'system', 'status_change', 'remediated → active (reappeared)', ?)",
            (item_id, now),
        )
        reopened_count += 1

    # 3. Continuing — update last_seen
    continuing = current_pairs & existing_pairs
    if continuing:
        conn.executemany(
            "UPDATE exposure_items SET last_seen=? WHERE asset_id=? AND entry_hash=? "
            "AND status IN ('active', 'acknowledged')",
            [(now, p[0], p[1]) for p in continuing],
        )
        updated_count = len(continuing)

    # 4. Gone — auto-remediate
    for pair in existing_pairs - current_pairs:
        item_id, old_status = existing_map[pair]
        conn.execute(
            "UPDATE exposure_items SET status='remediated', remediated_at=? WHERE id=?",
            (now, item_id),
        )
        conn.execute(
            "INSERT INTO exposure_audit_log "
            "(exposure_item_id, actor, action, detail, created_at) "
            "VALUES (?, 'system', 'status_change', ?, ?)",
            (item_id, f"{old_status} → remediated", now),
        )
        remediated_count += 1

    conn.commit()
    return {
        "new": new_count,
        "updated": updated_count,
        "remediated": remediated_count,
        "reopened": reopened_count,
    }


# ---------------------------------------------------------------------------
# Stubs for future tasks — will be fully implemented in tasks 3–7
# ---------------------------------------------------------------------------

def get_exposure_items(
    org: str,
    status: str = "active",
    limit: int = 50,
    offset: int = 0,
    kev_only: bool = False,
    conn=None,
) -> dict:
    """Return paginated exposure items with joined asset + entry data.

    status: 'active', 'acknowledged', 'remediated', or 'all'
    kev_only: filter to items whose underlying entry has entries.kev_flag
    set -- see get_runzero_matches()'s docstring for why this reuses that
    existing column rather than parsing a CVE id out of match_detail.
    Returns: {'total': int, 'items': [...]}
    """
    _VALID_STATUS = {"active", "acknowledged", "remediated", "all"}
    if status not in _VALID_STATUS:
        status = "active"

    status_clause = "" if status == "all" else "AND ei.status = ?"
    kev_clause = "AND e.kev_flag = 1" if kev_only else ""
    base_params = [org] if status == "all" else [org, status]

    owned = conn is None
    if owned:
        conn = _connect_db()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM exposure_items ei "
            f"JOIN runzero_assets ra ON ra.id = ei.asset_id "
            f"JOIN entries e ON e.hash = ei.entry_hash "
            f"WHERE ra.org = ? {status_clause} {kev_clause}",
            base_params,
        ).fetchone()[0]

        rows = conn.execute(
            f"""
            SELECT
                ei.id, ei.asset_id,
                COALESCE(ra.hostname, '') AS hostname,
                COALESCE(ra.site, '')     AS site,
                COALESCE(ra.os, '')       AS os,
                ei.entry_hash,
                COALESCE(e.title, '')     AS title,
                COALESCE(e.severity, '')  AS severity,
                COALESCE(e.ai_summary, '') AS ai_summary,
                COALESCE(e.link, '')      AS link,
                COALESCE(rm.confidence, '') AS confidence,
                COALESCE(rm.match_type, '') AS match_type,
                ei.status, ei.notes, ei.assigned_to,
                ei.first_seen, ei.last_seen, ei.remediated_at,
                COALESCE(e.published, '') AS published
            FROM exposure_items ei
            JOIN runzero_assets ra ON ra.id = ei.asset_id
            JOIN entries e ON e.hash = ei.entry_hash
            -- One exposure item can have several runzero_matches rows, since
            -- that table is keyed on (entry_hash, asset_id, match_type). SQLite
            -- collapsed them with a bare-column GROUP BY and picked a match
            -- arbitrarily; Postgres rejects bare columns from joined tables.
            -- This lateral keeps exactly one row per item and makes the choice
            -- deterministic, preferring a confirmed match over a possible one.
            LEFT JOIN LATERAL (
                SELECT rm2.confidence, rm2.match_type
                FROM runzero_matches rm2
                WHERE rm2.asset_id = ei.asset_id
                  AND rm2.entry_hash = ei.entry_hash
                ORDER BY CASE rm2.confidence WHEN 'confirmed' THEN 0 ELSE 1 END,
                         rm2.match_type
                LIMIT 1
            ) rm ON true
            WHERE ra.org = ? {status_clause} {kev_clause}
            -- ei.id is a tiebreaker, not decoration. reconcile_exposure stamps
            -- every pair in a batch with the same first_seen, so ORDER BY that
            -- column alone is non-deterministic under LIMIT/OFFSET: Postgres may
            -- return the same row on two consecutive pages and skip another.
            -- SQLite masked this by usually walking rows in rowid order.
            ORDER BY ei.first_seen DESC, ei.id DESC
            LIMIT ? OFFSET ?
            """,
            base_params + [limit, offset],
        ).fetchall()
    finally:
        if owned:
            conn.close()

    return {
        "total": total,
        "items": [
            {
                "id":           r[0],
                "asset_id":     r[1],
                "hostname":     r[2],
                "site":         r[3],
                "os":           r[4],
                "entry_hash":   r[5],
                "title":        r[6],
                "severity":     r[7],
                "ai_summary":   r[8],
                "link":         r[9],
                "confidence":   r[10],
                "match_type":   r[11],
                "status":       r[12],
                "notes":        r[13] or "",
                "assigned_to":  r[14],
                "first_seen":   r[15],
                "last_seen":    r[16],
                "remediated_at": r[17],
                "published":     r[18],
            }
            for r in rows
        ],
    }


_PATCHABLE_STATUSES = {"active", "acknowledged"}


def patch_exposure_item(
    item_id: int,
    actor: str,
    status: str = None,
    notes: str = None,
    assigned_to=...,
    conn=None,
) -> dict:
    """Update status, notes, and/or assigned_to on an exposure item.

    Writes one audit log row per changed field.
    assigned_to=None explicitly unassigns; omitting assigned_to (default ...) leaves it unchanged.
    Raises ValueError for invalid status ('remediated') or unknown assigned_to.
    Returns the updated item as a dict.
    """
    from datetime import datetime, timezone

    if status is not None and status not in _PATCHABLE_STATUSES:
        raise ValueError(
            f"Status '{status}' cannot be set via API; only 'active' and 'acknowledged' are allowed."
        )

    owned = conn is None
    if owned:
        conn = _connect_db()

    now = datetime.now(timezone.utc).isoformat()

    try:
        row = conn.execute(
            "SELECT status, notes, assigned_to FROM exposure_items WHERE id = ?",
            (item_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"Exposure item {item_id} not found.")

        current_status, current_notes, current_assigned = row

        # Validate assigned_to before writing anything
        if assigned_to is not ... and assigned_to is not None:
            exists = conn.execute(
                "SELECT COUNT(*) FROM users WHERE display_name = ? AND is_active = 1",
                (assigned_to,),
            ).fetchone()[0]
            if not exists:
                raise ValueError(f"User '{assigned_to}' not found or inactive.")

        updates = []
        params = []
        log_rows = []

        if status is not None and status != current_status:
            updates.append("status = ?")
            params.append(status)
            log_rows.append((item_id, actor, "status_change",
                             f"{current_status} → {status}", now))

        if notes is not None and notes != current_notes:
            updates.append("notes = ?")
            params.append(notes[:4000])
            log_rows.append((item_id, actor, "note_added", notes[:500], now))

        if assigned_to is not ...:
            if assigned_to != current_assigned:
                updates.append("assigned_to = ?")
                params.append(assigned_to)
                detail = f"→ {assigned_to}" if assigned_to else "unassigned"
                log_rows.append((item_id, actor, "assigned", detail, now))

        if updates:
            conn.execute(
                f"UPDATE exposure_items SET {', '.join(updates)} WHERE id = ?",
                params + [item_id],
            )
        if log_rows:
            conn.executemany(
                "INSERT INTO exposure_audit_log "
                "(exposure_item_id, actor, action, detail, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                log_rows,
            )
        conn.commit()

        # Return the updated item
        r = conn.execute(
            """
            SELECT
                ei.id, ei.asset_id,
                COALESCE(ra.hostname, '') AS hostname,
                COALESCE(ra.site, '')     AS site,
                COALESCE(ra.os, '')       AS os,
                ei.entry_hash,
                COALESCE(e.title, '')     AS title,
                COALESCE(e.severity, '')  AS severity,
                COALESCE(e.ai_summary,'') AS ai_summary,
                COALESCE(e.link, '')      AS link,
                COALESCE(rm.confidence,'') AS confidence,
                COALESCE(rm.match_type,'') AS match_type,
                ei.status, ei.notes, ei.assigned_to,
                ei.first_seen, ei.last_seen, ei.remediated_at
            FROM exposure_items ei
            JOIN runzero_assets ra ON ra.id = ei.asset_id
            JOIN entries e ON e.hash = ei.entry_hash
            -- Same deterministic single-match pick as get_exposure_items.
            LEFT JOIN LATERAL (
                SELECT rm2.confidence, rm2.match_type
                FROM runzero_matches rm2
                WHERE rm2.asset_id = ei.asset_id
                  AND rm2.entry_hash = ei.entry_hash
                ORDER BY CASE rm2.confidence WHEN 'confirmed' THEN 0 ELSE 1 END,
                         rm2.match_type
                LIMIT 1
            ) rm ON true
            WHERE ei.id = ?
            """,
            (item_id,),
        ).fetchone()

    finally:
        if owned:
            conn.close()

    if r is None:
        raise ValueError(f"Exposure item {item_id} not found after update.")

    return {
        "id": r[0], "asset_id": r[1], "hostname": r[2], "site": r[3], "os": r[4],
        "entry_hash": r[5], "title": r[6], "severity": r[7], "ai_summary": r[8],
        "link": r[9], "confidence": r[10], "match_type": r[11],
        "status": r[12], "notes": r[13] or "", "assigned_to": r[14],
        "first_seen": r[15], "last_seen": r[16], "remediated_at": r[17],
    }


def get_exposure_audit(item_id: int, conn=None) -> list:
    """Return audit log for one exposure item, newest first."""
    owned = conn is None
    if owned:
        conn = _connect_db()
    try:
        rows = conn.execute(
            "SELECT actor, action, detail, created_at FROM exposure_audit_log "
            "WHERE exposure_item_id = ? ORDER BY created_at DESC",
            (item_id,),
        ).fetchall()
    finally:
        if owned:
            conn.close()
    return [
        {"actor": r[0], "action": r[1], "detail": r[2], "created_at": r[3]}
        for r in rows
    ]


def get_exposure_summary(conn=None) -> list:
    """Return per-org exposure counts by status, ordered by total DESC."""
    owned = conn is None
    if owned:
        conn = _connect_db()
    try:
        rows = conn.execute("""
            SELECT
                ra.org,
                COUNT(ei.id) AS total,
                COALESCE(SUM(CASE WHEN ei.status = 'active'       THEN 1 ELSE 0 END), 0) AS active,
                COALESCE(SUM(CASE WHEN ei.status = 'acknowledged' THEN 1 ELSE 0 END), 0) AS acknowledged,
                COALESCE(SUM(CASE WHEN ei.status = 'remediated'   THEN 1 ELSE 0 END), 0) AS remediated
            FROM runzero_assets ra
            LEFT JOIN exposure_items ei ON ei.asset_id = ra.id
            WHERE ra.org != ''
            GROUP BY ra.org
            ORDER BY total DESC
        """).fetchall()
    finally:
        if owned:
            conn.close()
    return [
        {
            "org":          r[0],
            "total":        r[1],
            "active":       r[2] or 0,
            "acknowledged": r[3] or 0,
            "remediated":   r[4] or 0,
        }
        for r in rows
    ]


def get_exposure_metrics(since: str | None, until: str | None, org: str | None = None, conn=None) -> dict:
    """Intake/remediation trend + accumulative standing counts for the
    RunZero Metrics subtab (Workstream F, docs/superpowers/specs/
    2026-09-04-live-feedback-round-6-design.md). Built on `exposure_items`
    (TI-correlated, remediation-tracked matches -- confirmed with the user
    this is the right scope, not raw RunZero CVE rows, which have no
    history: runzero_sync.py DELETEs and reinserts runzero_vulns on every
    sync).

    Grouped by runzero_assets.org, not .site (changed 2026-09-04 per user
    request) -- org is the tenant-level grouping the rest of exposure
    reporting already uses (get_exposure_summary()/get_exposure_summary_
    by_org()), whereas site is a finer-grained sub-location under one org
    that isn't otherwise surfaced anywhere in this reporting.

    Framing (a deliberate scoping choice, since the ask's "current vulns /
    remediated / standing... based on the time window selected" doesn't
    map onto a single unambiguous query): every number here is scoped to
    the COHORT of items that first appeared (first_seen) within
    [since, until] -- not "every item currently active regardless of when
    it appeared." So "still standing" means "of what appeared in this
    window, how many are not yet remediated," not a live global snapshot.
    A since=until=None (All time) call is the closest thing to a live
    snapshot, since every item's first_seen necessarily falls in an
    unbounded window.

    exposure_items.first_seen/remediated_at are TEXT storing
    datetime.now(timezone.utc).isoformat() (e.g.
    "2026-09-04T12:00:00+00:00") -- a DIFFERENT text format than
    entries.ingested's space-separated one time_windows.window_to_range()
    was written against. Comparing these lexically as bare strings is
    unsafe (a 'T' sorts after a space at the same character position, so
    a same-day space-formatted `until` bound would lexically exclude
    every T-formatted row on that exact day). Every comparison here casts
    both sides to timestamptz explicitly so it's a real timestamp
    comparison, not a lexical one -- safe regardless of which of the two
    text formats either side happens to use.
    """
    owned = conn is None
    if owned:
        conn = _connect_db()
    try:
        since_clause = "AND ei.first_seen::timestamptz >= ?::timestamptz" if since is not None else ""
        until_clause = "AND ei.first_seen::timestamptz <= ?::timestamptz" if until is not None else ""
        window_params = ([since] if since is not None else []) + ([until] if until is not None else [])

        org_clause = "AND ra.org = ?" if org is not None else ""
        org_params = [org] if org is not None else []

        base_where = f"WHERE 1=1 {since_clause} {until_clause} {org_clause}"
        base_params = window_params + org_params

        intake_rows = conn.execute(
            f"SELECT ra.org AS org, date_trunc('day', ei.first_seen::timestamptz) AS bucket, "
            f"COUNT(*) AS count "
            f"FROM exposure_items ei JOIN runzero_assets ra ON ra.id = ei.asset_id "
            f"{base_where} GROUP BY ra.org, bucket ORDER BY bucket",
            tuple(base_params),
        ).fetchall()

        remediated_since_clause = (
            "AND ei.remediated_at::timestamptz >= ?::timestamptz" if since is not None else ""
        )
        remediated_until_clause = (
            "AND ei.remediated_at::timestamptz <= ?::timestamptz" if until is not None else ""
        )
        remediated_where = (
            f"WHERE ei.remediated_at IS NOT NULL {remediated_since_clause} {remediated_until_clause} {org_clause}"
        )
        remediated_params = window_params + org_params
        remediated_rows = conn.execute(
            f"SELECT ra.org AS org, date_trunc('day', ei.remediated_at::timestamptz) AS bucket, "
            f"COUNT(*) AS count "
            f"FROM exposure_items ei JOIN runzero_assets ra ON ra.id = ei.asset_id "
            f"{remediated_where} GROUP BY ra.org, bucket ORDER BY bucket",
            tuple(remediated_params),
        ).fetchall()

        standing_rows = conn.execute(
            f"SELECT ra.org AS org, "
            f"COUNT(*) AS total_intake, "
            f"COALESCE(SUM(CASE WHEN ei.status != 'remediated' THEN 1 ELSE 0 END), 0) AS still_standing, "
            f"COALESCE(SUM(CASE WHEN ei.status = 'remediated' THEN 1 ELSE 0 END), 0) AS remediated_of_cohort "
            f"FROM exposure_items ei JOIN runzero_assets ra ON ra.id = ei.asset_id "
            f"{base_where} GROUP BY ra.org",
            tuple(base_params),
        ).fetchall()
    finally:
        if owned:
            conn.close()

    return {
        "intake_by_day": [
            {"org": r["org"], "date": r["bucket"], "count": r["count"]} for r in intake_rows
        ],
        "remediated_by_day": [
            {"org": r["org"], "date": r["bucket"], "count": r["count"]} for r in remediated_rows
        ],
        "standing": [
            {
                "org": r["org"],
                "total_intake": r["total_intake"],
                "still_standing": r["still_standing"],
                "remediated": r["remediated_of_cohort"],
            }
            for r in standing_rows
        ],
    }


def list_active_display_names(conn=None) -> list:
    """Return display_names of all active users, sorted alphabetically."""
    owned = conn is None
    if owned:
        conn = _connect_db()
    try:
        rows = conn.execute(
            "SELECT display_name FROM users WHERE is_active = 1 ORDER BY display_name"
        ).fetchall()
    finally:
        if owned:
            conn.close()
    return [r[0] for r in rows]
