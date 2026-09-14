import re
import json
import uuid
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

_STOPWORDS = {
    "the", "a", "an", "of", "in", "on", "for", "to", "and",
    "or", "is", "are", "was", "were", "by", "from", "with",
    "that", "this", "its", "as", "at", "be",
}

JACCARD_THRESHOLD = 0.55
DEDUP_WINDOW_HOURS = 72

SEVERITY_RANK = {
    "Critical": 0, "High": 1, "Medium": 2,
    "Low": 3, "Informational": 4, "Unknown": 5,
}


def normalize_title(title: str) -> str:
    return re.sub(r"[^a-z0-9\s]", "", title.lower()).strip()


def _title_words(normalized: str) -> set:
    return {w for w in normalized.split() if w not in _STOPWORDS and len(w) > 2}


def title_jaccard(t1: str, t2: str) -> float:
    t1_norm = normalize_title(t1)
    t2_norm = normalize_title(t2)
    w1, w2 = _title_words(t1_norm), _title_words(t2_norm)
    if not w1 or not w2:
        return 0.0
    return len(w1 & w2) / len(w1 | w2)


def _parse_iocs(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}


def _ioc_overlap(iocs_a: dict, iocs_b: dict) -> bool:
    cves_a = set(iocs_a.get("cves") or [])
    cves_b = set(iocs_b.get("cves") or [])
    if cves_a & cves_b:
        return True

    weak_a = (
        set(iocs_a.get("ips") or [])
        | set(iocs_a.get("hashes") or [])
        | set(iocs_a.get("domains") or [])
    )
    weak_b = (
        set(iocs_b.get("ips") or [])
        | set(iocs_b.get("hashes") or [])
        | set(iocs_b.get("domains") or [])
    )
    return len(weak_a & weak_b) >= 2


def is_exact_duplicate(conn, source: str, normalized_title: str, published_day: str) -> bool:
    # try_date() mirrors SQLite's date(): it yields NULL instead of raising on an
    # empty or unparseable value. feed_manager passes `published or ""`, and many
    # RSS feeds omit pubDate entirely, so a raw ::date cast here would abort the
    # whole poll cycle on one bad entry.
    row = conn.execute(
        """SELECT 1 FROM entries
           WHERE source = ? AND normalized_title = ?
             AND try_date(published) = try_date(?)
           LIMIT 1""",
        (source, normalized_title, published_day),
    ).fetchone()
    return row is not None


def _entries_in_window(conn, published: str) -> list:
    """Return all entries within DEDUP_WINDOW_HOURS of `published`."""
    try:
        dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return []
    lo = (dt - timedelta(hours=DEDUP_WINDOW_HOURS)).isoformat()
    hi = (dt + timedelta(hours=DEDUP_WINDOW_HOURS)).isoformat()
    rows = conn.execute(
        """SELECT hash, source, normalized_title, iocs, group_id
           FROM entries
           WHERE published BETWEEN ? AND ?""",
        (lo, hi),
    ).fetchall()
    return [{"hash": r[0], "source": r[1], "normalized_title": r[2],
             "iocs": _parse_iocs(r[3]), "group_id": r[4]} for r in rows]


def _assign_group(conn, hashes: list, group_id: str) -> None:
    for h in hashes:
        conn.execute(
            "UPDATE entries SET group_id = ? WHERE hash = ?", (group_id, h)
        )


def run_dedup_pass(conn, new_hashes: list) -> None:
    """Group newly-ingested entries with existing entries by title/IOC similarity."""
    if not new_hashes:
        return

    placeholders = ",".join("?" * len(new_hashes))
    new_rows = conn.execute(
        f"""SELECT hash, source, normalized_title, iocs, published, group_id
            FROM entries WHERE hash IN ({placeholders})""",
        new_hashes,
    ).fetchall()

    for row in new_rows:
        h, source, norm_title, raw_iocs, published, current_gid = row
        if current_gid:
            continue

        iocs_e = _parse_iocs(raw_iocs)
        candidates = _entries_in_window(conn, published or "")

        matches = []
        for c in candidates:
            if c["hash"] == h:
                continue
            jaccard = title_jaccard(norm_title or "", c["normalized_title"] or "")
            if jaccard >= JACCARD_THRESHOLD or _ioc_overlap(iocs_e, c["iocs"]):
                matches.append(c)

        if not matches:
            continue

        matched_groups = {c["group_id"] for c in matches if c["group_id"]}

        if not matched_groups:
            gid = str(uuid.uuid4())
            ungrouped_hashes = [c["hash"] for c in matches if not c["group_id"]]
            _assign_group(conn, [h] + ungrouped_hashes, gid)
        elif len(matched_groups) == 1:
            gid = matched_groups.pop()
            ungrouped_hashes = [c["hash"] for c in matches if not c["group_id"]]
            _assign_group(conn, [h] + ungrouped_hashes, gid)
        else:
            group_sizes = {}
            for gid in matched_groups:
                count = conn.execute(
                    "SELECT COUNT(*) FROM entries WHERE group_id = ?", (gid,)
                ).fetchone()[0]
                group_sizes[gid] = count
            canonical_gid = max(group_sizes, key=group_sizes.get)
            for old_gid in matched_groups:
                if old_gid != canonical_gid:
                    conn.execute(
                        "UPDATE entries SET group_id = ? WHERE group_id = ?",
                        (canonical_gid, old_gid),
                    )
            ungrouped_hashes = [c["hash"] for c in matches if not c["group_id"]]
            _assign_group(conn, [h] + ungrouped_hashes, canonical_gid)

    conn.commit()


def backfill_dedup_groups(conn) -> None:
    """Run dedup on all existing ungrouped entries. Idempotent."""
    # Populate normalized_title for entries ingested before the column was added.
    null_rows = conn.execute(
        "SELECT hash, title FROM entries WHERE normalized_title IS NULL AND title IS NOT NULL"
    ).fetchall()
    if null_rows:
        for h, title in null_rows:
            conn.execute(
                "UPDATE entries SET normalized_title = ? WHERE hash = ?",
                (normalize_title(title), h),
            )
        conn.commit()
        logger.info(
            "backfill_dedup_groups: populated normalized_title for %d entries", len(null_rows)
        )

    rows = conn.execute(
        "SELECT hash FROM entries WHERE group_id IS NULL ORDER BY published ASC"
    ).fetchall()
    hashes = [r[0] for r in rows]
    logger.info("backfill_dedup_groups: processing %d ungrouped entries", len(hashes))
    run_dedup_pass(conn, hashes)
