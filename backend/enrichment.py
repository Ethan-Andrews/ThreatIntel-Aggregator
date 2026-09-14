"""
enrichment.py — KEV + EPSS enrichment pipeline and priority scoring.

Data sources (both free, no API key required):
  KEV  — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  EPSS — https://api.first.org/data/v1/epss  (FIRST.org, batch up to 30 CVEs)
"""

import datetime
import json
import logging

import httpx

from db import _connect_db, get_all_stack_items_flat, match_entry_against_stack, write_stack_match, persist_runtime_db

logger = logging.getLogger(__name__)

KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

# In-memory set of CVE IDs present in the CISA KEV catalog (uppercase).
# Populated by refresh_kev_cache() at startup and refreshed daily.
_kev_ids: set = set()

# ── Severity / tier weight tables (used in score formula) ─────────────────────

_SEVERITY_WEIGHT = {
    "Critical":      1.00,
    "High":          0.80,
    "Medium":        0.50,
    "Low":           0.20,
    "Informational": 0.05,
    "Unknown":       0.30,
}

_TIER_WEIGHT = {1: 1.00, 2: 0.75, 3: 0.50}


# ── KEV cache ─────────────────────────────────────────────────────────────────

def refresh_kev_cache() -> int:
    """Download the CISA KEV JSON catalog and rebuild the in-memory set.

    Returns the number of CVE IDs loaded (0 on failure, previous cache kept).
    """
    global _kev_ids
    try:
        resp = httpx.get(KEV_URL, timeout=20, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
        new_ids = {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
        _kev_ids = new_ids
        logger.info("KEV cache refreshed: %d entries", len(_kev_ids))
        return len(_kev_ids)
    except Exception as exc:
        logger.warning("KEV cache refresh failed: %s", exc)
        return 0


def is_kev(cve_id: str) -> bool:
    return cve_id.upper() in _kev_ids


# ── EPSS ──────────────────────────────────────────────────────────────────────

def query_epss(cve_ids: list) -> dict:
    """Batch-query FIRST EPSS API for a list of CVE IDs.

    FIRST allows up to ~30 CVEs per request as a comma-separated list.
    Returns {CVE-ID (uppercase): epss_score (float 0..1)}.
    Missing CVEs are omitted from the result.
    """
    if not cve_ids:
        return {}
    results = {}
    for i in range(0, len(cve_ids), 30):
        batch = cve_ids[i : i + 30]
        try:
            resp = httpx.get(
                EPSS_URL,
                params={"cve": ",".join(batch)},
                timeout=12,
                follow_redirects=True,
            )
            resp.raise_for_status()
            for item in resp.json().get("data", []):
                results[item["cve"].upper()] = float(item["epss"])
        except Exception as exc:
            logger.warning("EPSS query failed for batch starting at %d: %s", i, exc)
    return results


# ── Priority score formula ────────────────────────────────────────────────────

def compute_priority_score(tier: int, severity: str, kev_flag: int,
                            epss_score, ingested_str: str,
                            stack_match: bool = False) -> float:
    """Compute a 0.0–1.0 actionability score from enrichment signals.

    Weights (user-specified):
        source tier      0.20
        severity (CVSS proxy)  0.20
        KEV flag         0.30   ← heaviest single signal
        EPSS score       0.20
        recency decay    0.10   (linear: 1.0 at ingest → 0.0 at 30 days)

    Total = 1.00
    """
    tier_norm  = _TIER_WEIGHT.get(int(tier), 0.50)
    sev_norm   = _SEVERITY_WEIGHT.get(severity, 0.30)
    kev_norm   = 1.0 if kev_flag else 0.0
    epss_norm  = float(epss_score) if epss_score is not None else 0.0

    # Recency: linear from 1.0 at ingest to 0.0 at 30 days old
    try:
        ingested_dt = datetime.datetime.fromisoformat(str(ingested_str))
        # SQLite stores UTC without timezone info; treat as UTC
        now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        age_hours = (now_utc - ingested_dt).total_seconds() / 3600
    except Exception:
        age_hours = 0
    recency = max(0.0, 1.0 - (age_hours / 720))  # 720 h = 30 days

    raw = (
        tier_norm * 0.20 +
        sev_norm  * 0.20 +
        kev_norm  * 0.30 +
        epss_norm * 0.20 +
        recency   * 0.10
    )
    if stack_match:
        raw += 0.20
    return round(min(1.0, max(0.0, raw)), 4)


# ── Main enrichment run ───────────────────────────────────────────────────────

def run_enrichment() -> dict:
    """Enrich all triaged, un-enriched entries.

    For each entry:
      1. Check every extracted CVE against the KEV catalog.
      2. Fetch EPSS score (uses the highest score across all CVEs in the entry).
      3. Match title + ai_summary + tags against the configured stack.
      4. Compute a priority_score using the formula above, including the stack
         bonus when the entry matches.
      5. Write kev_flag, epss_score, priority_score, stack_match and
         stack_matched_items back, and mark enriched=1.

    Entries without CVEs still get a priority_score (tier + severity + recency).

    Stack matching used to happen only in run_stack_rematch, which is triggered
    solely by the Your Stack rematch button. Any entry ingested after the last
    button press kept stack_match=0 no matter how many stack keywords it
    contained, and its priority_score was computed without the stack bonus.
    Doing it here makes both correct at ingest time.

    Returns {"enriched": int, "kev_hits": int}.
    """
    conn = _connect_db()
    try:
        rows = conn.execute(
            "SELECT e.hash, e.source, e.severity, e.iocs, e.ingested, "
            "       e.title, e.ai_summary, e.tags, "
            "       COALESCE(s.tier, 3) AS tier "
            "FROM   entries e "
            "LEFT JOIN sources s ON s.name = e.source "
            "WHERE  e.triaged=1 AND e.archived=0 AND e.enriched=0"
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return {"enriched": 0, "kev_hits": 0}

    # Collect unique CVEs across all pending entries
    all_cves: set = set()
    entry_cves: dict = {}
    for row in rows:
        try:
            iocs = json.loads(row["iocs"] or "{}")
            cves = [c.upper() for c in (iocs.get("cves") or []) if isinstance(c, str)]
        except Exception:
            cves = []
        entry_cves[row["hash"]] = cves
        all_cves.update(cves)

    # Batch-fetch EPSS for every unique CVE we found
    epss_map = query_epss(list(all_cves)) if all_cves else {}

    # Load the stack definition once rather than per entry: it is small and
    # unchanged for the duration of a run.
    try:
        stack_items = get_all_stack_items_flat()
    except Exception as exc:
        # A broken stack definition must not stop KEV/EPSS enrichment. Degrade
        # to no matches and say so, rather than failing the whole batch.
        logger.warning("Stack unavailable, enriching without stack match: %s", exc)
        stack_items = []

    # Compute per-entry enrichment values
    kev_hits   = 0
    stack_hits = 0
    updates    = []
    for row in rows:
        cves       = entry_cves[row["hash"]]
        kev_flag   = 1 if any(c in _kev_ids for c in cves) else 0

        epss_scores = [epss_map[c] for c in cves if c in epss_map]
        epss_score  = max(epss_scores) if epss_scores else None

        matched = match_entry_against_stack(dict(row), stack_items) if stack_items else []
        stack_match = 1 if matched else 0

        priority = compute_priority_score(
            row["tier"], row["severity"], kev_flag, epss_score, row["ingested"],
            stack_match=bool(matched),
        )

        if kev_flag:
            kev_hits += 1
        if stack_match:
            stack_hits += 1

        updates.append((
            kev_flag, epss_score, priority, stack_match,
            json.dumps(matched), row["hash"],
        ))

    conn = _connect_db()
    try:
        conn.executemany(
            "UPDATE entries "
            "SET kev_flag=?, epss_score=?, priority_score=?, "
            "    stack_match=?, stack_matched_items=?, enriched=1 "
            "WHERE hash=?",
            updates,
        )
        conn.commit()
    finally:
        conn.close()
    persist_runtime_db()

    logger.info(
        "Enrichment complete: %d entries processed, %d KEV hits, %d stack matches",
        len(updates), kev_hits, stack_hits,
    )
    return {"enriched": len(updates), "kev_hits": kev_hits,
            "stack_matches": stack_hits}


_rematch_running: bool = False


def is_rematch_running() -> bool:
    return _rematch_running


def run_stack_rematch() -> dict:
    """Re-evaluate every active, enriched entry against the current stack.

    For each entry:
      1. Fetch all stack items flat.
      2. Match the entry title + ai_summary + tags against each item's keywords.
      3. Recompute priority_score (including +0.20 if matched).
      4. Persist via write_stack_match.

    Returns {"matched": int, "total": int}.
    """
    global _rematch_running
    if _rematch_running:
        return {"matched": 0, "total": 0, "skipped": True}
    _rematch_running = True
    try:
        stack_items = get_all_stack_items_flat()

        conn = _connect_db()
        rows = conn.execute(
            "SELECT e.hash, e.source, e.severity, e.kev_flag, e.epss_score, "
            "       e.ingested, e.title, e.ai_summary, e.tags, "
            "       COALESCE(s.tier, 3) AS tier "
            "FROM   entries e "
            "LEFT JOIN sources s ON s.name = e.source "
            "WHERE  e.archived=0 AND e.is_duplicate=0 AND e.enriched=1"
        ).fetchall()
        conn.close()

        matched_count = 0
        for row in rows:
            entry = dict(row)
            matched = match_entry_against_stack(entry, stack_items)
            new_score = compute_priority_score(
                entry["tier"], entry["severity"],
                entry["kev_flag"], entry["epss_score"],
                entry["ingested"], stack_match=bool(matched),
            )
            write_stack_match(entry["hash"], matched, new_score)
            if matched:
                matched_count += 1

        logger.info("Stack rematch: %d/%d entries matched", matched_count, len(rows))
        return {"matched": matched_count, "total": len(rows)}
    finally:
        _rematch_running = False


def refresh_and_reenrich() -> dict:
    """Refresh the KEV catalog then reset all enrichment flags so the full
    pipeline re-runs on the next enrichment cycle.  Called once daily."""
    count = refresh_kev_cache()
    if count == 0:
        return {"kev_refreshed": 0, "reset": 0}

    conn = _connect_db()
    cur  = conn.execute(
        "UPDATE entries SET enriched=0 WHERE archived=0 AND triaged=1"
    )
    reset = cur.rowcount
    conn.commit()
    conn.close()
    if reset:
        persist_runtime_db()

    logger.info("Daily KEV refresh: %d KEV IDs, %d entries reset for re-enrichment", count, reset)
    # Run enrichment immediately so scores are fresh
    stats = run_enrichment()
    return {"kev_refreshed": count, "reset": reset, **stats}
