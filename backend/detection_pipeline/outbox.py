"""Outbox reader for the TI-to-detection pipeline.

Claims detection candidates from the aggregator's entries table and marks them
emitted once the pipeline has finished with them.

The gate was measured against real data on 2026-08-03 rather than guessed:

    ttps <> ''        Only 29% of triaged entries carry ATT&CK techniques.
                      Sampling the severe entries without them showed breach
                      notices, patch advisories and legal settlements: correct
                      to exclude, since there is no behaviour to detect on.

    severity          Critical/High/Medium. Informational is the largest single
                      bucket and is almost entirely news.

    stack_match = 1   Does the article touch technology actually in the
                      environment? This is what makes the pipeline sustainable:
                      without it the gate passes ~22 entries/day, which is ~22
                      pull requests a day for a human to review. With it, ~3.

A RunZero asset-match clause was measured and dropped: zero Low/Informational
entries had both techniques and an asset match, so it admitted nothing the
severity clause did not already admit.

Concurrency: claims use FOR UPDATE SKIP LOCKED, so two overlapping job runs
never process the same entry and neither blocks waiting on the other. A run
that dies mid-flight leaves its rows unclaimed for the next run to pick up,
because emitted_at is only set on success.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

GATE_SQL = """
    e.triaged = 1
    AND e.archived = 0
    AND e.is_duplicate = 0
    AND e.emitted_at IS NULL
    AND e.ttps <> ''
    AND e.severity IN ('Critical', 'High', 'Medium')
    AND e.stack_match = 1
"""


@dataclass
class Candidate:
    """One article the pipeline should attempt to build a detection from."""

    hash: str
    title: str
    link: str
    source: str
    source_tier: int
    severity: str
    published: str
    ingested: str
    ai_summary: str
    ttps: list[str] = field(default_factory=list)
    iocs: dict = field(default_factory=dict)
    stack_matched_items: list[str] = field(default_factory=list)
    kev_flag: int = 0
    priority_score: float | None = None
    asset_matches: list[dict] = field(default_factory=list)

    @property
    def operation_id(self) -> str:
        """Idempotency key for detections.ai.

        The article hash carries end to end: entries.hash -> operation_id ->
        pull-request branch name. A retry after a crash resumes the same
        server-side operation rather than paying for a second generation.
        """
        return f"tiagg-{self.hash[:32]}"

    @property
    def project_title(self) -> str:
        return f"[{self.severity}] {self.title}"

    @property
    def asset_scope(self) -> list[str]:
        """Distinct RunZero orgs with a confirmed match.

        Used to scope the backtest. Microsoft Defender advanced hunting is
        capped at three hours of execution time per day across the whole
        tenant, shared with every analyst; querying the entire estate for a
        detection that only affects one org wastes that budget.
        """
        return sorted({m["org"] for m in self.asset_matches
                       if m.get("confidence") == "confirmed" and m.get("org")})


def _loads(raw: Any, default):
    if raw is None or raw == "":
        return default
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return default


def _split_ttps(raw: str) -> list[str]:
    # ttps is stored as a comma-separated string, e.g. "T1059.001,T1547.001".
    if not raw:
        return []
    return [t.strip() for t in raw.split(",") if t.strip()]


def claim_candidates(conn, limit: int = 10) -> list[Candidate]:
    """Claim up to `limit` candidates for this run.

    Does not commit. The caller marks each entry emitted individually as it
    succeeds, so a failure part-way through a batch does not lose the entries
    that already completed.
    """
    rows = conn.execute(
        f"""
        SELECT e.hash, e.title, e.link, e.source, e.severity, e.published,
               e.ingested, e.ai_summary, e.ttps, e.iocs, e.stack_matched_items,
               e.kev_flag, e.priority_score,
               COALESCE(s.tier, 3) AS source_tier
        FROM entries e
        LEFT JOIN sources s ON s.name = e.source
        WHERE {GATE_SQL}
        -- Highest priority first, then oldest: a backlog drains in a sensible
        -- order instead of newest-first starving older entries.
        ORDER BY COALESCE(e.priority_score, 0) DESC, e.ingested ASC
        LIMIT ?
        FOR UPDATE OF e SKIP LOCKED
        """,
        (limit,),
    ).fetchall()

    candidates: list[Candidate] = []
    for r in rows:
        c = Candidate(
            hash=r["hash"],
            title=r["title"] or "",
            link=r["link"] or "",
            source=r["source"] or "",
            source_tier=r["source_tier"],
            severity=r["severity"] or "",
            published=r["published"] or "",
            ingested=r["ingested"] or "",
            ai_summary=r["ai_summary"] or "",
            ttps=_split_ttps(r["ttps"] or ""),
            iocs=_loads(r["iocs"], {}),
            stack_matched_items=_loads(r["stack_matched_items"], []),
            kev_flag=r["kev_flag"] or 0,
            priority_score=r["priority_score"],
        )
        c.asset_matches = _asset_matches(conn, c.hash)
        candidates.append(c)

    if candidates:
        logger.info(
            "OUTBOX_CLAIMED count=%d hashes=%s",
            len(candidates), [c.hash[:12] for c in candidates],
        )
    return candidates


def _asset_matches(conn, entry_hash: str) -> list[dict]:
    """Rolled-up RunZero matches for one entry.

    Rolled up by org and match type rather than returning asset ids: the
    pipeline needs this to scope a backtest, not to enumerate hosts.
    """
    rows = conn.execute(
        """
        SELECT a.org, m.match_type, m.confidence, COUNT(DISTINCT m.asset_id) AS n
        FROM runzero_matches m
        JOIN runzero_assets a ON a.id = m.asset_id
        WHERE m.entry_hash = ?
        GROUP BY a.org, m.match_type, m.confidence
        ORDER BY n DESC
        """,
        (entry_hash,),
    ).fetchall()
    return [
        {"org": r["org"], "match_type": r["match_type"],
         "confidence": r["confidence"], "asset_count": r["n"]}
        for r in rows
    ]


def mark_emitted(conn, entry_hash: str) -> None:
    """Mark one entry as processed. Call only after the pipeline succeeded."""
    conn.execute(
        "UPDATE entries SET emitted_at = "
        "to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS') "
        "WHERE hash = ?",
        (entry_hash,),
    )
    logger.info("OUTBOX_EMITTED hash=%s", entry_hash[:12])


def replay(conn, entry_hash: str) -> None:
    """Clear emitted_at so the entry is claimed again on the next run.

    For re-running a single article after a pipeline fix, without disturbing
    anything else.
    """
    conn.execute(
        "UPDATE entries SET emitted_at = NULL WHERE hash = ?", (entry_hash,)
    )
    logger.info("OUTBOX_REPLAY hash=%s", entry_hash[:12])


def pending_count(conn) -> int:
    """How many candidates are waiting. Cheap: uses the partial index."""
    return conn.execute(
        f"SELECT COUNT(*) AS n FROM entries e WHERE {GATE_SQL}"
    ).fetchone()["n"]
