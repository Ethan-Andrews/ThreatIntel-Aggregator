"""Per-entity hit-frequency baselining for fired detections.

Answers a narrower question than the coverage ledger: not "do we have a
detection for this technique," but "when THIS specific detection fires,
is this specific hit expected given its own history, or something new?"

Deliberately NOT identity/hash matching against literal field values. A rule
that suppresses "we've seen this exact combination before" has exactly the
fragility of an artifact-keyed detection one layer up: an adversary mimicking
a pattern that already reads as routine defeats it trivially, the same way a
filename-keyed rule falls to a rename. What this module tracks instead is
FREQUENCY relative to an entity's own history -- deviation from self, not an
absolute threshold and not exact-match novelty. This is the same principle
already used for telemetry_baseline's column-population history, one layer
up: a column's population share means nothing on its own; what's meaningful
is whether it moved from where it's always been.

Honest limitation, stated plainly rather than glossed over: an entity that is
genuinely malicious but behaves consistently over time will eventually read
as "expected" under this model, the same way any frequency-based baseline
would. This narrows a human reviewer's attention toward what's new or
unusual; it does not and cannot prove absence of a patient, low-and-slow
adversary who matches their own established rhythm. It is a triage aid, not
a verdict.

Bootstrap is honest, not hidden: the first few days after an analytic starts
being tracked, every entity will show 'novel' or 'insufficient_history'
because there IS no history yet. That is correct, expected behavior, not a
gap in the tool -- and it should read that way to whoever's watching, not
as a wall of alarming-looking findings.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

# A day's count under this floor of prior history is not enough to trust an
# average. An entity seen once at count 1 then again at count 4 is not a "4x
# spike" -- it's noise from a two-point sample. Below this floor the
# disposition is honestly insufficient_history, not a false-confidence
# expected or spike.
MIN_HISTORY_DAYS = 3

# Today's count more than this multiple of the historical daily average is a
# spike. Chosen to be generous rather than twitchy: the goal is surfacing
# genuine departures from an entity's rhythm, not re-litigating ordinary
# day-to-day variance.
SPIKE_THRESHOLD = 3.0

# How far back load_entity_history looks when building an entity's baseline.
# Matches the same retention window used elsewhere in this pipeline.
DEFAULT_LOOKBACK_DAYS = 90


@dataclass
class EntityHistory:
    dimension: str
    entity_value: str
    days_seen: int
    total_hits: int
    avg_per_day: float
    max_per_day: int


@dataclass
class HitAssessment:
    dimension: str
    entity_value: str
    today_count: int
    disposition: str  # novel | insufficient_history | expected | spike
    history: EntityHistory | None
    deviation_ratio: float | None

    def to_row(self) -> dict:
        return {
            "dimension": self.dimension,
            "entity_value": self.entity_value,
            "today_count": self.today_count,
            "disposition": self.disposition,
            "days_seen": self.history.days_seen if self.history else 0,
            "avg_per_day": round(self.history.avg_per_day, 2) if self.history else None,
            "deviation_ratio": round(self.deviation_ratio, 2)
                if self.deviation_ratio is not None else None,
        }


# --------------------------------------------------------------- scoring

def assess_hit(dimension: str, entity_value: str, today_count: int,
               history: EntityHistory | None,
               min_history_days: int = MIN_HISTORY_DAYS,
               spike_threshold: float = SPIKE_THRESHOLD) -> HitAssessment:
    """Pure scoring: given today's count and an entity's prior history (or
    none), decide the disposition. No I/O -- everything this function needs
    is passed in, so it's fully testable without a live database or Sentinel
    connection.
    """
    if history is None or history.days_seen == 0:
        return HitAssessment(dimension, entity_value, today_count,
                             disposition="novel", history=None, deviation_ratio=None)

    if history.days_seen < min_history_days:
        return HitAssessment(dimension, entity_value, today_count,
                             disposition="insufficient_history",
                             history=history, deviation_ratio=None)

    ratio = (today_count / history.avg_per_day) if history.avg_per_day > 0 else float("inf")
    disposition = "spike" if ratio > spike_threshold else "expected"
    return HitAssessment(dimension, entity_value, today_count,
                         disposition=disposition, history=history, deviation_ratio=ratio)


def assess_distribution(dimension: str, today_pairs: list[tuple[str, int]],
                        histories: dict[str, EntityHistory | None]) -> list[HitAssessment]:
    """assess_hit() applied across one dimension's today-distribution. A
    thin loop, kept separate from assess_hit() so the per-entity scoring
    stays a pure, single-entity function usable on its own in tests."""
    return [assess_hit(dimension, value, count, histories.get(value))
            for value, count in today_pairs]


# ------------------------------------------------------------- persistence

def load_entity_history(conn, analytic_id: int, dimension: str, entity_value: str,
                        as_of: date, lookback_days: int = DEFAULT_LOOKBACK_DAYS
                        ) -> EntityHistory | None:
    """This entity's daily hit counts strictly BEFORE as_of. Excluding as_of
    itself matters: today's count must never appear in its own baseline, or
    every entity would trivially match itself."""
    start = as_of - timedelta(days=lookback_days)
    rows = conn.execute(
        "SELECT hit_count FROM hit_baseline WHERE analytic_id = ? AND dimension = ? "
        "AND entity_value = ? AND window_start >= ? AND window_start < ?",
        (analytic_id, dimension, entity_value, start, as_of),
    ).fetchall()
    if not rows:
        return None
    counts = [int(r["hit_count"]) for r in rows]
    return EntityHistory(
        dimension=dimension, entity_value=entity_value, days_seen=len(counts),
        total_hits=sum(counts), avg_per_day=sum(counts) / len(counts),
        max_per_day=max(counts),
    )


def record_hit_count(conn, analytic_id: int, dimension: str, entity_value: str,
                     window_start: date, hit_count: int) -> None:
    """Upsert today's count -- this becomes part of tomorrow's history. Must
    be called AFTER load_entity_history() for the same day, never before, or
    the entity would see its own count as history."""
    conn.execute(
        "INSERT INTO hit_baseline (analytic_id, dimension, entity_value, "
        "window_start, hit_count) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (analytic_id, dimension, entity_value, window_start) "
        "DO UPDATE SET hit_count = EXCLUDED.hit_count, recorded_at = now()",
        (analytic_id, dimension, entity_value, window_start, hit_count),
    )
    conn.commit()


# ------------------------------------------------------------- live wiring

def assess_and_record(client, conn, analytic_id: int, body: str,
                      as_of: date | None = None) -> list[HitAssessment]:
    """The full daily cycle for one analytic: pull today's per-dimension hit
    distribution, assess each entity against its stored history, then record
    today's counts so tomorrow's run has this day available as history.

    Reuses tune.py's dimension logic wholesale -- referenced_dimensions() for
    which fields are real, queryable candidates on this rule (not the rule's
    own display aliases, the exact bug fixed there earlier), and
    distribution_query() for the safe-insertion-point query that won't break
    on a rule whose trailing project already renamed the column away.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from tune import referenced_dimensions, distribution_query, is_narrowable

    as_of = as_of or date.today()
    assessments: list[HitAssessment] = []

    # A join (leftanti, in particular) is itself a filter -- distribution_query's
    # safe-insertion-point lands BEFORE it, which is fine for tune.py's proposal
    # use (an over-inclusive candidate is caught by a real count re-check
    # afterward) but wrong here: it would count rows the join later excludes,
    # silently overstating a join-structured rule's true hit distribution.
    # Declining matches is_narrowable()'s existing bias for exactly this rule
    # shape rather than shipping a baseline that's subtly wrong for the
    # highest-value rules (joins tend to be the more selective, interesting
    # ones -- Reflective DLL Load, already in the ledger, is exactly this case).
    eligible, _reason = is_narrowable(body)
    if not eligible:
        return assessments

    for dim in referenced_dimensions(body):
        q = distribution_query(body, dim)
        if q is None:
            continue
        try:
            res = client.query(q, timespan="P1D")
        except Exception:
            continue

        for row in res.dicts():
            value = str(row.get(dim, "")).strip()
            count = int(row.get("Hits") or 0)
            if not value or count == 0:
                continue
            history = load_entity_history(conn, analytic_id, dim, value, as_of)
            assessments.append(assess_hit(dim, value, count, history))
            record_hit_count(conn, analytic_id, dim, value, as_of, count)

    return assessments


# ------------------------------------------------------------------- sweep

DEFAULT_BASELINE_SWEEP_LIMIT = 10
MIN_BASELINE_RECHECK_INTERVAL_HOURS = 6


def due_for_baseline(conn, limit: int = DEFAULT_BASELINE_SWEEP_LIMIT,
                     min_interval_hours: int = MIN_BASELINE_RECHECK_INTERVAL_HOURS) -> list[dict]:
    """Approved analytics not yet baselined today (or whose last baseline
    pass was more than min_interval_hours ago), oldest-swept-first. Scoped
    to review_state='approved': this module tracks *fired* detections'
    per-entity frequency, which only means something for a rule that's
    actually deployed, not a pending/rejected draft."""
    rows = conn.execute(
        "SELECT a.id, a.kql_body, MAX(hb.recorded_at) AS last_recorded "
        "FROM analytics a "
        "LEFT JOIN hit_baseline hb ON hb.analytic_id = a.id "
        "WHERE a.review_state = 'approved' "
        "GROUP BY a.id, a.kql_body "
        "HAVING MAX(hb.recorded_at) IS NULL "
        "       OR MAX(hb.recorded_at) < now() - (? || ' hours')::interval "
        "ORDER BY MAX(hb.recorded_at) ASC NULLS FIRST "
        "LIMIT ?",
        (min_interval_hours, limit),
    ).fetchall()
    return [{"id": r["id"], "kql_body": r["kql_body"]} for r in rows]


def sweep_baseline(client, conn, limit: int = DEFAULT_BASELINE_SWEEP_LIMIT,
                   min_interval_hours: int = MIN_BASELINE_RECHECK_INTERVAL_HOURS,
                   as_of: date | None = None) -> list[tuple[int, list["HitAssessment"]]]:
    """due_for_baseline() -> assess_and_record() for each, once per
    orchestrator run. One analytic's Sentinel query failing (dead
    telemetry, a transient error) must not abort the sweep or the candidate
    batch it runs alongside -- assess_and_record() already swallows
    per-dimension query errors internally, but this also guards the rare
    case of the whole call raising (e.g. is_narrowable() itself erroring on
    a malformed body)."""
    import logging
    logger = logging.getLogger(__name__)
    results = []
    for row in due_for_baseline(conn, limit=limit, min_interval_hours=min_interval_hours):
        try:
            assessments = assess_and_record(client, conn, row["id"], row["kql_body"], as_of=as_of)
            results.append((row["id"], assessments))
        except Exception as exc:  # noqa: BLE001
            logger.warning("BASELINE_SWEEP_FAILED analytic_id=%s: %s", row["id"], exc)
    return results


# ------------------------------------------------------------------ runner

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: hit_baseline.py <analytic_id> [--dry-run]")
        print("  env: SENTINEL_WORKSPACE_ID")
        return 2

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import pgcompat
    from sentinel import SentinelClient

    analytic_id = int(argv[1])
    dry_run = "--dry-run" in argv

    conn = pgcompat.connect()
    row = conn.execute(
        "SELECT a.kql_body, a.review_state, s.technique_id "
        "FROM analytics a JOIN detection_strategies s ON s.id = a.strategy_id "
        "WHERE a.id = ?",
        (analytic_id,),
    ).fetchone()
    if row is None:
        print(f"no analytic #{analytic_id} found")
        conn.close()
        return 1

    print(f"analytic #{analytic_id}  technique={row['technique_id']}  "
          f"review_state={row['review_state']}")

    if dry_run:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from tune import referenced_dimensions
        dims = referenced_dimensions(row["kql_body"])
        print(f"candidate dimensions: {dims or 'none referenced'}")
        conn.close()
        return 0

    client = SentinelClient()
    from tune import is_narrowable
    eligible, reason = is_narrowable(row["kql_body"])
    if not eligible:
        print(f"join/multi-let rule -- distribution-based baselining declined "
              f"({reason}); would silently miscount entities excluded by the "
              f"join, so this analytic isn't tracked yet")
        client.close()
        conn.close()
        return 0

    assessments = assess_and_record(client, conn, analytic_id, row["kql_body"])
    client.close()
    conn.close()

    if not assessments:
        print("no hits today (or no candidate dimensions on this rule)")
        return 0

    counts: dict[str, int] = {}
    for a in assessments:
        counts[a.disposition] = counts.get(a.disposition, 0) + 1
    print(f"\n{len(assessments)} entity-hits assessed: {counts}\n")

    order = {"novel": 0, "spike": 1, "insufficient_history": 2, "expected": 3}
    for a in sorted(assessments, key=lambda x: order.get(x.disposition, 9)):
        detail = ""
        if a.disposition == "spike":
            detail = f"  ({a.today_count} vs avg {a.history.avg_per_day:.1f}/day, " \
                     f"{a.deviation_ratio:.1f}x)"
        elif a.disposition == "expected":
            detail = f"  ({a.today_count} vs avg {a.history.avg_per_day:.1f}/day)"
        elif a.disposition == "insufficient_history":
            detail = f"  (only {a.history.days_seen} day(s) on record)"
        print(f"  [{a.disposition:20}] {a.dimension}={a.entity_value!r}: "
              f"{a.today_count} today{detail}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
