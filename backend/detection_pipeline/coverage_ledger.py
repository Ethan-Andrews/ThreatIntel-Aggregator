"""Technique-indexed coverage ledger: check existing coverage before treating
a new TI-sourced gap as automatically requiring a new detection.

The core question this answers: for a given ATT&CK technique, does an active
Detection Strategy already exist? If yes, a new article describing that
technique is evidence to evaluate against EXISTING coverage, not an automatic
trigger for a new analytic. If no, it's a genuine gap.

Deliberately technique-granular (T1053.005), not tactic-granular
(Persistence) -- "we're covered in Persistence" is enumeration wearing a
behavioral costume; "we're covered for T1053.005 specifically" is a claim
that can actually be checked against a new article's specifics. See
pg_detection_strategies.sql for the schema rationale.

What this module does NOT do: decide whether an existing strategy's logic
actually generalizes to a new article's specifics. That judgment -- "does it
still generalize" -- is the single hardest, highest-value open problem this
whole pipeline is built toward automating, and it stays a human call for now.
This module's job is narrower: surface existing coverage so a human doesn't
have to remember what's already been built, and give whatever eventually
automates that judgment a durable place to write its answer.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Self-bootstrapped (not just the lazy inserts already used below) because
# this needs to resolve at *module* load time for the top-level
# `from alignment_check import check_alignment` right after it -- callers
# that import this module via the detection_pipeline package path (e.g.
# orchestrator.py's `from detection_pipeline.coverage_ledger import ...`)
# only put backend/ on sys.path, not detection_pipeline/ itself, so a bare
# `import alignment_check` would fail without this.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from alignment_check import check_alignment

# The primary technique ID from a rule's header comment. Rules routinely list
# several ("T1606 - Forge Web Credentials, T1528 - Steal Application Access
# Token"); the FIRST is treated as primary -- what the ledger indexes on --
# and the rest are context, not separate coverage claims. A rule genuinely
# covering two techniques equally is rare enough that forcing a choice here,
# with the rest visible in the stored kql_body's own header, is a reasonable
# simplification rather than a multi-valued schema for a rare case.
_MITRE_ID = re.compile(r"MITRE ATT&CK:\s*(T\d{4}(?:\.\d{3})?)", re.I)
# [^\n,]+ alone assumes a real newline character ends the header line. When
# the rule body instead arrives with escaped newlines (literal "\n" -- a
# backslash followed by the letter n, not a linefeed), that assumption
# breaks: nothing stops the match at end-of-line, and it runs on into every
# following line until the next real comma -- confirmed live 2026-08-31,
# where an entire YARA rule body ended up as a "technique_name". Excluding
# a literal backslash from the character class stops the match at that same
# escaped "\n" either way, and the length cap is defense-in-depth against
# any other pathological content this pattern hasn't hit yet.
_MITRE_NAME = re.compile(r"MITRE ATT&CK:\s*T\d{4}(?:\.\d{3})?\s*-\s*([^\n,\\]{1,120})", re.I)


def extract_technique(content: str) -> tuple[str, str] | None:
    """Pull (technique_id, technique_name) from a rule's header comment.
    None if the header has no MITRE ATT&CK line at all."""
    id_match = _MITRE_ID.search(content)
    if not id_match:
        return None
    technique_id = id_match.group(1).upper()
    name_match = _MITRE_NAME.search(content)
    technique_name = name_match.group(1).strip() if name_match else ""
    return technique_id, technique_name


@dataclass
class ExistingAnalytic:
    id: int
    artifact_id: str
    source_entry_hash: str
    durability: float | None
    disposition: str | None
    review_state: str


@dataclass
class ExistingCoverage:
    strategy_id: int
    technique_id: str
    technique_name: str
    objective: str
    status: str
    analytics: list[ExistingAnalytic] = field(default_factory=list)
    corroboration_count: int = 0
    confidence: str = "unproven"
    last_validated_at: object = None       # datetime | None, kept loose to avoid an import here
    last_validation_result: str | None = None
    mitre_detection_strategy_id: str | None = None


def corroboration_count(conn, strategy_id: int) -> int:
    """How many independent articles have corroborated this strategy via
    coverage_evidence -- point 1 of the trust-building plan. A strategy
    seeded once and never independently re-tested should visibly read as
    unproven, not as confirmed, regardless of how confident the original
    seed looked."""
    row = conn.execute(
        "SELECT count(*) AS n FROM coverage_evidence "
        "WHERE strategy_id = ? AND verdict = 'corroborates'",
        (strategy_id,),
    ).fetchone()
    return int(row["n"]) if row else 0


def confidence_label(count: int) -> str:
    """Deliberately three coarse buckets, not a numeric score -- a fake-precision
    number invites exactly the false confidence this whole mechanism exists to
    prevent. Zero is the important case: 'unproven' should read as a real
    caution, not just a low number next to a technique ID."""
    if count == 0:
        return "unproven"
    if count < 3:
        return "lightly corroborated"
    return "well corroborated"


def check_coverage(conn, technique_id: str) -> ExistingCoverage | None:
    """Does an active strategy already exist for this exact technique?

    None means a genuine gap -- no existing claim to evaluate against. A
    non-None result does NOT mean "skip generation": it means a human
    reviewing this gap should see what already exists -- including how
    corroborated and how recently re-validated it is -- and judge whether it
    still applies, per this module's central open question.
    """
    row = conn.execute(
        "SELECT id, technique_id, technique_name, objective, status, "
        "last_validated_at, last_validation_result, mitre_detection_strategy_id "
        "FROM detection_strategies WHERE technique_id = ? AND status = 'active'",
        (technique_id,),
    ).fetchone()
    if row is None:
        return None

    analytics_rows = conn.execute(
        "SELECT id, artifact_id, source_entry_hash, static_gate_durability, "
        "backtest_disposition, review_state FROM analytics "
        "WHERE strategy_id = ? ORDER BY created_at DESC",
        (row["id"],),
    ).fetchall()

    count = corroboration_count(conn, row["id"])

    return ExistingCoverage(
        strategy_id=row["id"],
        technique_id=row["technique_id"],
        technique_name=row["technique_name"],
        objective=row["objective"],
        status=row["status"],
        analytics=[
            ExistingAnalytic(
                id=a["id"], artifact_id=a["artifact_id"] or "",
                source_entry_hash=a["source_entry_hash"],
                durability=float(a["static_gate_durability"])
                    if a["static_gate_durability"] is not None else None,
                disposition=a["backtest_disposition"], review_state=a["review_state"],
            )
            for a in analytics_rows
        ],
        corroboration_count=count,
        confidence=confidence_label(count),
        last_validated_at=row["last_validated_at"],
        last_validation_result=row["last_validation_result"],
        mitre_detection_strategy_id=row["mitre_detection_strategy_id"],
    )


def register_strategy(conn, technique_id: str, technique_name: str, objective: str,
                      chokepoint_tables: list[str]) -> int:
    """Create a new strategy row. Called only after a human has confirmed a
    check_coverage() miss is a genuine gap, not automatically."""
    row = conn.execute(
        "INSERT INTO detection_strategies "
        "(technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, technique_name, objective, chokepoint_tables),
    ).fetchone()
    conn.commit()
    return row["id"]


def register_analytic(conn, strategy_id: int, source_entry_hash: str, kql_body: str,
                      artifact_id: str = "", durability: float | None = None,
                      disposition: str | None = None,
                      tune_history: dict | None = None,
                      static_gate_verdict: str | None = None,
                      static_gate_findings: list[dict] | None = None,
                      control_probe_result: dict | None = None,
                      review_state: str = "pending",
                      name: str | None = None,
                      description: str | None = None,
                      hunt_id: int | None = None,
                      origin: str = "ai_generated") -> int:
    """Attach a validated analytic to a strategy. Reuses stage 5-8 output
    directly (verdict/findings/durability from static_gate.py, the probe
    result from control_probe.py, disposition from backtest.py, tune_history
    from tune.py's TuneResult.to_row()) rather than re-deriving or
    duplicating any of it.

    name/description come from detections.ai's Detection.title/description
    at generation time (see orchestrator.py's process_one()) -- persisting
    them is what lets every downstream consumer (disposition alerts,
    alignment review, the catalog, hunts) identify a row by more than the
    MITRE technique it shares with every other analytic on the same
    strategy. Empty strings are stored as NULL, not as a visible-but-blank
    value.

    analytics has no UPDATE grant for the app role (see
    pg_detection_strategies.sql) -- every validation stage must finish
    before this single INSERT, not be patched in afterward. review_state
    defaults to 'pending' but a caller passes 'rejected' for a static-gate
    reject, so the row still records that generation was attempted and why
    it didn't proceed, instead of the pipeline silently regenerating a
    duplicate later.

    Idempotent on artifact_id (added 2026-09-01, confirmed live: three rows
    shared one artifact_id, created ~20-30 minutes apart -- one per
    orchestrator run, matching a candidate that generated and registered
    successfully but failed before outbox.mark_emitted() and got reclaimed
    on the next cycle, re-registering the same already-generated detection
    as a brand-new row every time). Checked at the application layer, not
    only via pg_analytics_artifact_id_unique.sql's partial unique index --
    that migration is applied by hand (see root CLAUDE.md's migration
    gotchas) and may lag behind this code in a given environment, so this
    check must not depend on it existing yet. A caller with no artifact_id
    (empty string, no reasonable identity to dedupe on) always inserts, as
    before.
    """
    import json
    if artifact_id:
        existing = conn.execute(
            "SELECT id FROM analytics WHERE artifact_id = ?", (artifact_id,)
        ).fetchone()
        if existing:
            return existing["id"]
    row = conn.execute(
        "INSERT INTO analytics "
        "(strategy_id, artifact_id, source_entry_hash, kql_body, "
        " static_gate_durability, backtest_disposition, tune_history, "
        " static_gate_verdict, static_gate_findings, control_probe_result, "
        " review_state, name, description, hunt_id, origin) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        (strategy_id, artifact_id, source_entry_hash, kql_body,
         durability, disposition,
         json.dumps(tune_history) if tune_history is not None else None,
         static_gate_verdict,
         json.dumps(static_gate_findings) if static_gate_findings is not None else None,
         json.dumps(control_probe_result) if control_probe_result is not None else None,
         review_state, name or None, description or None, hunt_id, origin),
    ).fetchone()
    conn.commit()
    return row["id"]


def record_coverage_evidence(conn, strategy_id: int, source_entry_hash: str,
                             verdict: str, reasoning: str = "",
                             reviewed_by: str = "") -> int:
    """Log a new article's relationship to an existing strategy: corroborates
    (the existing analytic plausibly covers this new tool too), gap_new_analytic
    (same technique, different mechanism -- needs a new analytic under the
    same strategy), or uncertain (needs a closer human look).
    """
    row = conn.execute(
        "INSERT INTO coverage_evidence "
        "(strategy_id, source_entry_hash, verdict, reasoning, reviewed_by) "
        "VALUES (?, ?, ?, ?, ?) RETURNING id",
        (strategy_id, source_entry_hash, verdict, reasoning, reviewed_by or None),
    ).fetchone()
    conn.commit()
    return row["id"]


def revalidate_strategy(client, conn, strategy_id: int, ai_client=None,
                        sentinel_client=None) -> str:
    """Re-run every analytic under this strategy's control probe (is the
    telemetry it depends on still there -- point 2 of the trust-building
    plan) and, when ai_client is provided, re-check it against MITRE's own
    Detection Strategy for the same technique (see alignment_check.py).

    Both axes feed the same one-way downgrade: a bad result on either one
    moves the strategy to needs_review. Never auto-reverts to active on a
    good result on either axis -- moving a strategy back to active after
    review is a human action.

    ai_client is optional and defaults to None so existing callers (and any
    strategy revalidated before an AI provider was configured) keep working
    unchanged; sentinel_client defaults to None too, meaning a 'diverges'
    verdict found here still gets its suggested fix telemetry-gated
    (Task 10), just without the ability to confirm telemetry positively --
    same degraded-but-safe behavior as orchestrator.py's generation-time
    check without a SentinelClient.
    """
    # Prefer the package-qualified import so run_probe's `except
    # QuerySemanticError`/`SentinelError` binds to the SAME class objects
    # `client` (built by orchestrator.py's _build_sentinel_client() via
    # `from detection_pipeline.sentinel import SentinelClient`) actually
    # raises. The bare `from sentinel import ...` fallback loads sentinel.py
    # a second time under a different module name -- Python does not
    # deduplicate that -- so its QuerySemanticError is a distinct class from
    # detection_pipeline.sentinel.QuerySemanticError, and `except
    # QuerySemanticError` silently fails to match, letting a real semantic
    # error (bad table/column name) escape run_probe's error handling
    # entirely instead of being recorded as a normal "error" outcome.
    # Confirmed live 2026-09-01: three strategies revalidating a query
    # against a nonexistent table/column raised straight through to
    # sweep_revalidation's generic except, so last_validated_at never
    # advanced and the strategy never got the needs_review downgrade this
    # function exists to apply -- same fix pattern already used in
    # backtest.py's module-level import.
    try:
        from detection_pipeline.control_query import build_plan
        from detection_pipeline.sentinel import run_probe
    except ImportError:  # running as a standalone script from this directory
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from control_query import build_plan
        from sentinel import run_probe

    rows = conn.execute(
        "SELECT id, kql_body FROM analytics WHERE strategy_id = ? "
        "AND review_state != 'rejected'",
        (strategy_id,),
    ).fetchall()

    worst = "ok"
    for row in rows:
        plan = build_plan(row["kql_body"])
        if not plan.probes:
            worst = "degraded"
            continue
        for table, q in plan.queries():
            outcome = run_probe(client, table, q)
            if outcome.error:
                worst = "error"
            elif (outcome.total == 0 or outcome.dead_fields) and worst != "error":
                worst = "degraded"

    if ai_client is not None:
        alignment_result = check_alignment(ai_client, sentinel_client, conn, strategy_id)
        if alignment_result.verdict == "diverges" and worst not in ("error",):
            worst = "alignment_diverges"

    needs_review = worst in ("degraded", "error", "alignment_diverges")
    conn.execute(
        "UPDATE detection_strategies SET last_validated_at = now(), "
        "last_validation_result = ?, "
        "status = CASE WHEN ? THEN 'needs_review' ELSE status END "
        "WHERE id = ?",
        (worst, needs_review, strategy_id),
    )
    conn.commit()
    return worst


DEFAULT_REVALIDATION_SWEEP_LIMIT = 10
MIN_REVALIDATION_INTERVAL_HOURS = 24


def due_for_revalidation(conn, limit: int = DEFAULT_REVALIDATION_SWEEP_LIMIT,
                         min_interval_hours: int = MIN_REVALIDATION_INTERVAL_HOURS) -> list[int]:
    """Active strategies never revalidated, or last revalidated before the
    cutoff -- oldest-first, never-revalidated sorts first. Scoped to
    status='active' only: a strategy already sitting in needs_review has
    already surfaced what revalidate_strategy() would tell a human again,
    and re-flagging it every sweep adds no new information until a person
    acts on the existing flag."""
    rows = conn.execute(
        "SELECT id FROM detection_strategies WHERE status = 'active' "
        "AND (last_validated_at IS NULL "
        "     OR last_validated_at < now() - (? || ' hours')::interval) "
        "ORDER BY last_validated_at ASC NULLS FIRST LIMIT ?",
        (min_interval_hours, limit),
    ).fetchall()
    return [r["id"] for r in rows]


def sweep_revalidation(client, conn, ai_client=None, sentinel_client=None,
                       limit: int = DEFAULT_REVALIDATION_SWEEP_LIMIT) -> list[tuple[int, str]]:
    """due_for_revalidation() -> revalidate_strategy() for each, once per
    orchestrator run. A single strategy's revalidation failing (a bad
    Sentinel query, a transient AI-call error) must not abort the sweep or
    the candidate batch it runs alongside -- matches disposition_tracker's
    sweep() never-blocks discipline. Returns (strategy_id, worst) pairs for
    the ones that completed; failures are logged by the caller, not raised.
    """
    import logging
    logger = logging.getLogger(__name__)
    results = []
    for strategy_id in due_for_revalidation(conn, limit=limit):
        try:
            worst = revalidate_strategy(client, conn, strategy_id,
                                        ai_client=ai_client, sentinel_client=sentinel_client)
            results.append((strategy_id, worst))
        except Exception as exc:  # noqa: BLE001
            logger.warning("REVALIDATION_FAILED strategy_id=%s: %s", strategy_id, exc)
    return results


def set_mitre_reference(conn, strategy_id: int, mitre_detection_strategy_id: str) -> None:
    """Record a human's manual cross-reference to MITRE's own Detection
    Strategies catalog (DETxxxx) for this technique. Not automated lookup or
    matching -- point 3's comparison judgment (does MITRE's own strategy for
    this technique agree with ours, does ours still generalize) stays a
    human call per the standing agreement. This just gives that judgment a
    durable place once made, the same role coverage_evidence plays for the
    narrower "does it still generalize" question.
    """
    conn.execute(
        "UPDATE detection_strategies SET mitre_detection_strategy_id = ? WHERE id = ?",
        (mitre_detection_strategy_id, strategy_id),
    )
    conn.commit()


def mitre_technique_url(technique_id: str) -> str:
    """The MITRE ATT&CK technique page for a technique_id -- where a human
    doing the point-3 comparison would start. Sub-technique dots become path
    segments (T1055.001 -> /techniques/T1055/001/); MITRE has no stable,
    documented technique-id -> DETxxxx lookup endpoint, so this points a
    human at the right page to search from rather than guessing at a scrape.
    """
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"


def check_opportunities(conn, gaps: list) -> list[tuple[object, "ExistingCoverage | None"]]:
    """Check detections.ai's own gap-status opportunities against our ledger
    BEFORE generation is requested for any of them -- earlier than
    check_coverage() is used elsewhere in this module, which only sees
    already-generated KQL.

    Takes CoverageItem-shaped objects (detections_client.CoverageItem, or
    anything with .primary_mitre_attack_id and .opportunity_title) as
    returned by DetectionsAIClient.coverage_report(), which runs before
    generate() in generate_from_url(). Reuses check_coverage() entirely --
    same lookup, just called at the point where it can still change whether
    generation happens at all, not just after the fact.
    """
    results = []
    for gap in gaps:
        technique_id = (getattr(gap, "primary_mitre_attack_id", "") or "").upper().strip()
        coverage = check_coverage(conn, technique_id) if technique_id else None
        results.append((gap, coverage))
    return results


# ------------------------------------------------------------------ runner

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: coverage_ledger.py <dump_dir>")
        return 2

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from static_gate import evaluate, _load_dump
    import pgcompat

    dump_dir = Path(argv[1])
    conn = pgcompat.connect()

    checked = 0
    no_technique = 0
    genuine_gaps = 0
    existing = 0

    for f in sorted(dump_dir.glob("kql__*.txt")):
        title, content = _load_dump(f)
        gate = evaluate(content, artifact_id=f.name, title=title)
        if gate.verdict != "pass":
            continue
        checked += 1

        parsed = extract_technique(content)
        if parsed is None:
            no_technique += 1
            print(f"{title[:60]:60}  no MITRE ATT&CK header -- cannot check coverage")
            continue

        technique_id, technique_name = parsed
        coverage = check_coverage(conn, technique_id)

        if coverage is None:
            genuine_gaps += 1
            print(f"{title[:60]:60}  {technique_id:12} GENUINE GAP -- no existing strategy")
        else:
            existing += 1
            print(f"{title[:60]:60}  {technique_id:12} EXISTING COVERAGE "
                  f"(strategy #{coverage.strategy_id}, {len(coverage.analytics)} analytic(s), "
                  f"{coverage.confidence}, {coverage.corroboration_count} corroboration(s))")
            if coverage.last_validated_at is None:
                print("      never revalidated -- run revalidate_strategy() to check current telemetry")
            else:
                print(f"      last validated {coverage.last_validated_at}: "
                      f"{coverage.last_validation_result}")
            if coverage.mitre_detection_strategy_id:
                print(f"      MITRE cross-reference: {coverage.mitre_detection_strategy_id}")
            for a in coverage.analytics[:3]:
                dur = f"{a.durability:.2f}" if a.durability is not None else "?"
                print(f"      analytic #{a.id}: durability={dur} "
                      f"disposition={a.disposition or '?'} review={a.review_state}")

    conn.close()
    print(f"\n{checked} gate-passing candidates: {genuine_gaps} genuine gaps, "
          f"{existing} against existing coverage, {no_technique} missing a "
          f"MITRE ATT&CK header entirely")
    print("no automatic action taken -- coverage status is advisory for human review")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
