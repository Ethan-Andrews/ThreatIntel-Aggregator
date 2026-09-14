"""TI-to-detection pipeline orchestrator. Entrypoint for the Container Apps Job.

Covers the full pipeline, primary path:

    1-3  ingest, IOC/TTP extraction, "applies to us"   already done by the
                                                       aggregator; this reads
                                                       the result from the
                                                       outbox
    4    redundant TTP coverage                        detections.ai
                                                       coverage-report
    5    draft KQL                                     detections.ai generate
    6    static validation                             static_gate.evaluate()
    7    telemetry control-probe                        control_probe.run_control_probe()
    8    backtest                                        backtest.run_backtest()
    9    bounded tuning (needs_tuning only)              tune.run_tune_loop()

Stages 6-9 run in that order, cheapest-first, before the single INSERT that
registers an analytic -- analytics has no UPDATE grant for the app role (see
pg_detection_strategies.sql), so every validation stage finishes before the
row is written rather than patching results in afterward. A static-gate
reject still gets a row, tagged review_state='rejected', so a human later
sees "already tried, gate rejected it" instead of the pipeline silently
regenerating a duplicate.

The MITRE alignment check (see alignment_check.py) runs immediately after a
passing detection is registered -- it's cheap (one AI call) and catches a
wrong technique tag or a divergence from MITRE's own guidance before the
article's project link ever reaches a human.

Stage 10 (periodic re-confirmation that a shipped 'clean' rule hasn't
silently rotted -- see disposition_tracker.py) runs once per batch, after
the candidate loop, not per candidate: rot is a function of time passing,
not of new TI arriving.

Runs to completion and exits. Safe to overlap with itself: the outbox claims
with FOR UPDATE SKIP LOCKED, and an entry is only marked emitted once its run
succeeds.

    PG_DSN                          required
    DETECTIONS_AI_API_KEY           required
    PIPELINE_BATCH_SIZE             default 5
    PIPELINE_DRY_RUN                "true" to claim and log without calling the API
    PIPELINE_LANGUAGE               default kql
    PIPELINE_DISPOSITION_SWEEP_LIMIT default 10 (see disposition_tracker.py)
"""

from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pgcompat  # noqa: E402
from detection_pipeline import outbox  # noqa: E402
from detection_pipeline import disposition_tracker  # noqa: E402
from detection_pipeline import hit_baseline  # noqa: E402
from detection_pipeline import orchestrator_settings  # noqa: E402
from detection_pipeline import hunts as hunts_module  # noqa: E402
from detection_pipeline import sentinel_hunting  # noqa: E402
from detection_pipeline import hunt_sync_settings  # noqa: E402
from detection_pipeline import sentinel_table_sync  # noqa: E402
from detection_pipeline.detections_client import (  # noqa: E402
    DetectionsAIClient,
    DetectionsAIError,
    PollTimeout,
    PreprocessingFailed,
)
from detection_pipeline.coverage_ledger import (  # noqa: E402
    extract_technique,
    check_coverage,
    register_strategy,
    register_analytic,
    sweep_revalidation,
    DEFAULT_REVALIDATION_SWEEP_LIMIT,
)
from detection_pipeline.alignment_check import check_alignment  # noqa: E402
from detection_pipeline.mitre_sync import get_cached_strategy  # noqa: E402
from detection_pipeline.static_gate import evaluate as gate_evaluate  # noqa: E402
from detection_pipeline.control_probe import run_control_probe  # noqa: E402
from detection_pipeline.backtest import (  # noqa: E402
    run_backtest,
    rule_body,
    DEFAULT_LOOKBACK_DAYS as BACKTEST_LOOKBACK_DAYS,
)
from detection_pipeline.tune import (  # noqa: E402
    run_tune_loop,
    collect_distributions,
    make_count_fn,
    make_field_population_fn,
    make_distribution_fn,
)

# A candidate that fails this many times is consumed rather than retried
# forever. Deliberately low: three failures across three runs is a permanent
# problem, not a rate limit.
MAX_ATTEMPTS = 3

def _record_failure(conn, entry_hash: str, error: str) -> int:
    """Increment and return the failure count for one entry.

    Table (and the app role's DML grant on it) come from
    pg_detection_pipeline_attempts.sql -- no DDL here. The app role has no
    CREATE on schema public, matching every other table's convention.
    """
    row = conn.execute(
        """
        INSERT INTO detection_pipeline_attempts
            (entry_hash, attempts, last_error, last_attempt)
        VALUES (?, 1, ?, to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'))
        ON CONFLICT (entry_hash) DO UPDATE SET
            attempts     = detection_pipeline_attempts.attempts + 1,
            last_error   = EXCLUDED.last_error,
            last_attempt = EXCLUDED.last_attempt
        RETURNING attempts
        """,
        (entry_hash, error[:500]),
    ).fetchone()
    return row["attempts"]


def _clear_failures(conn, entry_hash: str) -> None:
    conn.execute(
        "DELETE FROM detection_pipeline_attempts WHERE entry_hash = ?",
        (entry_hash,),
    )


def _get_saved_project(conn, entry_hash: str) -> str | None:
    """A project already created for this entry in a prior, later-failed run.

    Checked before calling create_project() so a candidate that fails
    downstream of project creation (validation, DB write, alignment check)
    resumes the same detections.ai project on retry instead of creating a
    duplicate -- see pg_detection_pipeline_attempts_project_id.sql.
    """
    row = conn.execute(
        "SELECT project_id FROM detection_pipeline_attempts WHERE entry_hash = ?",
        (entry_hash,),
    ).fetchone()
    return row["project_id"] if row and row["project_id"] else None


def _save_project(conn, entry_hash: str, project_id: str) -> None:
    """Persist a newly-created project_id immediately, ahead of everything
    that can still fail in this candidate's run -- committed by the caller
    right after this returns, independently of the rest of the attempt."""
    conn.execute(
        """
        INSERT INTO detection_pipeline_attempts (entry_hash, project_id, attempts, last_attempt)
        VALUES (?, ?, 0, to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'))
        ON CONFLICT (entry_hash) DO UPDATE SET
            project_id   = EXCLUDED.project_id,
            last_attempt = EXCLUDED.last_attempt
        """,
        (entry_hash, project_id),
    )


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("detection_pipeline")


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes")


def _build_ai_client():
    """Reuses feed_manager's already-configured AI client rather than
    building a second, narrower one that only knows about
    ANTHROPIC_API_KEY -- feed_manager.py also supports AI_PROVIDER=azure
    (Azure AI Foundry's Anthropic-compatible endpoint), and alignment
    checking must not silently disable itself for a Foundry deployment
    that has no ANTHROPIC_API_KEY at all. None when neither provider's
    credential is configured, same discipline as
    feed_manager._ai_configured()."""
    from feed_manager import _ai_client, _ai_configured
    return _ai_client if _ai_configured() else None


def _build_sentinel_client():
    from detection_pipeline.sentinel import SentinelClient
    try:
        return SentinelClient()
    except Exception as exc:
        logger.warning("SentinelClient unavailable, diverges suggestions won't be probed: %s", exc)
        return None


def _build_draft_provider():
    """None when no draft-generation provider is configured.

    This repo still ships and supports DetectionsAIClient (see
    detections_client.py) -- a deployment with DETECTIONS_AI_API_KEY set
    keeps getting real AI-drafted detections exactly as before. What
    changed here is that it is no longer *required*: an OSS user with no
    draft provider at all (only Sentinel-native content, hand-written
    local imports, or nothing yet) must not have the whole batch run
    crash out from under them. Independent of _build_sentinel_client() --
    an operator can have a draft provider with no Sentinel connection, a
    Sentinel connection with no draft provider (exactly the Local
    Detections Import case), both, or neither."""
    try:
        return DetectionsAIClient()
    except DetectionsAIError:
        return None


@dataclass
class RunResult:
    claimed: int = 0
    generated: int = 0
    gaps_found: int = 0
    fully_covered: int = 0
    skipped: int = 0
    failed: int = 0
    detections: int = 0
    alignment_checked: int = 0
    projects: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"claimed={self.claimed} generated={self.generated} "
            f"gaps={self.gaps_found} covered={self.fully_covered} "
            f"detections={self.detections} skipped={self.skipped} "
            f"failed={self.failed}"
        )


def process_one(client, conn, cand, language: str, result: RunResult,
                sentinel_client=None, available_tables: set[str] | None = None) -> None:
    """Run one candidate through detections.ai, then stages 6-9.

    Marks the entry emitted on success and on a permanent failure alike. A
    permanent failure (an unfetchable article URL, for example) will fail the
    same way on every retry, so leaving it unclaimed would make the pipeline
    retry it forever and never drain the outbox. Transient failures are left
    unclaimed deliberately, so the next run picks them up.

    sentinel_client defaults to None so this can still be called directly
    (as the existing tests do) without a live Sentinel workspace -- when
    None, one is built per call; run() builds a single client once per
    batch and passes it in, since SentinelClient caches an Azure bearer
    token that doesn't need re-acquiring per candidate.

    available_tables follows the same "built once per batch, not per
    candidate" shape: None means "look it up fresh" (test-call
    convenience); run() reads the cached Sentinel table catalog
    (sentinel_table_sync.get_tables_for_gate(), which auto-syncs once if
    the cache has never been populated) once per batch and passes it in,
    since it's the same DB read regardless of which candidate is being
    processed. static_gate.gate_evaluate() itself falls back to
    DEFAULT_MDE_TABLES when this is empty.
    """
    if available_tables is None:
        available_tables = sentinel_table_sync.get_tables_for_gate(conn)
    logger.info(
        "CANDIDATE hash=%s severity=%s ttps=%s stack=%s orgs=%s title=%s",
        cand.hash[:12], cand.severity, ",".join(cand.ttps),
        ",".join(cand.stack_matched_items), ",".join(cand.asset_scope),
        cand.title[:70],
    )

    if not cand.link:
        logger.warning("SKIP_NO_LINK hash=%s", cand.hash[:12])
        outbox.mark_emitted(conn, cand.hash)
        conn.commit()
        result.skipped += 1
        return

    started = time.monotonic()
    project_id = _get_saved_project(conn, cand.hash)
    try:
        if project_id is None:
            project_id = client.create_project(
                title=cand.project_title,
                description=(
                    f"Auto-generated from TI aggregator entry {cand.hash}.\n"
                    f"Source: {cand.source} (tier {cand.source_tier})\n"
                    f"Severity: {cand.severity}\n"
                    f"ATT&CK: {', '.join(cand.ttps)}\n"
                    f"Stack: {', '.join(cand.stack_matched_items)}\n"
                    f"Affected orgs: {', '.join(cand.asset_scope) or 'none correlated'}"
                ),
                suffix=cand.hash[:8],
            )
            logger.info("PROJECT_CREATED project=%s title=%s", project_id, cand.project_title[:80])
            # Committed on its own, ahead of everything below that can still
            # fail -- a later failure must not lose track of this project.
            _save_project(conn, cand.hash, project_id)
            conn.commit()
        else:
            logger.info("PROJECT_RESUMED project=%s hash=%s", project_id, cand.hash[:12])

        project_id, report, detections = client.generate_from_project(
            project_id=project_id,
            url=cand.link,
            operation_id=cand.operation_id,
            language=language,
        )

        # One hunt per candidate/article -- every detection generated from
        # this project belongs to the same hunt, mirroring how Sentinel's
        # own Hunts feature groups queries. Idempotent by source_entry_hash,
        # so a resumed candidate reuses its hunt rather than duplicating it.
        hunt_id = hunts_module.get_or_create_hunt(
            conn, cand.hash, title=cand.project_title,
            description=(
                f"Source: {cand.source} (tier {cand.source_tier})\n"
                f"Severity: {cand.severity}\n"
                f"ATT&CK: {', '.join(cand.ttps)}"
            ),
            source_title=cand.title, source_link=cand.link,
            source_name=cand.source, source_severity=cand.severity,
        )

    except PreprocessingFailed as exc:
        # Terminal: the article could not be fetched or parsed. Retrying will
        # produce the identical failure, so consume the entry.
        logger.warning("PREPROCESSING_FAILED hash=%s: %s", cand.hash[:12], exc)
        outbox.mark_emitted(conn, cand.hash)
        conn.commit()
        result.skipped += 1
        return

    except (PollTimeout, DetectionsAIError) as exc:
        # Possibly transient (rate limit, generation queue depth, network).
        # Leave unclaimed so the next run retries; the operation_id makes that
        # resume rather than duplicate.
        #
        # But a candidate that fails every time must not monopolise the queue.
        # Ordering is priority_score DESC, so a permanently failing entry at the
        # head is re-claimed on every run and everything behind it starves. After
        # MAX_ATTEMPTS the entry is consumed and logged for human attention.
        attempts = _record_failure(conn, cand.hash, str(exc))
        if attempts >= MAX_ATTEMPTS:
            logger.error(
                "GIVING_UP hash=%s after %d attempts, marking emitted: %s",
                cand.hash[:12], attempts, exc,
            )
            outbox.mark_emitted(conn, cand.hash)
            conn.commit()
            result.skipped += 1
        else:
            logger.error(
                "GENERATION_FAILED hash=%s attempt=%d/%d: %s",
                cand.hash[:12], attempts, MAX_ATTEMPTS, exc,
            )
            conn.commit()  # keep the attempt count, not the claim
            result.failed += 1
        return

    elapsed = time.monotonic() - started
    result.generated += 1
    result.projects.append(project_id)

    gaps = report.gaps
    result.gaps_found += len(gaps)
    result.detections += len(detections)

    logger.info(
        "RESULT hash=%s project=%s gaps=%d covered=%d undetermined=%d "
        "detections=%d elapsed=%.1fs",
        cand.hash[:12], project_id, len(gaps),
        report.summary.get("covered", 0), len(report.undetermined),
        len(detections), elapsed,
    )

    if not gaps:
        # Everything this article suggests is already covered by the existing
        # rule corpus. That is a success, not a failure: it is exactly what the
        # redundancy check exists to tell us, and it costs nothing further.
        result.fully_covered += 1
        logger.info("FULLY_COVERED hash=%s: no new coverage needed",
                    cand.hash[:12])

    for gap in gaps:
        logger.info(
            "GAP hash=%s technique=%s source=%s title=%s",
            cand.hash[:12], gap.primary_mitre_attack_id,
            gap.data_source, gap.opportunity_title[:70],
        )

    for item in report.undetermined:
        # Not a gap and not covered. Surfaced for a human rather than acted on:
        # generating for these risks duplicating coverage that already exists.
        logger.info(
            "UNDETERMINED hash=%s technique=%s title=%s",
            cand.hash[:12], item.primary_mitre_attack_id,
            item.opportunity_title[:70],
        )

    ai_client = _build_ai_client()
    if sentinel_client is None:
        # Deliberately independent of ai_client -- stages 6-9 are
        # deterministic and have nothing to do with the AI provider. Gating
        # this on ai_client (the old behavior) meant a deployment with no
        # AI key configured would also silently lose all telemetry/
        # backtest/tune validation, which was never the intent.
        sentinel_client = _build_sentinel_client()

    hunt_detections = []  # fed to sentinel_hunting.sync_hunt() after the loop
    for det in detections:
        preview = " ".join(det.content.split())[:150]
        logger.info(
            "DETECTION hash=%s artifact=%s title=%s len=%d\n    %s",
            cand.hash[:12], det.artifact_id, det.title[:60],
            len(det.content), preview,
        )

        parsed = extract_technique(det.content)
        if parsed is None:
            continue
        technique_id, technique_name = parsed
        coverage = check_coverage(conn, technique_id)
        if coverage:
            strategy_id = coverage.strategy_id
        else:
            # Prefer MITRE's own published objective for this technique
            # (same source alignment_check.py compares against) over the
            # bare technique_name -- the latter is only a fallback for a
            # technique with no cached MITRE Detection Strategy. Reads the
            # cache only (get_cached_strategy(), never get_mitre_strategy())
            # -- this runs synchronously in the per-candidate hot loop
            # before stage 6 even starts, so it must never block on a full
            # STIX-bundle sync just to get a nicer objective string; a
            # cache miss degrades to the old technique_name behavior, not
            # a network call. Length-capped regardless of source as
            # defense-in-depth, matching _MITRE_NAME's own 120-char cap in
            # coverage_ledger.py -- an untrusted technique_name is already
            # bounded there, but a MITRE objective sentence has no such
            # cap upstream.
            mitre = get_cached_strategy(conn, technique_id)
            objective = (mitre.objective or technique_name or "")[:500]
            strategy_id = register_strategy(
                conn, technique_id, technique_name,
                objective=objective, chokepoint_tables=[],
            )

        # ---- Stage 6: static gate. Pure text analysis, no I/O, runs first
        # and unconditionally -- cheapest possible check, decides whether
        # any live query budget gets spent on this detection at all.
        gate = gate_evaluate(
            det.content, artifact_id=det.artifact_id, title=det.title,
            available_tables=available_tables,
        )

        control_result = None      # control_probe.ControlProbeResult | None
        backtest_result = None     # backtest.BacktestOutcome | None
        tune_result = None         # tune.TuneResult | None

        if gate.verdict == "pass" and sentinel_client is not None:
            # ---- Stage 7: real per-field telemetry probe, gates backtest.
            control_result = run_control_probe(
                sentinel_client, det.content, artifact_id=det.artifact_id, title=det.title,
            )
            if control_result.telemetry_ok:
                # ---- Stage 8: backtest.
                backtest_result = run_backtest(
                    sentinel_client, det.content, artifact_id=det.artifact_id, title=det.title,
                )
                # ---- Stage 9: bounded tuning loop, only for needs_tuning.
                if backtest_result.disposition == "needs_tuning":
                    body = rule_body(det.content)
                    timespan = f"P{BACKTEST_LOOKBACK_DAYS}D"
                    distributions = collect_distributions(sentinel_client, body, timespan)
                    # tune.py's field_population_fn is single-table by
                    # design (pre-existing constraint). A multi-table rule
                    # only gets narrowing-candidate field checks against
                    # the first probed table -- logged via control_result,
                    # not silently papered over.
                    primary_table = control_result.plan.probes[0].table
                    tune_result = run_tune_loop(
                        artifact_id=det.artifact_id, title=det.title, body=body,
                        original_hits=backtest_result.hits, distributions=distributions,
                        count_fn=make_count_fn(sentinel_client, timespan),
                        field_population_fn=make_field_population_fn(sentinel_client, primary_table),
                        distribution_fn=make_distribution_fn(sentinel_client, timespan),
                    )
        elif gate.verdict == "pass":
            logger.warning(
                "SENTINEL_UNAVAILABLE hash=%s artifact=%s: registering static-gate-only, "
                "no telemetry/backtest/tune validation this run",
                cand.hash[:12], det.artifact_id,
            )

        analytic_id = register_analytic(
            conn, strategy_id, source_entry_hash=cand.hash, kql_body=det.content,
            artifact_id=det.artifact_id,
            name=det.title, description=det.description,
            hunt_id=hunt_id,
            durability=gate.durability,
            disposition=backtest_result.disposition if backtest_result else None,
            tune_history=tune_result.to_row() if tune_result else None,
            static_gate_verdict=gate.verdict,
            static_gate_findings=[{"code": f.code, "detail": f.detail} for f in gate.findings],
            control_probe_result=control_result.to_row() if control_result else None,
            review_state="rejected" if gate.verdict == "reject" else "pending",
        )
        result.alignment_checked += 1
        hunt_detections.append({
            "id": analytic_id, "name": det.title, "description": det.description,
            "kql_body": det.content, "technique_id": technique_id,
            "technique_name": technique_name,
        })

        logger.info(
            "VALIDATION hash=%s artifact=%s gate=%s durability=%.3f control=%s backtest=%s tune=%s",
            cand.hash[:12], det.artifact_id, gate.verdict, gate.durability,
            control_result.disposition if control_result else "skipped",
            backtest_result.disposition if backtest_result else "skipped",
            tune_result.disposition if tune_result else "skipped",
        )

        if ai_client is not None and gate.verdict == "pass":
            try:
                alignment_result = check_alignment(
                    ai_client, sentinel_client, conn, strategy_id, analytic_id=analytic_id,
                )
                logger.info(
                    "ALIGNMENT hash=%s strategy=%s verdict=%s",
                    cand.hash[:12], strategy_id, alignment_result.verdict,
                )
            except Exception as exc:
                logger.warning(
                    "ALIGNMENT_CHECK_FAILED hash=%s strategy=%s analytic=%s: %s",
                    cand.hash[:12], strategy_id, analytic_id, exc,
                )

    logger.info("REVIEW hash=%s url=%s/projects/%s",
                cand.hash[:12],
                os.environ.get("DETECTIONS_AI_BASE_URL", "https://detections.ai"),
                project_id)

    if hunt_detections:
        # Auto-sync only runs when an admin has explicitly opted into
        # hunt_sync_settings.mode == 'auto' (Settings > Hunt Sentinel Sync);
        # 'off' (default) and 'manual' never push automatically here -- a
        # human deploys a hunt manually via POST
        # /api/detections/hunts/{id}/deploy in 'manual' mode instead. Also a
        # no-op whenever SENTINEL_HUNTING_SYNC_ENABLED is unset (the master
        # kill switch, checked inside sync_hunt itself); never fatal to this
        # candidate either way -- see sentinel_hunting.py's module docstring.
        sync_settings = hunt_sync_settings.get_settings(conn)
        if sync_settings["mode"] == "auto":
            # Workstream E cadence gate (docs/superpowers/specs/2026-09-04-
            # live-feedback-round-6-design.md): reuses orchestrator_settings.
            # is_due() as-is rather than a second copy of the same interval/
            # window/day-of-week algorithm -- only the settings source
            # differs. A "not due yet" hunt is skipped silently this cycle,
            # same non-fatal posture as every other auto-sync skip reason.
            sync_due, skip_reason = orchestrator_settings.is_due(
                sync_settings, orchestrator_settings.db_now(conn),
            )
            # Severity gate: severities=None (default) preserves today's
            # behavior exactly -- every eligible hunt syncs regardless of
            # severity. A hunt whose source_severity isn't in the configured
            # set is simply never auto-synced this cycle -- not marked
            # failed, same silent-skip posture as mode == 'off'/'manual'.
            severities = sync_settings.get("severities")
            hunt_severity = None
            if severities:
                sev_row = conn.execute(
                    "SELECT source_severity FROM hunts WHERE id = ?", (hunt_id,)
                ).fetchone()
                hunt_severity = (sev_row["source_severity"] or "").lower() if sev_row else None
            severity_ok = not severities or hunt_severity in severities

            if not sync_due:
                logger.info(
                    "HUNT_AUTO_SYNC_SKIPPED hash=%s hunt_id=%s: %s",
                    cand.hash[:12], hunt_id, skip_reason,
                )
            elif not severity_ok:
                logger.info(
                    "HUNT_AUTO_SYNC_SKIPPED hash=%s hunt_id=%s: severity %r not in configured set %s",
                    cand.hash[:12], hunt_id, hunt_severity, severities,
                )
            else:
                eligible = hunts_module.get_sync_eligible_detections(
                    conn, hunt_id, require_alignment=sync_settings["require_alignment"],
                )
                if eligible:
                    # hunt_id can point at a pre-existing hunt row here too,
                    # not only a brand-new one -- get_or_create_hunt() is
                    # idempotent by source_entry_hash, so a source article
                    # whose entries.emitted_at got reset (e.g. by
                    # scripts/reset_unnamed_detections.py) and reprocesses
                    # reuses the same hunt, target_sentinel_hunt_id included.
                    target_row = conn.execute(
                        "SELECT target_sentinel_hunt_id FROM hunts WHERE id = ?", (hunt_id,)
                    ).fetchone()
                    per_hunt_target = target_row["target_sentinel_hunt_id"] if target_row else None
                    # A hunt's own explicit target (set via hunts.set_hunt_
                    # target()) always wins; only fall back to the admin-
                    # configured auto-deploy default (Settings > Hunt
                    # Sentinel Sync, possibly rolled over to a fresh "In The
                    # News: Hunts vN" if the current one is full) when this
                    # hunt has no override of its own.
                    effective_target = per_hunt_target or sentinel_hunting.resolve_auto_deploy_target(conn)
                    # Recorded right before the push, not after -- a slow
                    # sync must not skew the next fire's elapsed-time check.
                    hunt_sync_settings.mark_run_started(conn)
                    sentinel_hunting.sync_hunt(
                        conn, hunt_id, hunt_title=cand.project_title,
                        hunt_description=cand.title, detections=eligible,
                        target_sentinel_hunt_id=effective_target,
                    )

    _clear_failures(conn, cand.hash)
    outbox.mark_emitted(conn, cand.hash)
    conn.commit()


def run(batch_size: int = 5, dry_run: bool = False, language: str = "kql",
        disposition_sweep_limit: int = disposition_tracker.DEFAULT_SWEEP_LIMIT,
        revalidation_sweep_limit: int = DEFAULT_REVALIDATION_SWEEP_LIMIT,
        baseline_sweep_limit: int = hit_baseline.DEFAULT_BASELINE_SWEEP_LIMIT) -> RunResult:
    result = RunResult()
    conn = pgcompat.connect()
    sentinel_client = None

    try:
        settings = orchestrator_settings.get_settings(conn)
        if not settings["enabled"]:
            logger.info("RUN_SKIPPED disabled_by=%s", settings.get("updated_by"))
            return result

        due, skip_reason = orchestrator_settings.is_due(settings, orchestrator_settings.db_now(conn))
        if not due:
            logger.info("RUN_SKIPPED reason=%s", skip_reason)
            return result
        orchestrator_settings.mark_run_started(conn)

        # Built once per batch run, not per candidate: SentinelClient caches
        # an Azure bearer token, so rebuilding it per candidate would
        # re-authenticate once per candidate for no benefit.
        sentinel_client = _build_sentinel_client()

        pending = outbox.pending_count(conn)
        logger.info("RUN_START pending=%d batch=%d dry_run=%s",
                    pending, batch_size, dry_run)

        if pending == 0:
            logger.info("RUN_END nothing to do")
            return result

        candidates = outbox.claim_candidates(conn, limit=batch_size)
        result.claimed = len(candidates)
        available_tables = sentinel_table_sync.get_tables_for_gate(conn)

        if dry_run:
            for c in candidates:
                logger.info(
                    "DRY_RUN hash=%s op_id=%s severity=%s ttps=%s url=%s",
                    c.hash[:12], c.operation_id, c.severity,
                    ",".join(c.ttps), c.link[:80],
                )
            conn.rollback()  # claim nothing
            logger.info("RUN_END %s", result.summary())
            return result

        provider = _build_draft_provider()
        if provider is None:
            # No draft provider configured (DETECTIONS_AI_API_KEY unset) --
            # release the claim rather than leave these candidates stuck
            # claimed-but-unprocessed, and fall through to the maintenance
            # sweeps below instead of returning early. Those sweeps are
            # deterministic and independent of a draft provider entirely
            # (see _build_draft_provider()'s own docstring), so an OSS
            # deployment with no provider configured still gets real value
            # from every other stage -- this is exactly the coupling bug
            # this decoupling pass exists to fix, not a new limitation.
            logger.info(
                "RUN_NO_PROVIDER claimed=%d: no draft-generation provider "
                "configured; skipping new draft generation and continuing "
                "with existing-detection maintenance sweeps", result.claimed,
            )
            conn.rollback()
            result.claimed = 0
        else:
            with provider:
                who = provider.whoami()
                logger.info("AUTH_OK team=%s", who.get("team_name", "?"))

                for cand in candidates:
                    try:
                        process_one(provider, conn, cand, language, result,
                                   sentinel_client=sentinel_client,
                                   available_tables=available_tables)
                    except Exception as exc:  # noqa: BLE001
                        # One bad candidate must not abort the batch. Counted
                        # against the same MAX_ATTEMPTS cap as a generation
                        # failure -- a candidate that fails downstream (static
                        # gate, control probe, DB write, alignment check) on
                        # every retry must not be reclaimed forever either.
                        # Confirmed live in prod (2026-08-20): a candidate that
                        # kept hitting an unrelated error here was reprocessed on
                        # every 30-minute run indefinitely, since only the
                        # generate_from_url() exception path was ever capped.
                        logger.exception("UNHANDLED hash=%s: %s", cand.hash[:12], exc)
                        conn.rollback()
                        attempts = _record_failure(conn, cand.hash, str(exc))
                        if attempts >= MAX_ATTEMPTS:
                            logger.error(
                                "GIVING_UP hash=%s after %d attempts, marking emitted: %s",
                                cand.hash[:12], attempts, exc,
                            )
                            outbox.mark_emitted(conn, cand.hash)
                        conn.commit()
                        result.failed += 1

        # ---- Stage 10: disposition sweep, once per batch run (not per
        # candidate) -- rot is a function of time passing, not of new TI
        # arriving. Never blocks the run: a sweep failure is logged and
        # dropped, since the candidates above already committed.
        if sentinel_client is not None and not dry_run:
            try:
                swept = disposition_tracker.sweep(sentinel_client, conn, limit=disposition_sweep_limit)
                logger.info("DISPOSITION_SWEEP checked=%d", len(swept))
            except Exception as exc:  # noqa: BLE001
                logger.warning("DISPOSITION_SWEEP_FAILED: %s", exc)

        # ---- Strategy revalidation sweep: coverage_ledger.revalidate_strategy()
        # re-checks an active strategy's telemetry (and, with an AI client,
        # its MITRE alignment) -- previously only ever run manually, never
        # from this automated path. Same once-per-batch, never-blocks
        # discipline as the disposition sweep above; ai_client is optional
        # so a deployment without one configured still gets the telemetry
        # axis instead of skipping revalidation entirely.
        if sentinel_client is not None and not dry_run:
            try:
                ai_client = _build_ai_client()
                revalidated = sweep_revalidation(sentinel_client, conn, ai_client=ai_client,
                                                 sentinel_client=sentinel_client,
                                                 limit=revalidation_sweep_limit)
                logger.info("REVALIDATION_SWEEP checked=%d", len(revalidated))
            except Exception as exc:  # noqa: BLE001
                logger.warning("REVALIDATION_SWEEP_FAILED: %s", exc)

        # ---- Hit-baseline sweep: hit_baseline.assess_and_record() tracks
        # each approved analytic's per-entity firing frequency against its
        # own history -- previously only ever run manually per analytic via
        # its CLI, never scheduled. Idempotent per (analytic, dimension,
        # entity, day), so running it more than once in the same day just
        # refreshes "today so far" -- safe under this every-30-minutes job.
        if sentinel_client is not None and not dry_run:
            try:
                baselined = hit_baseline.sweep_baseline(sentinel_client, conn, limit=baseline_sweep_limit)
                logger.info("BASELINE_SWEEP checked=%d", len(baselined))
            except Exception as exc:  # noqa: BLE001
                logger.warning("BASELINE_SWEEP_FAILED: %s", exc)

        logger.info("RUN_END %s", result.summary())
        if result.projects:
            logger.info("PROJECTS %s", ", ".join(result.projects))
        return result

    finally:
        if sentinel_client is not None:
            sentinel_client.close()
        conn.close()


def main() -> int:
    batch = int(os.environ.get("PIPELINE_BATCH_SIZE", "5"))
    dry = _flag("PIPELINE_DRY_RUN")
    language = os.environ.get("PIPELINE_LANGUAGE", "kql")
    sweep_limit = int(os.environ.get(
        "PIPELINE_DISPOSITION_SWEEP_LIMIT", str(disposition_tracker.DEFAULT_SWEEP_LIMIT)
    ))
    revalidation_limit = int(os.environ.get(
        "PIPELINE_REVALIDATION_SWEEP_LIMIT", str(DEFAULT_REVALIDATION_SWEEP_LIMIT)
    ))
    baseline_limit = int(os.environ.get(
        "PIPELINE_BASELINE_SWEEP_LIMIT", str(hit_baseline.DEFAULT_BASELINE_SWEEP_LIMIT)
    ))

    try:
        result = run(batch_size=batch, dry_run=dry, language=language,
                    disposition_sweep_limit=sweep_limit,
                    revalidation_sweep_limit=revalidation_limit,
                    baseline_sweep_limit=baseline_limit)
    except Exception as exc:  # noqa: BLE001
        logger.exception("RUN_ABORTED: %s", exc)
        return 1

    # Non-zero only when nothing succeeded but something was attempted, so a
    # Container Apps Job shows as failed for a systemic problem and succeeds
    # when individual articles fail for their own reasons.
    if result.failed and not result.generated:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
