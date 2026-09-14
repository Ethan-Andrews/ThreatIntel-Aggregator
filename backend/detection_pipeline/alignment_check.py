"""AI-judged comparison between our detection strategies and MITRE ATT&CK's
own Detection Strategy catalog for the same technique -- including its
per-analytic platform, log sources, and mutable elements, not just prose.

Follows this repo's standing AI-security pattern (.claude/rules/ai-security.md,
already used for feed triage in feed_manager.py's _sanitize_for_llm() and
_triage_entry()): externally-sourced text is length-capped and stripped of
injection patterns before reaching a prompt, and the AI's JSON response is
validated field-by-field with any malformed or out-of-vocabulary value
falling back to a safe default rather than a silent bad write.

Never merges without a human: an 'aligned' verdict just records the check
happened; a 'diverges' verdict is telemetry-gated (see telemetry_resolver.py
and _write_diverges() in Task 10) before any suggested fix is validated
through the exact static_gate -> control_query/sentinel -> backtest
pipeline stage 6 already uses for newly-generated KQL, so a human reviewer
always sees either why a fix couldn't be attempted or that fix's own
validation result -- never a blind suggestion.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mitre_sync import get_mitre_strategy

logger = logging.getLogger(__name__)

_VERDICTS = {"aligned", "diverges", "partial"}

ALIGNMENT_SYSTEM_PROMPT = """You compare a detection engineering team's own \
detection strategy for one MITRE ATT&CK technique against MITRE's own \
published Detection Strategy for that same technique, including the \
specific platforms, log sources, and channels MITRE's analytics depend on.

Respond with strict JSON only, no prose outside the JSON object:
{"verdict": "aligned" | "diverges" | "partial", "reasoning": "<1-3 sentences>", \
"suggested_kql": "<KQL string, only when verdict is diverges, else null>"}

- "aligned": our objective and analytic substantively match MITRE's stated \
detection approach for this technique.
- "diverges": MITRE's approach differs in a way that suggests a real gap in \
ours. Only use this verdict when you can propose a concrete KQL fix; put it \
in suggested_kql. Your suggestion may or may not end up validated -- ground \
it in MITRE's stated log sources where possible, but do not assume any \
specific table exists in our tenant.
- "partial": you cannot make a confident judgment either way.
"""


@dataclass
class AlignmentResult:
    strategy_id: int
    verdict: str
    reasoning: str
    suggested_kql: str | None = None
    review_id: int | None = None


def _sanitize_for_prompt(text: str, max_length: int = 4000) -> str:
    """Reuses feed_manager's injection-pattern filter so externally-sourced
    text (MITRE's catalog content) is treated with the same suspicion as
    feed-entry text before it reaches a prompt."""
    from feed_manager import _sanitize_for_llm
    return _sanitize_for_llm(text, max_length=max_length)


def _model_id() -> str:
    """The model/deployment identifier for whichever AI provider
    feed_manager.py is configured for -- AI_PROVIDER=azure routes through
    an Azure AI Foundry deployment name, anything else is a direct
    Anthropic model id. Reused rather than hardcoded so this module keeps
    working under either provider, matching feed_manager._triage_entry()'s
    own branch."""
    import os
    from feed_manager import _ai_provider
    if _ai_provider == "azure":
        return os.environ.get("AZURE_FOUNDRY_DEPLOYMENT", "claude-haiku-4-5")
    return "claude-haiku-4-5-20251001"


def _coerce_verdict_output(raw: str) -> dict:
    """Parse and validate the AI's JSON response. Any malformed or
    out-of-vocabulary output becomes verdict='partial' rather than a
    silent bad write -- same discipline as feed_manager._triage_entry()'s
    inline validation of AI triage output."""
    try:
        cleaned = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(cleaned)
    except (json.JSONDecodeError, AttributeError):
        return {"verdict": "partial", "reasoning": "AI response was not valid JSON.", "suggested_kql": None}

    if not isinstance(parsed, dict):
        return {"verdict": "partial", "reasoning": "AI response was not a JSON object.", "suggested_kql": None}

    verdict = parsed.get("verdict")
    if verdict not in _VERDICTS:
        return {"verdict": "partial", "reasoning": "AI returned an unrecognized verdict.", "suggested_kql": None}

    # Rendered as plain JSX text ({item.ai_reasoning}) in AlignmentReviewPanel,
    # never dangerouslySetInnerHTML -- React already escapes text nodes, so
    # HTML-escaping here has no XSS benefit and only corrupts apostrophes/
    # ampersands into visible "&#39;"-style entities in the UI.
    reasoning = str(parsed.get("reasoning", ""))[:1000]

    suggested_kql = parsed.get("suggested_kql")
    if verdict != "diverges" or not isinstance(suggested_kql, str) or not suggested_kql.strip():
        suggested_kql = None

    return {"verdict": verdict, "reasoning": reasoning, "suggested_kql": suggested_kql}


def _write_aligned(conn, strategy_id: int, reasoning: str) -> AlignmentResult:
    conn.execute(
        "UPDATE detection_strategies SET mitre_alignment_status = 'aligned', "
        "mitre_alignment_checked_at = now(), mitre_alignment_reasoning = ? WHERE id = ?",
        (reasoning, strategy_id),
    )
    conn.commit()
    return AlignmentResult(strategy_id=strategy_id, verdict="aligned", reasoning=reasoning)


def _write_partial(conn, strategy_id: int, analytic_id: int | None, reasoning: str) -> AlignmentResult:
    conn.execute(
        "UPDATE detection_strategies SET mitre_alignment_status = 'partial', "
        "mitre_alignment_checked_at = now(), mitre_alignment_reasoning = ? WHERE id = ?",
        (reasoning, strategy_id),
    )
    row = conn.execute(
        "INSERT INTO alignment_reviews (strategy_id, analytic_id, verdict, ai_reasoning, status) "
        "VALUES (?, ?, 'partial', ?, 'queued_for_rereview') RETURNING id",
        (strategy_id, analytic_id, reasoning),
    ).fetchone()
    conn.commit()
    return AlignmentResult(strategy_id=strategy_id, verdict="partial", reasoning=reasoning,
                           review_id=row["id"])


def _resolve_telemetry_for_analytic(analytic: dict) -> list[dict]:
    """For each log source the analytic references, try to resolve it via
    the platform's registered TelemetryResolver. Returns one entry per log
    source attempted -- resolved or not -- so the dashboard can show
    exactly what was checked, not just a final yes/no."""
    from telemetry_resolver import get_resolver

    platform = analytic.get("platform")
    resolver = get_resolver(platform)
    results = []
    for ls in analytic.get("log_sources", []):
        if resolver is None:
            results.append({**ls, "resolved": None,
                            "reason": f"no telemetry resolver for platform '{platform}'"})
            continue
        resolved = resolver.resolve(ls.get("data_component", ""), ls.get("name", ""),
                                    ls.get("channel", ""), platform)
        if resolved is None:
            results.append({**ls, "resolved": None, "reason": "log source not mapped to a known table"})
        else:
            results.append({**ls, "resolved": {"table": resolved.table, "filter_hint": resolved.filter_hint}})
    return results


def _outcome_ok(outcome) -> bool:
    """True only when a probe outcome is unambiguously healthy -- no error,
    real data, no dead fields. Reads the raw fields rather than a computed
    .disposition property, matching control_probe._outcome_disposition's
    same accommodation: test_alignment_check.py's fake probe outcome is a
    plain types.SimpleNamespace with no .disposition property at all."""
    return (
        not getattr(outcome, "error", "")
        and getattr(outcome, "total", 0) > 0
        and not getattr(outcome, "dead_fields", None)
    )


def _write_diverges(sentinel_client, conn, strategy_id: int, analytic_id: int | None,
                    reasoning: str, suggested_kql: str | None,
                    mitre_analytics: list[dict]) -> AlignmentResult:
    """Telemetry-gated: before the AI's suggested KQL (already drafted in
    the same call that produced the verdict) is ever run through
    static_gate/backtest, resolve whether the divergent analytic's log
    sources are even mapped to known telemetry and, if so, confirm that
    telemetry is actually populated. If either check fails, the draft is
    discarded -- never validated or surfaced -- and the row instead records
    why a fix couldn't be attempted.

    The telemetry probe itself now goes through control_probe.run_control_probe()
    (the real per-field population probe, built from suggested_kql's own
    referenced tables/columns via control_query.build_plan) instead of a bare
    `table | take 1` existence check -- same upgrade orchestrator.py's
    primary path uses for stage 6. Everything else about the sequencing
    (telemetry confirmed -> static_gate -> backtest) is unchanged from
    before.
    """
    target_analytic = mitre_analytics[0] if mitre_analytics else {"log_sources": [], "platform": None}
    log_source_checks = _resolve_telemetry_for_analytic(target_analytic)
    resolved = [c for c in log_source_checks if c.get("resolved")]

    validation: dict = {"log_source_checks": log_source_checks}
    telemetry_ok = False

    if resolved and sentinel_client is not None and suggested_kql:
        from control_probe import run_control_probe
        probe = run_control_probe(sentinel_client, suggested_kql,
                                  artifact_id=f"alignment-strategy-{strategy_id}")
        validation["telemetry_probes"] = [
            {"table": getattr(o, "table", ""), "ok": _outcome_ok(o)}
            for o in probe.outcomes
        ]
        telemetry_ok = probe.telemetry_ok
    elif resolved and (sentinel_client is None or not suggested_kql):
        validation["telemetry_probes"] = "skipped: no sentinel_client provided"

    final_kql = None
    if telemetry_ok and suggested_kql:
        from static_gate import evaluate
        gate = evaluate(suggested_kql, artifact_id=f"alignment-strategy-{strategy_id}")
        validation["static_gate"] = {"verdict": gate.verdict, "durability": gate.durability, "reasons": gate.reasons}
        if gate.verdict == "pass":
            final_kql = suggested_kql
            from backtest import run_backtest
            backtest = run_backtest(sentinel_client, suggested_kql, artifact_id=f"alignment-strategy-{strategy_id}")
            validation["backtest"] = {"disposition": backtest.disposition}
    elif not resolved:
        validation["gap_reason"] = "no log source for this analytic resolved to a known table"
    elif not telemetry_ok:
        validation["gap_reason"] = "resolved table(s) have no confirmed telemetry in this tenant"

    conn.execute(
        "UPDATE detection_strategies SET mitre_alignment_status = 'diverges', "
        "mitre_alignment_checked_at = now(), mitre_alignment_reasoning = ? WHERE id = ?",
        (reasoning, strategy_id),
    )
    row = conn.execute(
        "INSERT INTO alignment_reviews "
        "(strategy_id, analytic_id, verdict, ai_reasoning, suggested_kql, validation_result, status) "
        "VALUES (?, ?, 'diverges', ?, ?, ?, 'pending_review') RETURNING id",
        (strategy_id, analytic_id, reasoning, final_kql, json.dumps(validation)),
    ).fetchone()
    conn.commit()
    return AlignmentResult(strategy_id=strategy_id, verdict="diverges", reasoning=reasoning,
                           suggested_kql=final_kql, review_id=row["id"])


def check_alignment(ai_client, sentinel_client, conn, strategy_id: int,
                    analytic_id: int | None = None) -> AlignmentResult:
    """Compare one detection strategy against MITRE's own Detection
    Strategy for the same technique. ai_client is an Anthropic client;
    sentinel_client is only used on a 'diverges' verdict, to probe whether
    the analytic's required telemetry is actually present before a fix is
    validated (see Task 10) -- pass None if you know this call can only
    resolve aligned or partial (e.g. a technique already confirmed to have
    no MITRE strategy)."""
    row = conn.execute(
        "SELECT technique_id, objective FROM detection_strategies WHERE id = ?",
        (strategy_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"no detection_strategies row for id={strategy_id}")

    if analytic_id is not None:
        kql_row = conn.execute(
            "SELECT kql_body FROM analytics WHERE id = ?", (analytic_id,)
        ).fetchone()
    else:
        kql_row = conn.execute(
            "SELECT kql_body FROM analytics WHERE strategy_id = ? "
            "AND review_state != 'rejected' ORDER BY created_at DESC LIMIT 1",
            (strategy_id,),
        ).fetchone()
    kql_body = kql_row["kql_body"] if kql_row else ""

    try:
        mitre = get_mitre_strategy(conn, row["technique_id"])
    except Exception as exc:
        logger.warning("MITRE sync failed for %s: %s", row["technique_id"], exc)
        return _write_partial(conn, strategy_id, analytic_id,
                              f"MITRE catalog sync failed: {exc}")

    if mitre.det_id is None:
        return _write_partial(conn, strategy_id, analytic_id,
                              "MITRE has no published Detection Strategy for this technique.")

    prompt = (
        f"Our objective: {_sanitize_for_prompt(row['objective'])}\n"
        f"Our KQL:\n{_sanitize_for_prompt(kql_body)}\n\n"
        f"MITRE's objective ({mitre.det_id}): {_sanitize_for_prompt(mitre.objective or '')}\n"
        f"MITRE's analytics (platform, log sources, tuning notes):\n"
        f"{_sanitize_for_prompt(json.dumps(mitre.analytics))}"
    )
    response = ai_client.messages.create(
        model=_model_id(),
        max_tokens=1024,
        system=ALIGNMENT_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    parsed = _coerce_verdict_output(response.content[0].text)

    conn.execute(
        "UPDATE detection_strategies SET mitre_detection_strategy_id = ? WHERE id = ?",
        (mitre.det_id, strategy_id),
    )

    if parsed["verdict"] == "aligned":
        return _write_aligned(conn, strategy_id, parsed["reasoning"])
    if parsed["verdict"] == "partial":
        return _write_partial(conn, strategy_id, analytic_id, parsed["reasoning"])

    return _write_diverges(sentinel_client, conn, strategy_id, analytic_id,
                           parsed["reasoning"], parsed["suggested_kql"], mitre.analytics)


def run_rereview_sweep(ai_client, sentinel_client, conn, batch_size: int = 50) -> list[AlignmentResult]:
    """Bounded pass over the 'partial' backlog. Capped like
    TriageRunRequest's ge=1,le=500 pattern in main.py -- a growing backlog
    must not trigger unbounded AI calls in one run. A result that resolves
    to aligned or diverges marks the old row rereview_resolved; a repeat
    partial leaves it queued_for_rereview untouched, since re-checking it
    again later costs nothing extra."""
    rows = conn.execute(
        "SELECT id, strategy_id, analytic_id FROM alignment_reviews "
        "WHERE status = 'queued_for_rereview' ORDER BY created_at ASC LIMIT ?",
        (batch_size,),
    ).fetchall()

    results = []
    for row in rows:
        result = check_alignment(ai_client, sentinel_client, conn, row["strategy_id"],
                                 analytic_id=row["analytic_id"])
        if result.verdict != "partial":
            conn.execute(
                "UPDATE alignment_reviews SET status = 'rereview_resolved' WHERE id = ?",
                (row["id"],),
            )
            conn.commit()
        results.append(result)
    return results


def main(argv: list[str]) -> int:
    """Manual Cloud Shell entrypoint, mirroring coverage_ledger.py's own
    main() runner -- scheduled execution is a separate, not-yet-built piece
    of work (see the design doc's 'Out of scope' section). Also usable to
    run mitre_sync.sync_all() ad hoc: `python alignment_check.py --sync`."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import pgcompat
    from sentinel import SentinelClient
    from feed_manager import _ai_client, _ai_configured

    conn = pgcompat.connect()

    if len(argv) > 1 and argv[1] == "--sync":
        from mitre_sync import sync_all
        counts = sync_all(conn)
        print(f"synced {counts['strategies']} strategies, {counts['data_components']} data components")
        conn.close()
        return 0

    if not _ai_configured():
        print("no AI provider configured -- set ANTHROPIC_API_KEY, or AI_PROVIDER=azure "
              "plus AZURE_FOUNDRY_API_KEY/AZURE_FOUNDRY_ENDPOINT")
        conn.close()
        return 1

    batch_size = int(argv[1]) if len(argv) > 1 else 50
    ai_client = _ai_client
    sentinel_client = SentinelClient()

    results = run_rereview_sweep(ai_client, sentinel_client, conn, batch_size=batch_size)
    for r in results:
        print(f"strategy #{r.strategy_id}: {r.verdict} -- {r.reasoning[:80]}")
    print(f"\n{len(results)} partial review(s) re-checked")
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
