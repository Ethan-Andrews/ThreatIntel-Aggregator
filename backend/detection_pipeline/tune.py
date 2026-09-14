"""Stage 7: bounded, deterministic rule narrowing.

Takes a needs_tuning backtest result and proposes a narrowing predicate drawn
from the hit distribution the backtest already collected. Deterministic, not
model-written -- the same principle as the control probes: auditable to a
human reviewer, no extra API cost, no run-to-run variance.

Zero hits after narrowing is the goal state, not a failure, provided the
control still shows telemetry present -- a rule that goes quiet because
nobody did the bad thing is exactly what "clean" should look like. What is
NOT acceptable is narrowing that goes quiet because the new predicate
references a field that is dead in this tenant; that relocates the same
false negative the control probe exists to prevent, one layer up. So every
narrowing iteration re-checks population on the specific field it touched,
not just the full rule's hit count.

Bounded at MAX_TUNE_ITERATIONS. Terminal on: zero hits, hit count in the
readable range, no further reduction from the prior iteration, an increase
(a tuner defect, not a fix), or the iteration cap. Every terminal state
routes to human review -- nothing here merges automatically.

The narrowing dimension is deliberately never "which specific device" --
excluding named devices is per-entity allowlisting, the same fragility as an
IOC. Candidates are drawn only from process/account/path dimensions the rule
itself already projects, matching the same "scope by ancestry, not by
identity" principle as the False-Positive-Handling guidance in the Build
Profile.

Only single-table, linear-pipeline rules are auto-narrowed. A rule with
multiple let-bound sub-queries or a join is declined rather than risking an
insertion point that silently breaks the query or changes its join
semantics -- the same "don't guess, degrade safely" choice made for
unavailable_table and unresolved entity columns elsewhere in this pipeline.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

MAX_TUNE_ITERATIONS = 3

# A dimension's top value must carry at least this share of hits to be worth
# excluding. Below this, excluding it wouldn't move the needle much and the
# "narrowing" would be closer to noise than to a real fix.
CONCENTRATION_THRESHOLD = 0.30

# Need at least this many distinct values on a dimension before considering
# exclusion of one. Excluding 1-of-2 values isn't narrowing, it's just
# picking the other branch, and a human should make that call explicitly.
MIN_DIMENSION_VALUES = 3

# Only these dimensions are ever proposed. No DeviceName, no raw identity --
# see module docstring.
CANDIDATE_DIMENSIONS = (
    "InitiatingProcessAccountName",
    "InitiatingProcessFileName",
    "InitiatingProcessFolderPath",
    "AccountName",
    "FileName",
    "FolderPath",
)

# Where in a linear pipeline a new exclusion clause is safe to insert: after
# the last top-level `where`, before anything that could drop the column
# (project, summarize) or reshape rows (sort, take, join, union). Inserting
# after a project that dropped the needed column would produce a clause
# referencing a name no longer in scope.
_BLOCKING_STAGE = re.compile(
    r"^\s*\|\s*(project|summarize|sort|take|top|join|union|extend)\b", re.I | re.M
)
_LET_BINDING = re.compile(r"^\s*let\s+\w+\s*=", re.I | re.M)
_WHERE_LINE = re.compile(r"^\s*\|\s*where\b.*$", re.I | re.M)


@dataclass
class NarrowingCandidate:
    dimension: str
    excluded_value: str
    share: float          # fraction of total hits this value carried
    total_values: int      # distinct values seen on this dimension

    @property
    def predicate(self) -> str:
        # Verbatim string (@"...") matches the convention every real generated
        # rule already uses for path values -- confirmed necessary: a regular
        # double-quoted string treats backslash as an escape character, and a
        # proposed exclusion on a real FolderPath/FileName value (Windows
        # paths are full of backslashes) produced "could not be parsed" at the
        # exact column an unescaped backslash sequence sat. A verbatim string
        # has no such escaping; only a literal double-quote needs doubling.
        escaped = self.excluded_value.replace('"', '""')
        return f'| where {self.dimension} != @"{escaped}"'


@dataclass
class TuneIteration:
    iteration: int
    candidate: NarrowingCandidate
    hits_before: int
    hits_after: int | None = None
    field_check: str = "unchecked"   # ok | dead_field | error
    note: str = ""

    @property
    def effective(self) -> bool:
        return self.hits_after is not None and self.hits_after < self.hits_before


@dataclass
class TuneResult:
    artifact_id: str
    title: str
    original_body: str
    original_hits: int
    iterations: list[TuneIteration] = field(default_factory=list)
    final_body: str = ""
    final_hits: int | None = None
    disposition: str = "needs_human_tuning"
    # clean_after_tuning | tuned | needs_human_tuning | ineffective |
    # not_narrowable

    def to_row(self) -> dict:
        """Shape for detection_backtests.tune_history. Never written into the
        rule body itself -- see the earlier decision that stage 7 must not
        annotate rule logic, since the internal AI tuner owns that surface.

        final_body is only ever populated for the two dispositions where a
        genuine narrowed query exists to show a reviewer ('tuned' and
        'clean_after_tuning') -- every other disposition
        (needs_human_tuning/ineffective/not_narrowable) either never adopted
        a narrowing or adopted one that didn't help, so final_body would
        equal original_body and misleadingly read as "here is a real
        suggestion" when there isn't one. Without this, the only place the
        actual proposed KQL text existed was this in-memory dataclass --
        tune_history recorded iteration bookkeeping (which dimension, which
        value, hit counts) but never the query text itself, so nothing
        downstream had an actual suggestion to show or apply.
        """
        return {
            "original_hits": self.original_hits,
            "final_hits": self.final_hits,
            "disposition": self.disposition,
            "final_body": (
                self.final_body
                if self.disposition in ("tuned", "clean_after_tuning")
                else None
            ),
            "iterations": [
                {
                    "iteration": it.iteration,
                    "dimension": it.candidate.dimension,
                    "excluded_value": it.candidate.excluded_value,
                    "share": round(it.candidate.share, 3),
                    "hits_before": it.hits_before,
                    "hits_after": it.hits_after,
                    "field_check": it.field_check,
                    "note": it.note,
                }
                for it in self.iterations
            ],
        }


# ------------------------------------------------------------- eligibility

def is_narrowable(body: str) -> tuple[bool, str]:
    """Whether this rule's structure is simple enough to auto-narrow safely.

    Returns (eligible, reason). A multi-let or join/union rule is declined --
    see module docstring for why guessing an insertion point there is worse
    than doing nothing.
    """
    if _LET_BINDING.search(body):
        return False, "multi-part rule (let-bound sub-queries): needs manual narrowing"
    if re.search(r"\bjoin\b|\bunion\b", body, re.I):
        return False, "join/union rule: narrowing point is ambiguous, needs manual review"
    if not _WHERE_LINE.search(body):
        return False, "no existing where clause to anchor a new exclusion after"
    return True, ""


# ------------------------------------------------------------------ propose

def propose_narrowing(
    distributions: dict[str, list[tuple[str, int]]],
    excluded_so_far: set[tuple[str, str]],
) -> NarrowingCandidate | None:
    """Pick the single best narrowing candidate across all sampled dimensions.

    distributions maps dimension name -> [(value, hit_count), ...] sorted
    descending, as pulled from the backtest's own evidence query. Returns the
    candidate with the highest concentration meeting the threshold, excluding
    anything already tried. None means no dimension qualifies -- the rule
    needs a human, not another automated pass.
    """
    best: NarrowingCandidate | None = None
    for dim, values in distributions.items():
        if dim not in CANDIDATE_DIMENSIONS:
            continue
        if len(values) < MIN_DIMENSION_VALUES:
            continue
        total = sum(n for _, n in values)
        if total <= 0:
            continue
        top_value, top_hits = values[0]
        if (dim, top_value) in excluded_so_far:
            # Already tried this exact exclusion in an earlier iteration;
            # look at the next-ranked value on this dimension instead.
            remaining = [(v, n) for v, n in values if (dim, v) not in excluded_so_far]
            if not remaining:
                continue
            top_value, top_hits = remaining[0]
        share = top_hits / total
        if share < CONCENTRATION_THRESHOLD:
            continue
        cand = NarrowingCandidate(dimension=dim, excluded_value=top_value,
                                  share=share, total_values=len(values))
        if best is None or cand.share > best.share:
            best = cand
    return best


def _safe_insertion_point(body: str) -> int | None:
    """Line index right after the last top-level `where`, before anything
    that could drop or rename a column a later stage wants to reference
    (project, summarize, sort, take, top, join, union, extend).

    Shared by apply_narrowing() and distribution_query() -- both need to
    land before the same blocking stages, for the same reason: a rule's own
    trailing project frequently renames the exact raw column name either one
    needs to see. Confirmed necessary for distribution_query() specifically:
    a rule that renamed InitiatingProcessFolderPath to FolderPath via project
    caused every distribution query for that column to fail silently (caught,
    skipped) when the summarize was naively appended after the rename.
    """
    lines = body.rstrip().splitlines()
    insert_at = None
    for i, line in enumerate(lines):
        if _WHERE_LINE.match(line):
            insert_at = i + 1
        elif _BLOCKING_STAGE.match(line) and insert_at is not None:
            break
    return insert_at


def apply_narrowing(body: str, candidate: NarrowingCandidate) -> str | None:
    """Insert the exclusion clause at the last safe point in a linear pipeline.

    Returns None if no safe insertion point exists (should not happen if
    is_narrowable() was checked first, but re-verified here defensively --
    silently producing a malformed query is worse than declining).
    """
    lines = body.rstrip().splitlines()
    insert_at = _safe_insertion_point(body)
    if insert_at is None:
        return None
    new_lines = lines[:insert_at] + [candidate.predicate] + lines[insert_at:]
    return "\n".join(new_lines)


# ------------------------------------------------------------------ runner

class CountFn(Protocol):
    """Returns the full-rule hit count for a given rule body."""
    def __call__(self, body: str) -> int: ...


class FieldPopulationFn(Protocol):
    """Returns True if `dimension` has non-trivial population on the tables
    this rule touches. Backed by the same control-probe machinery used
    elsewhere; injected here so the loop's termination logic is testable
    without a live query."""
    def __call__(self, dimension: str) -> bool: ...


class DistributionFn(Protocol):
    """Returns a fresh hit distribution for the given (already-narrowed) rule
    body. Optional -- see run_tune_loop's docstring for what changes when
    it's provided versus omitted."""
    def __call__(self, body: str) -> dict[str, list[tuple[str, int]]]: ...


def run_tune_loop(
    artifact_id: str,
    title: str,
    body: str,
    original_hits: int,
    distributions: dict[str, list[tuple[str, int]]],
    count_fn: CountFn,
    field_population_fn: FieldPopulationFn,
    distribution_fn: DistributionFn | None = None,
    max_iterations: int = MAX_TUNE_ITERATIONS,
) -> TuneResult:
    """Run the bounded narrowing loop for one rule.

    distributions is the starting evidence pull. Without distribution_fn, it
    is never refreshed, and every proposal's share is computed against the
    ORIGINAL total even after an exclusion has already removed a large chunk
    of it -- confirmed to cost real convergence on live data: a rule that
    excluded 70% of its hits on one value found no second candidate, because
    every remaining value's share against the original total fell under the
    30% threshold, even though one of them plausibly dominated what was
    actually left.

    With distribution_fn provided, the loop re-pulls a fresh distribution
    against the narrowed body after each adopted, non-terminal exclusion, so
    the next proposal reflects what is actually left rather than the
    original population. This costs one extra query per continued iteration
    (never on the final one, which is about to terminate anyway) -- omit
    distribution_fn to keep the cheaper, single-pull behavior when that
    tradeoff isn't worth it.
    """
    result = TuneResult(artifact_id=artifact_id, title=title,
                        original_body=body, original_hits=original_hits,
                        final_body=body, final_hits=original_hits)

    eligible, reason = is_narrowable(body)
    if not eligible:
        result.disposition = "not_narrowable"
        result.iterations.append(TuneIteration(
            iteration=0,
            candidate=NarrowingCandidate("", "", 0.0, 0),
            hits_before=original_hits,
            note=reason,
        ))
        return result

    current_body = body
    current_hits = original_hits
    excluded: set[tuple[str, str]] = set()

    for i in range(1, max_iterations + 1):
        candidate = propose_narrowing(distributions, excluded)
        if candidate is None:
            result.disposition = "needs_human_tuning"
            break

        if not field_population_fn(candidate.dimension):
            # The field itself is effectively dead in this tenant. Excluding
            # on it wouldn't be tuning, it would be coincidentally narrowing
            # via a predicate that can barely ever match -- exactly the
            # ambiguity the control probe exists to prevent. Record it, do
            # not apply, try the next candidate on the next loop pass.
            excluded.add((candidate.dimension, candidate.excluded_value))
            result.iterations.append(TuneIteration(
                iteration=i, candidate=candidate, hits_before=current_hits,
                field_check="dead_field",
                note=f"{candidate.dimension} is not populated in this tenant; "
                     f"skipped rather than narrowing on a near-dead field",
            ))
            continue

        narrowed = apply_narrowing(current_body, candidate)
        if narrowed is None:
            result.disposition = "not_narrowable"
            result.iterations.append(TuneIteration(
                iteration=i, candidate=candidate, hits_before=current_hits,
                field_check="error", note="no safe insertion point found",
            ))
            break

        new_hits = count_fn(narrowed)
        excluded.add((candidate.dimension, candidate.excluded_value))
        it = TuneIteration(iteration=i, candidate=candidate,
                           hits_before=current_hits, hits_after=new_hits,
                           field_check="ok")
        result.iterations.append(it)

        if new_hits > current_hits:
            it.note = "narrowing increased hits: tuner defect, not a fix -- stopping"
            result.disposition = "needs_human_tuning"
            break

        if new_hits == current_hits:
            it.note = "no reduction: this dimension isn't separating the noise"
            result.disposition = "needs_human_tuning"
            break

        # Genuine reduction. Adopt it and continue or stop.
        current_body, current_hits = narrowed, new_hits
        result.final_body, result.final_hits = current_body, current_hits

        if new_hits == 0:
            result.disposition = "clean_after_tuning"
            break
        if new_hits <= 3:
            result.disposition = "tuned"
            break
        if i == max_iterations:
            result.disposition = "needs_human_tuning"
            it.note = (it.note + "; " if it.note else "") + "iteration cap reached"
            break

        # Continuing to another iteration: refresh against the narrowed body
        # so the next proposal reflects what's actually left, not the
        # pre-exclusion population. A failed or empty refresh falls back to
        # the existing (now slightly stale) distributions rather than
        # aborting the loop -- a missed refresh should degrade to the old
        # behavior, not stop tuning altogether.
        if distribution_fn is not None:
            try:
                fresh = distribution_fn(current_body)
            except Exception:
                fresh = None
            if fresh:
                distributions = fresh

    else:
        result.disposition = "needs_human_tuning"

    return result


# ------------------------------------------------------------- live wiring

# A name assigned via = in a project/extend/summarize/by clause is a local
# display alias the rule created, not a raw column reference. Deliberately
# not reusing control_query.extract_aliases()'s KNOWN_COLUMNS override here:
# that override exists because a name can be a real column on one table in a
# multi-table union while being an alias on another branch of the same rule.
# tune.py's question is narrower and stricter -- is this name a genuine
# column on THIS rule's specific table -- so any name this rule assigns to is
# excluded outright, regardless of whether it happens to be a legitimate
# column name on some other table entirely.
_ALIAS_TARGET = re.compile(
    r"(?:\bextend\b|\bproject\b|\bsummarize\b|\bby\b|,)\s*"
    r"([A-Za-z][A-Za-z0-9_]*)\s*=(?!=)"
)


def referenced_dimensions(body: str) -> list[str]:
    """Candidate dimensions genuinely referenced as raw columns in the rule
    body -- not merely appearing as a display alias the rule's own project,
    extend, or summarize creates.

    Confirmed necessary: a rule's `project ... AccountName=
    InitiatingProcessAccountName, FileName=InitiatingProcessFileName`
    created local aliases named AccountName and FileName. Because both names
    also happen to be genuine columns on other tables, a plain word-boundary
    match picked them up as narrowing candidates on a table (DeviceNetworkEvents)
    where neither name exists at all -- field_population_fn's direct probe
    then failed to resolve them, was caught safely by its exception handler,
    but reported as "not populated" when the real reason was "this is a
    local alias here, not a column on this table."
    """
    aliased = {m.group(1) for m in _ALIAS_TARGET.finditer(body)}
    return [d for d in CANDIDATE_DIMENSIONS
            if re.search(rf"\b{d}\b", body) and d not in aliased]


def distribution_query(body: str, dimension: str) -> str | None:
    """Hit distribution across one candidate dimension, inserted at the same
    safe point apply_narrowing() uses -- before any project/summarize/sort
    that would already have renamed or dropped the raw column. Returns None
    if there's no safe insertion point, mirroring apply_narrowing()'s decline
    behavior rather than silently sending a query that can't resolve.

    Everything after the insertion point is replaced, not kept: a
    distribution query only needs the rows that already satisfy the rule's
    own where clauses, grouped by one dimension -- the rule's original
    project/sort tail is irrelevant to that and would only risk re-hiding the
    same column again.
    """
    lines = body.rstrip().splitlines()
    insert_at = _safe_insertion_point(body)
    if insert_at is None:
        return None
    tail = [f"| summarize Hits = count() by {dimension}", "| top 20 by Hits desc"]
    return "\n".join(lines[:insert_at] + tail)


def collect_distributions(client, body: str,
                          timespan: str) -> dict[str, list[tuple[str, int]]]:
    """Pull a hit distribution for each candidate dimension the rule
    references. Only worth calling for a needs_tuning, narrowable rule --
    kept separate from backtest.py's evidence collection since "which
    dimension should we narrow on" is a tuning question, not a
    backtest-disposition question."""
    out: dict[str, list[tuple[str, int]]] = {}
    for dim in referenced_dimensions(body):
        q = distribution_query(body, dim)
        if q is None:
            continue
        try:
            res = client.query(q, timespan=timespan)
        except Exception:
            continue
        pairs = [(str(row.get(dim, "")), int(row.get("Hits") or 0))
                 for row in res.dicts()]
        pairs = [(v, n) for v, n in pairs if v]
        if pairs:
            out[dim] = sorted(pairs, key=lambda p: p[1], reverse=True)
    return out


def make_count_fn(client, timespan: str) -> CountFn:
    """count_fn backed by a real Sentinel query: wrap the narrowed body in
    | count, same pattern backtest.py uses for the original hit count."""
    def count_fn(body: str) -> int:
        res = client.query(f"{body}\n| count", timespan=timespan)
        row = res.first()
        return int(row.get("Count") or 0) if row else 0
    return count_fn


def make_field_population_fn(client, table: str) -> FieldPopulationFn:
    """field_population_fn backed by a real Sentinel query: the same
    countif(isnotempty(tostring(field))) shape control_query.py generates,
    scoped to one field. A short window (7 days) since this asks whether the
    field is populated at all, not how often the rule fires -- same
    reasoning as CONTROL_LOOKBACK_DAYS in control_query.py.

    A query error is treated as "not populated" rather than propagated: if
    we can't confirm the field is real, the conservative move is to decline
    narrowing on it, not to assume it's fine.
    """
    def field_population_fn(dimension: str) -> bool:
        q = (
            f"{table}\n"
            f"| where TimeGenerated > ago(7d)\n"
            f"| summarize Total = count(), "
            f"Pop = countif(isnotempty(tostring({dimension})))"
        )
        try:
            res = client.query(q)
        except Exception:
            return False
        row = res.first()
        if not row:
            return False
        total = int(row.get("Total") or 0)
        pop = int(row.get("Pop") or 0)
        return total > 0 and pop > 0
    return field_population_fn


def make_distribution_fn(client, timespan: str) -> DistributionFn:
    """distribution_fn backed by real Sentinel queries: re-collect the hit
    distribution against the already-narrowed body via collect_distributions,
    so propose_narrowing()'s next pick reflects what's actually left rather
    than shares computed against the original, larger total."""
    def distribution_fn(body: str) -> dict[str, list[tuple[str, int]]]:
        return collect_distributions(client, body, timespan)
    return distribution_fn


def verify_clean(client, plan, run_probe_fn) -> tuple[str, list[str]]:
    """Re-check whether a clean or tunable result's underlying fields are
    genuinely populated, rather than trusting a bare hit count.

    A rule reporting 0 hits (or a low, "tunable" count) proves nothing about
    whether the fields it filters on actually contain data -- that is exactly
    the ambiguity the control probe exists to resolve, and it was being
    skipped for every clean/tunable result before this fix: run_backtest()
    only reports the hit count, never re-confirms the telemetry underneath
    it. A rule referencing an unpopulated field can report 0 hits and look
    identical to a genuinely selective one.

    run_probe_fn is injected rather than imported at module scope, matching
    count_fn/field_population_fn elsewhere in this module -- keeps this
    function testable without a live client and avoids a cross-scope import
    bug (a local import inside main() is not visible to a sibling
    module-level function).

    Returns (status, issues): 'ok' with no issues, 'dead_fields' with the
    specific table.field combinations that are unpopulated, or 'error' with
    the control probe's own errors (e.g. a table this rule can't actually
    query against).
    """
    dead: list[str] = []
    errors: list[str] = []
    for table, q in plan.queries():
        outcome = run_probe_fn(client, table, q)
        if outcome.error:
            errors.append(f"{table}: {outcome.error}")
            continue
        if outcome.total == 0:
            dead.append(f"{table}: no telemetry in the lookback window at all")
            continue
        dead.extend(f"{table}.{f}" for f in outcome.dead_fields)
    if errors:
        return "error", errors
    if dead:
        return "dead_fields", dead
    return "ok", []


# ------------------------------------------------------------------ runner

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: tune.py <dump_dir> [--dry-run] [--days N]")
        print("  env: SENTINEL_WORKSPACE_ID")
        return 2

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from static_gate import evaluate, _load_dump
    from control_query import build_plan, DEFAULT_LOOKBACK_DAYS
    from backtest import rule_body, run_backtest
    from sentinel import SentinelClient, run_probe

    dump_dir = Path(argv[1])
    dry_run = "--dry-run" in argv
    days = DEFAULT_LOOKBACK_DAYS
    if "--days" in argv:
        days = int(argv[argv.index("--days") + 1])

    candidates = []
    for f in sorted(dump_dir.glob("kql__*.txt")):
        title, content = _load_dump(f)
        gate = evaluate(content, artifact_id=f.name, title=title)
        if gate.verdict != "pass":
            continue
        plan = build_plan(content, artifact_id=f.name, title=title)
        if not plan.backtestable:
            continue
        candidates.append((f.name, title, content, plan))

    print(f"{len(candidates)} candidates cleared the static gate\n")

    client = None if dry_run else SentinelClient()
    results = []

    for aid, title, content, plan in candidates:
        print("=" * 70)
        print(title[:66])
        body = rule_body(content)

        if dry_run:
            eligible, reason = is_narrowable(body)
            print(f"  narrowable: {eligible}" + (f"  ({reason})" if reason else ""))
            if eligible:
                dims = referenced_dimensions(body)
                print(f"  candidate dimensions: {dims or 'none referenced'}")
            print()
            continue

        bt = run_backtest(client, content, artifact_id=aid, title=title,
                          lookback_days=days, with_evidence=True)
        if bt.error:
            print(f"  backtest error, not tuning: {bt.error}")
            print()
            continue
        if bt.disposition != "needs_tuning":
            if bt.disposition in ("clean", "tunable"):
                status, issues = verify_clean(client, plan, run_probe)
                if status == "ok":
                    print(f"  {bt.disposition}: {bt.hits:,} hits -- verified: "
                          f"all referenced fields confirmed populated")
                else:
                    print(f"  {bt.disposition}: {bt.hits:,} hits -- "
                          f"** UNVERIFIED ({status}) ** do not trust this as-is:")
                    for issue in issues:
                        print(f"      {issue}")
            else:
                print(f"  {bt.disposition}: {bt.hits:,} hits -- no tuning needed")
            print()
            continue

        eligible, reason = is_narrowable(body)
        if not eligible:
            print(f"  needs_tuning but not narrowable: {reason}")
            print()
            continue

        table = plan.probes[0].table if plan.probes else None
        if table is None:
            print("  needs_tuning but no table resolved -- skipping")
            print()
            continue

        timespan = f"P{days}D"
        distributions = collect_distributions(client, body, timespan)
        if not distributions:
            print("  needs_tuning but no candidate dimension has a usable "
                  "distribution -- needs a human")
            print()
            continue

        count_fn = make_count_fn(client, timespan)
        field_population_fn = make_field_population_fn(client, table)
        distribution_fn = make_distribution_fn(client, timespan)

        result = run_tune_loop(
            artifact_id=aid, title=title, body=body,
            original_hits=bt.hits, distributions=distributions,
            count_fn=count_fn, field_population_fn=field_population_fn,
            distribution_fn=distribution_fn,
        )
        results.append(result)

        print(f"  original: {result.original_hits:,} hits")
        for it in result.iterations:
            status = f"{it.hits_after:,}" if it.hits_after is not None else it.field_check
            print(f"    iter {it.iteration}: exclude {it.candidate.dimension}"
                  f"={it.candidate.excluded_value!r} (share={it.candidate.share:.2f}) "
                  f"-> {status}" + (f"  [{it.note}]" if it.note else ""))
        final = result.final_hits if result.final_hits is not None else result.original_hits
        print(f"  disposition: {result.disposition}  final: {final:,} hits")
        print()

    if not dry_run:
        counts: dict[str, int] = {}
        for r in results:
            counts[r.disposition] = counts.get(r.disposition, 0) + 1
        print(f"{len(results)} rules run through tuning: {counts}")
        print("all dispositions route to human review; nothing merges from here")
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))