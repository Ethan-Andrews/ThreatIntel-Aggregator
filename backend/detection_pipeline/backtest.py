"""Stage 6c: full-rule backtest and evidence bundle.

Runs each candidate rule against the Sentinel workspace and counts what it
matches, then pulls enough of the matches for a human to judge them.

The rule body is executed as written. Nothing is rewritten, reformatted or
retimed, because the artifact under test is the rule that would ship -- a
backtest of a modified rule proves something about the modification.

Dispositions, all of which end at a human review:

    hits == 0     clean          the rule fires on nothing in 90 days
    hits 1-3      tunable        few enough to read every hit
    hits > 3      needs_tuning   narrow it, then re-run

Zero is not automatically good and a handful is not automatically bad. What
separates them is the hits themselves, so the evidence bundle -- not the count
-- is the actual output of this stage. A rule matching two events might be
catching exactly the right rare behaviour, or might be overfit to the source
incident and coincidentally matching two unrelated events. Only the rows say
which.

Depends on the control probe having already returned `ok` for every table the
rule touches. Without that, a zero here is uninterpretable.
"""

from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    from detection_pipeline.sentinel import (
        SentinelClient, SentinelError, QuerySemanticError)
    from detection_pipeline.static_gate import strip_comments, evaluate, _load_dump
    from detection_pipeline.control_query import build_plan, DEFAULT_LOOKBACK_DAYS
except ImportError:  # running as a standalone script from this directory
    from sentinel import SentinelClient, SentinelError, QuerySemanticError
    from static_gate import strip_comments, evaluate, _load_dump
    from control_query import build_plan, DEFAULT_LOOKBACK_DAYS

# Hit count at or below which every match can be read individually. Above it the
# reviewer gets a distribution instead, and the rule goes to stage 7 for
# narrowing first.
READABLE_HITS = 3

# Rows pulled for a low-hit rule. A little above READABLE_HITS so a rule that
# just crossed the line still shows its matches.
EVIDENCE_ROWS = 10

# Long command lines and file paths are routine in this telemetry and a full one
# can run to several kilobytes. Truncate for display and storage.
MAX_FIELD_CHARS = 300

# A rule that has not returned by this point is scanning too much to be worth
# the wall clock. Reported, not enforced -- the server has its own timeout.
SLOW_QUERY_SECONDS = 60

_AGO_LITERAL = re.compile(r"\bago\s*\(\s*(\d+)\s*([dhm])\s*\)", re.I)
# Rules routinely bind the window to a name first: `let lookback = 1d;` then
# `where TimeGenerated > ago(lookback)`. Missing this reported a one-day rule as
# a ninety-day one, which inverts how a hit count reads.
_AGO_VARIABLE = re.compile(r"\bago\s*\(\s*([A-Za-z_]\w*)\s*\)", re.I)
_LET_TIMESPAN = re.compile(r"\blet\s+(\w+)\s*=\s*(\d+)\s*([dhm])\s*;", re.I)

_HOURS = {"d": 24.0, "h": 1.0, "m": 1.0 / 60.0}


@dataclass
class BacktestOutcome:
    artifact_id: str
    title: str
    hits: int = 0
    elapsed: float = 0.0
    own_window: str = ""          # the rule's own ago() bound, if it has one
    own_window_hours: float = 0.0
    window_hours: float = 0.0     # the window that actually applied
    evidence_columns: list[str] = field(default_factory=list)
    evidence_rows: list[list] = field(default_factory=list)
    distribution: list[dict] = field(default_factory=list)
    error: str = ""

    @property
    def disposition(self) -> str:
        if self.error:
            return "backtest_error"
        if self.hits == 0:
            return "clean"
        if self.hits <= READABLE_HITS:
            return "tunable"
        return "needs_tuning"

    @property
    def hits_per_90d(self) -> float:
        """Hits normalized to the full retention window.

        A rule bounded to one hour and a rule bounded to ninety days are not
        comparable on raw count. Extrapolation assumes a uniform rate, which is
        wrong in detail but right enough to rank noise.
        """
        if not self.window_hours:
            return float(self.hits)
        return self.hits * (90 * 24.0) / self.window_hours


def rule_body(content: str) -> str:
    """The executable query, with the header comment block removed."""
    return strip_comments(content).strip().rstrip(";")


def own_time_window(body: str) -> tuple[str, float]:
    """The narrowest window the rule sets for itself, as (label, hours).

    The API timespan is an outer bound; the server intersects it with whatever
    the query says. A rule carrying ago(1d) is backtested over one day no matter
    what timespan is passed, and a hit count read against the wrong window
    inverts its meaning -- 173,000 hits is alarming over ninety days and far
    worse over one.

    Handles both a literal ago(30d) and the common let-bound form.
    """
    bound = {name.lower(): (n, unit)
             for name, n, unit in _LET_TIMESPAN.findall(body)}

    found = list(_AGO_LITERAL.findall(body))
    for var in _AGO_VARIABLE.findall(body):
        resolved = bound.get(var.lower())
        if resolved:
            found.append(resolved)

    if not found:
        return "", 0.0
    best = min(found, key=lambda f: int(f[0]) * _HOURS[f[1].lower()])
    return f"ago({best[0]}{best[1]})", int(best[0]) * _HOURS[best[1].lower()]


def count_query(body: str) -> str:
    """Wrap the rule so it returns a single count.

    `| count` operates on any tabular result, including one that already ends in
    a summarize or sort, so the rule needs no inspection to wrap it.
    """
    return f"{body}\n| count"


def evidence_query(body: str, hits: int) -> str:
    """Rows for a low-hit rule, or a distribution for a noisy one."""
    if hits <= READABLE_HITS:
        return f"{body}\n| take {EVIDENCE_ROWS}"
    return (
        f"{body}\n"
        f"| summarize Hits = count() by DeviceName\n"
        f"| top 20 by Hits desc"
    )


def _truncate(value):
    if isinstance(value, str) and len(value) > MAX_FIELD_CHARS:
        return value[:MAX_FIELD_CHARS] + f" ...[+{len(value) - MAX_FIELD_CHARS}]"
    return value


def run_backtest(client: SentinelClient, content: str, artifact_id: str = "",
                 title: str = "", lookback_days: int = DEFAULT_LOOKBACK_DAYS,
                 with_evidence: bool = True) -> BacktestOutcome:
    """Count what the rule matches, then collect evidence for the reviewer."""
    out = BacktestOutcome(artifact_id=artifact_id, title=title)
    body = rule_body(content)
    if not body:
        out.error = "no executable query after stripping comments"
        return out

    out.own_window, out.own_window_hours = own_time_window(body)
    timespan = f"P{lookback_days}D"
    outer_hours = lookback_days * 24.0
    # The server intersects the two, so the narrower one is what ran.
    out.window_hours = (min(out.own_window_hours, outer_hours)
                        if out.own_window_hours else outer_hours)

    started = time.monotonic()
    try:
        res = client.query(count_query(body), timespan=timespan)
    except QuerySemanticError as exc:
        # The rule did not run. Reporting this as zero hits would be the same
        # false negative the control probe exists to prevent.
        out.error = f"semantic: {exc}"
        return out
    except SentinelError as exc:
        out.error = str(exc)
        return out
    out.elapsed = time.monotonic() - started

    row = res.first()
    if row is None:
        out.error = "count returned no rows"
        return out
    # `| count` names its column Count.
    out.hits = int(row.get("Count") or 0)

    if out.hits == 0 or not with_evidence:
        return out

    try:
        ev = client.query(evidence_query(body, out.hits), timespan=timespan)
    except SentinelError as exc:
        # Evidence is supporting material: losing it should not discard a
        # perfectly good hit count.
        out.error = f"evidence unavailable: {exc}"
        return out

    if out.hits <= READABLE_HITS:
        out.evidence_columns = ev.columns
        out.evidence_rows = [[_truncate(v) for v in r] for r in ev.rows]
    else:
        out.distribution = ev.dicts()
    return out


# ------------------------------------------------------------------ runner

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: backtest.py <dump_dir> [--dry-run] [--days N] [--no-evidence]")
        print("  env: SENTINEL_WORKSPACE_ID")
        return 2

    dump_dir = Path(argv[1])
    if not dump_dir.is_dir():
        print(f"not a directory: {dump_dir}")
        return 2

    dry_run = "--dry-run" in argv
    with_evidence = "--no-evidence" not in argv
    days = DEFAULT_LOOKBACK_DAYS
    if "--days" in argv:
        days = int(argv[argv.index("--days") + 1])

    candidates = []
    for f in sorted(dump_dir.glob("kql__*.txt")):
        title, body = _load_dump(f)
        if evaluate(body, artifact_id=f.name, title=title).verdict != "pass":
            continue
        if not build_plan(body, artifact_id=f.name, title=title).backtestable:
            continue
        candidates.append((f.name, title, body))

    print(f"{len(candidates)} candidates; backtest window P{days}D\n")

    if dry_run:
        for _aid, title, content in candidates:
            body = rule_body(content)
            print("=" * 70)
            print(title[:66])
            win, hours = own_time_window(body)
            if win:
                print(f"  rule sets its own bound: {win} ({hours:.0f}h)")
            print(count_query(body))
            print()
        return 0

    client = SentinelClient()
    outcomes = []
    for aid, title, content in candidates:
        out = run_backtest(client, content, artifact_id=aid, title=title,
                           lookback_days=days, with_evidence=with_evidence)
        outcomes.append(out)

        print("=" * 70)
        print(title[:66])
        if out.error and out.hits == 0:
            print(f"  ERROR {out.error}")
            print()
            continue
        window = out.own_window or f"P{days}D"
        slow = "  SLOW" if out.elapsed > SLOW_QUERY_SECONDS else ""
        norm = ""
        if out.own_window_hours and out.own_window_hours < days * 24.0:
            norm = f", ~{out.hits_per_90d:,.0f}/90d"
        print(f"  {out.disposition}: {out.hits:,} hits over {window}{norm} "
              f"({out.elapsed:.1f}s){slow}")
        if out.error:
            print(f"  note: {out.error}")

        if out.evidence_rows:
            print(f"  evidence ({len(out.evidence_rows)} rows):")
            for r in out.evidence_rows:
                pairs = dict(zip(out.evidence_columns, r))
                keep = {k: v for k, v in pairs.items()
                        if k in ("TimeGenerated", "Timestamp", "DeviceName",
                                 "AccountName", "FileName", "FolderPath",
                                 "ProcessCommandLine", "InitiatingProcessFileName",
                                 "InitiatingProcessCommandLine",
                                 "RegistryValueName", "RegistryValueData")}
                print("    " + " | ".join(f"{k}={v}" for k, v in keep.items()))
        elif out.distribution:
            print("  top devices:")
            for d in out.distribution[:10]:
                print(f"    {d.get('DeviceName')}: {d.get('Hits'):,}")
        print()

    counts = {}
    for o in outcomes:
        counts[o.disposition] = counts.get(o.disposition, 0) + 1
    total = sum(o.elapsed for o in outcomes)
    print(f"{len(outcomes)} backtested in {total:.1f}s: {counts}")
    print("all dispositions route to human review; nothing merges from here")
    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))