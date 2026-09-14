"""Stage 6b: control query and field-population probe generation.

A backtest returning zero hits is ambiguous. It means either the rule is
correctly specific and nobody did this, or the rule can never fire here because
a field it tests is never populated in this tenant. Hit counts cannot separate
those two, and the second is the failure mode a tuning loop will happily
converge on.

This module builds the query that separates them, deterministically:

  1. Find every column the rule uses in a predicate.
  2. Emit one summarize per table measuring total rows and how many have each
     of those columns populated.

Total of zero means no telemetry. A column at zero means a dead predicate. Both
are terminal, and neither costs more than a single summarize to establish.

Generation is deliberately deterministic rather than model-driven. A
model-written control query can be silently narrower than the rule it is meant
to bound, which reproduces the ambiguity it exists to remove, and it leaves no
auditable trail for the reviewer.

Depends on static_gate for comment stripping: the detections.ai header block
names columns in prose and would otherwise pollute extraction.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    from detection_pipeline.static_gate import strip_comments, _load_dump
except ImportError:  # running as a standalone script from this directory
    from static_gate import strip_comments, _load_dump


# ------------------------------------------------------------ time columns

# MDE advanced hunting exposes Timestamp on the Device* tables. TimeGenerated
# exists only in the Log Analytics / Sentinel copy of the same data. A rule
# using the wrong one for its destination does not return zero rows -- it fails
# to execute on an unknown column.
#
# Detections from this pipeline are saved as Sentinel hunts, so TimeGenerated is
# correct and Timestamp is the anomaly.
MDE_TIME_COLUMN = "Timestamp"
SENTINEL_TIME_COLUMN = "TimeGenerated"
TIME_COLUMNS = {MDE_TIME_COLUMN, SENTINEL_TIME_COLUMN}

# Workspace retention is 90 days across all tables. A rule with no hits over 90
# days on a populated table is far stronger evidence than the same result over
# 30, so the full-rule backtest uses the whole window.
DEFAULT_LOOKBACK_DAYS = 90

# The control probe answers a narrower question -- does this table carry data
# and are these columns filled -- which a short window settles just as well.
# At roughly 1.4 billion rows per 90 days on the busier tables, scanning the
# full window to establish that a column exists is wasted work.
CONTROL_LOOKBACK_DAYS = 7

# Columns that genuinely exist on the Device* tables. A rule may alias a name
# that is also a real column elsewhere -- the ServiceMain rule creates an empty
# RegistryValueData on its process branch, where it is an alias, while the same
# name is a real column on DeviceRegistryEvents. This set lets a real column
# survive alias exclusion.
KNOWN_COLUMNS = {
    "AccountDomain", "AccountName", "AccountSid", "ActionType", "AdditionalFields",
    "AppGuardContainerId", "DeviceId", "DeviceName", "FileName", "FileSize",
    "FolderPath", "InitiatingProcessAccountDomain", "InitiatingProcessAccountName",
    "InitiatingProcessAccountSid", "InitiatingProcessCommandLine",
    "InitiatingProcessCreationTime", "InitiatingProcessFileName",
    "InitiatingProcessFileSize", "InitiatingProcessFolderPath", "InitiatingProcessId",
    "InitiatingProcessMD5", "InitiatingProcessParentFileName",
    "InitiatingProcessParentId", "InitiatingProcessSHA1", "InitiatingProcessSHA256",
    "InitiatingProcessTokenElevation", "InitiatingProcessVersionInfoCompanyName",
    "InitiatingProcessVersionInfoProductName", "LocalIP", "LocalPort", "LogonId",
    "MD5", "ProcessCommandLine", "ProcessCreationTime", "ProcessId",
    "ProcessIntegrityLevel", "ProcessTokenElevation", "ProcessVersionInfoCompanyName",
    "ProcessVersionInfoOriginalFileName", "ProcessVersionInfoProductName", "Protocol",
    "RegistryKey", "RegistryValueData", "RegistryValueName", "RegistryValueType",
    "RemoteIP", "RemoteIPType", "RemotePort", "RemoteUrl", "ReportId", "SHA1",
    "SHA256", "SharedFolderName", "Timestamp", "TimeGenerated",
}


# --------------------------------------------------------------- extraction

# Operators whose left operand is a column being tested.
_PREDICATE_OPS = (
    r"==|=~|!=|!~|<=|>=|<|>|"
    r"\bhas_any\b|\bhas_all\b|\bhas\b|\bcontains\b|\bnot?contains\b|"
    r"\bstartswith\b|\bendswith\b|\bin~?\b|\bmatches\s+regex\b|\bbetween\b"
)
_PREDICATE = re.compile(r"\b([A-Z][A-Za-z0-9_]{2,})\s*(?:!?\s*)(?:" + _PREDICATE_OPS + r")", re.I)

# Columns wrapped in a null/emptiness test are equally load-bearing.
_WRAPPED = re.compile(
    r"\b(?:isempty|isnotempty|isnull|isnotnull|tolower|toupper|strlen|"
    r"array_length|parse_json|tostring|todynamic)\s*\(\s*([A-Za-z][A-Za-z0-9_]*)\s*\)"
)

# Columns passed as an aggregation-function argument inside summarize. Neither
# _PREDICATE (needs a comparison operator) nor _WRAPPED (fixed function list)
# catches sum(BytesSent) -- confirmed missing when a rule referenced sum() on a
# column that does not exist on DeviceNetworkEvents in the documented MDE
# schema at all. The control probe passed clean because this column was never
# extracted, and the failure only surfaced at backtest time. Probing it now
# means a nonexistent aggregation target fails at the control-probe stage
# (probe_error) instead of silently reaching a live backtest.
_AGG_ARG = re.compile(
    r"\b(?:sum|avg|min|max|dcount|any|arg_max|arg_min|stdev|variance|"
    r"percentile)\s*\(\s*([A-Za-z][A-Za-z0-9_]*)"
)

# A table opening a statement, optionally bound by let.
_TABLE_STMT = re.compile(
    r"(?:^|;|\blet\s+\w+\s*=)\s*([A-Z][A-Za-z0-9]{5,})\s*(?:\n|\s)*\|", re.M
)

# Names the rule creates for itself via project, extend or summarize. Probing
# one of these fails the entire control query on an unknown identifier, which is
# worse than losing a probe column, so exclusion is deliberately aggressive:
# aliases are collected across the whole body rather than per fragment, because
# a name aliased in one let block is routinely compared in another.
_ALIAS = re.compile(
    r"(?:\bextend\b|\bproject\b|\bsummarize\b|\bby\b|,)\s*"
    r"([A-Za-z][A-Za-z0-9_]*)\s*=(?!=)"
)

# KQL keywords, operators and functions that the predicate regex can pick up.
_NOT_COLUMNS = {
    "where", "project", "summarize", "extend", "let", "join", "union", "count",
    "distinct", "top", "take", "limit", "sort", "order", "render", "mvexpand",
    "parse", "evaluate", "invoke", "range", "print", "datatable", "materialize",
    "and", "or", "not", "by", "on", "kind", "inner", "leftouter", "rightouter",
    "fullouter", "anti", "semi", "asc", "desc", "ago", "now", "bin", "case",
    "iff", "iif", "todatetime", "totimespan", "toint", "tolong", "toreal",
    "dcount", "countif", "sumif", "make_set", "make_list", "arg_max", "arg_min",
    "startofday", "endofday", "format_datetime", "datetime_diff", "split",
    "strcat", "substring", "indexof", "replace", "trim", "extract", "hourofday",
    "true", "false", "null", "dynamic", "real", "long", "int", "string", "bool",
}


# The "how widely is this happening" dimension varies by table family. A
# Device* or Identity* table counts distinct devices via DeviceName. Entra ID
# sign-in tables have no comparable device column -- DeviceDetail is a nested
# dynamic blob, not a flat scalar -- so the analogous breadth signal there is
# distinct principal instead.
#
# Confirmed necessary, not theoretical: a WHfB/FIDO2 article generated five
# SigninLogs rules, and the unconditional dcount(DeviceName) that used to sit
# here failed every one of them with "Failed to resolve scalar expression
# named 'DeviceName'" before a single Pop_ column was ever evaluated -- the
# same failure shape as the QueryTime/ExecTime alias leak fixed earlier, just a
# different hardcoded assumption.
_ENTITY_COLUMN_BY_TABLE = {
    "SigninLogs": "UserPrincipalName",
    "AADNonInteractiveUserSignInLogs": "UserPrincipalName",
    "AADServicePrincipalSignInLogs": "ServicePrincipalName",
    "AADManagedIdentitySignInLogs": "ServicePrincipalName",
    "ADFSSignInLogs": "UserId",
}


def _entity_column(table: str) -> str | None:
    """The natural breadth dimension for this table, if a safe one is known.

    Returns None rather than guessing for an unrecognised table. An absent
    breadth count only weakens the probe's context; a wrong column name breaks
    the entire query, which is the failure this function exists to prevent.
    """
    if table in _ENTITY_COLUMN_BY_TABLE:
        return _ENTITY_COLUMN_BY_TABLE[table]
    if table.startswith("Device") or table.startswith("Identity"):
        return "DeviceName"
    return None


@dataclass
class TableProbe:
    table: str
    columns: list[str] = field(default_factory=list)

    def control_query(self, time_column: str = SENTINEL_TIME_COLUMN,
                      lookback_days: int = CONTROL_LOOKBACK_DAYS) -> str:
        """Population probe for this table.

        Total answers whether telemetry exists. Each Pop_ column answers whether
        a predicate the rule depends on can ever be true. Entities, when a safe
        dimension is known for this table, answers how widely it is spread.

        isnotempty(tostring(col)) rather than either function alone. isnotempty
        is a string function and errors on datetimes and ints; isnotnull counts
        an empty string as populated, which made every string column report
        exactly 100 percent and carry no signal. tostring of a null yields an
        empty string, so the composed form works across types and treats blank
        as unpopulated.
        """
        entity_col = _entity_column(self.table)
        lines = [
            self.table,
            f"| where {time_column} > ago({lookback_days}d)",
            "| summarize",
            "    Total = count(),",
        ]
        if entity_col:
            lines.append(f"    Entities = dcount({entity_col}),")

        exclude = {entity_col, "DeviceName"} - {None}
        probes = [c for c in self.columns
                  if c not in TIME_COLUMNS and c not in exclude]
        for i, col in enumerate(probes):
            comma = "," if i < len(probes) - 1 else ""
            lines.append(
                f"    Pop_{col} = countif(isnotempty(tostring({col}))){comma}")
        if not probes:
            # No predicate columns beyond time (and entity, if present): strip
            # the trailing comma so the query stays valid.
            lines[-1] = lines[-1].rstrip(",")
        return "\n".join(lines)


@dataclass
class ControlPlan:
    artifact_id: str
    title: str
    probes: list[TableProbe] = field(default_factory=list)
    time_columns_used: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    dropped_aliases: list[str] = field(default_factory=list)

    @property
    def target(self) -> str:
        """Which backend the rule as written will actually execute against."""
        if SENTINEL_TIME_COLUMN in self.time_columns_used:
            return "sentinel"
        if MDE_TIME_COLUMN in self.time_columns_used:
            return "mde"
        return "unbounded"

    @property
    def backtestable(self) -> bool:
        """False when no control can be built, which is terminal for stage 6."""
        return bool(self.probes)

    def queries(self, time_column: str | None = None,
                lookback_days: int = CONTROL_LOOKBACK_DAYS) -> list[tuple[str, str]]:
        # Detections land as Sentinel hunts, so TimeGenerated is the default
        # regardless of what the rule body happens to use.
        tc = time_column or SENTINEL_TIME_COLUMN
        return [(p.table, p.control_query(tc, lookback_days)) for p in self.probes]


def _blank_literals(text: str) -> str:
    """Replace string literal contents with spaces, preserving offsets.

    Column extraction must not see identifiers that happen to appear inside a
    quoted value.
    """
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        verbatim = False
        if ch == "@" and i + 1 < n and text[i + 1] in "\"'":
            verbatim = True
            i += 1
            ch = text[i]
        if ch in "\"'":
            quote = ch
            i += 1
            while i < n:
                c = text[i]
                if not verbatim and c == "\\" and i + 1 < n:
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if c == quote:
                    break
                out[i] = " "
                i += 1
            i += 1
            continue
        i += 1
    return "".join(out)


def _split_by_table(body: str) -> list[tuple[str, str]]:
    """Segment the rule into (table, fragment) pairs.

    A multi-table rule binds each table in its own let statement, so columns are
    attributed to the nearest preceding table reference. Columns appearing after
    a join or union, which belong to whichever branch produced them, are
    attributed to the last table seen -- imprecise, but the probe is per table
    and a spurious extra column only costs one countif.
    """
    matches = list(_TABLE_STMT.finditer(body))
    if not matches:
        return []
    segments = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        segments.append((m.group(1), body[start:end]))
    return segments


def extract_aliases(text: str) -> set[str]:
    """Names the rule creates via project, extend, summarize or a by clause.

    A name that is also a genuine table column is kept: the ServiceMain rule
    aliases RegistryValueData to an empty string on its process branch while the
    same name is a real column on DeviceRegistryEvents.
    """
    return {m.group(1) for m in _ALIAS.finditer(text)
            if m.group(1) not in KNOWN_COLUMNS}


def extract_columns(fragment: str) -> list[str]:
    """Columns used in a predicate within this fragment, first-seen order."""
    found = []
    for m in _PREDICATE.finditer(fragment):
        col = m.group(1)
        if col.lower() in _NOT_COLUMNS:
            continue
        if col not in found:
            found.append(col)
    for m in _WRAPPED.finditer(fragment):
        col = m.group(1)
        if col.lower() in _NOT_COLUMNS or not col[0].isupper():
            continue
        if col not in found:
            found.append(col)
    for m in _AGG_ARG.finditer(fragment):
        col = m.group(1)
        if col.lower() in _NOT_COLUMNS or not col[0].isupper():
            continue
        if col not in found:
            found.append(col)
    return found


def build_plan(content: str, artifact_id: str = "", title: str = "") -> ControlPlan:
    """Derive the control plan for one detection."""
    plan = ControlPlan(artifact_id=artifact_id, title=title)

    body = _blank_literals(strip_comments(content))

    for tc in (MDE_TIME_COLUMN, SENTINEL_TIME_COLUMN):
        if re.search(r"\b" + tc + r"\b", body):
            plan.time_columns_used.append(tc)

    if plan.target == "mde":
        plan.warnings.append(
            "uses Timestamp: detections here are saved as Sentinel hunts, where "
            "the Device* tables expose TimeGenerated instead"
        )
    elif plan.target == "unbounded":
        plan.warnings.append(
            "no time column in any predicate: backtest scope comes only from "
            "the lookback added by the probe"
        )

    aliases = extract_aliases(body)

    merged: dict[str, list[str]] = {}
    for table, fragment in _split_by_table(body):
        merged.setdefault(table, [])
        for c in extract_columns(fragment):
            if c in aliases:
                if c not in plan.dropped_aliases:
                    plan.dropped_aliases.append(c)
                continue
            if c not in merged[table]:
                merged[table].append(c)

    if not merged:
        plan.warnings.append(
            "no table statement found: no control can be built, so a hit count "
            "from this rule would be uninterpretable"
        )

    plan.probes = [TableProbe(table=t, columns=c) for t, c in merged.items()]

    for p in plan.probes:
        if len(p.columns) > 12:
            plan.warnings.append(
                f"{p.table}: {len(p.columns)} predicate columns, probe will be wide"
            )
    return plan


# ------------------------------------------------------------------ runner

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: control_query.py <dump_dir> [--target mde|sentinel] [--days N]")
        return 2

    dump_dir = Path(argv[1])
    if not dump_dir.is_dir():
        print(f"not a directory: {dump_dir}")
        return 2

    target = None
    days = DEFAULT_LOOKBACK_DAYS
    if "--target" in argv:
        target = argv[argv.index("--target") + 1]
    if "--days" in argv:
        days = int(argv[argv.index("--days") + 1])

    time_column = None
    if target == "mde":
        time_column = MDE_TIME_COLUMN
    elif target == "sentinel":
        time_column = SENTINEL_TIME_COLUMN

    plans = []
    for f in sorted(dump_dir.glob("kql__*.txt")):
        title, body = _load_dump(f)
        plans.append(build_plan(body, artifact_id=f.name, title=title))

    targets = {}
    for p in plans:
        targets[p.target] = targets.get(p.target, 0) + 1
    usable = sum(1 for p in plans if p.backtestable)
    print(f"{len(plans)} KQL artifacts; {usable} backtestable; "
          f"target as written: {targets}\n")

    for p in plans:
        print("=" * 72)
        print(f"{p.title[:68]}")
        print(f"  target={p.target}  tables={[x.table for x in p.probes]}")
        if p.dropped_aliases:
            print(f"  dropped rule-created names: {', '.join(p.dropped_aliases)}")
        for w in p.warnings:
            print(f"  WARN {w}")
        for table, q in p.queries(time_column, days):
            print(f"\n  -- control probe: {table}")
            for line in q.splitlines():
                print(f"  {line}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))