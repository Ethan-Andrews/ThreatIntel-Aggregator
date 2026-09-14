"""Log Analytics / Sentinel query client for backtesting.

Detections from this pipeline are saved as Sentinel hunts, so backtests run
against the Sentinel workspace rather than MDE advanced hunting. That choice
removes the 3-hour tenant-wide execution budget from stage 6 entirely, and it
means a rule is validated against exactly the telemetry it will later alert on.

Two things are worth knowing before reading further:

  - The workspace is addressed by its customer id (a GUID), not by its resource
    name. `az monitor log-analytics workspace show --query customerId` returns
    it.
  - A query referencing a column that does not exist fails with HTTP 400 and a
    semantic error, not with zero rows. That distinction is the whole reason
    the control probe exists, so the client surfaces it as its own exception
    rather than folding it into a generic failure.

Used by stage 6b to run control probes and full-rule counts, and intended for
reuse by stage 8's retro-hunt, which queries the same workspace.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

try:
    from azure.identity import DefaultAzureCredential
except ImportError:  # pragma: no cover
    DefaultAzureCredential = None

logger = logging.getLogger(__name__)

LOGANALYTICS_ENDPOINT = "https://api.loganalytics.io/v1"
LOGANALYTICS_SCOPE = "https://api.loganalytics.io/.default"

# Log Analytics limits, for reference rather than enforcement: 5 concurrent
# queries per user before throttling, a 10-minute server-side timeout, 500,000
# result rows and roughly 64 MB per response. Control probes are summarize-only
# and run sequentially, so none of these bind at this volume.
QUERY_TIMEOUT_SECONDS = 180


class SentinelError(RuntimeError):
    """Any failure talking to the workspace."""


class QuerySemanticError(SentinelError):
    """The query is invalid -- typically an unknown column or table.

    Distinct from a zero-row result on purpose: an unknown column means the
    query never ran, so treating it as 'no hits' would be exactly the false
    negative the control probe exists to catch.
    """


class Throttled(SentinelError):
    """The workspace rate-limited the request."""


@dataclass
class QueryResult:
    columns: list[str]
    rows: list[list]
    elapsed: float

    def first(self) -> dict | None:
        if not self.rows:
            return None
        return dict(zip(self.columns, self.rows[0]))

    def dicts(self) -> list[dict]:
        return [dict(zip(self.columns, r)) for r in self.rows]


class SentinelClient:
    def __init__(self, workspace_id: str | None = None,
                 credential=None, timeout: float = QUERY_TIMEOUT_SECONDS) -> None:
        self.workspace_id = workspace_id or os.environ.get("SENTINEL_WORKSPACE_ID", "")
        if not self.workspace_id:
            raise SentinelError(
                "SENTINEL_WORKSPACE_ID is not set. This is the workspace customer "
                "id (a GUID), not the resource name -- get it with: az monitor "
                "log-analytics workspace show -g <rg> -n <name> --query customerId -o tsv"
            )
        if credential is None:
            if DefaultAzureCredential is None:
                raise SentinelError(
                    "azure-identity is not installed: pip install azure-identity"
                )
            credential = DefaultAzureCredential()
        self._credential = credential
        self._client = httpx.Client(timeout=timeout)
        self._token = None
        self._token_expires = 0.0

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SentinelClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _bearer(self) -> str:
        # Refresh a minute early rather than racing the expiry.
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        try:
            tok = self._credential.get_token(LOGANALYTICS_SCOPE)
        except Exception as exc:  # credential types vary too much to narrow
            raise SentinelError(f"could not acquire a token: {exc}") from exc
        self._token = tok.token
        self._token_expires = float(tok.expires_on)
        return self._token

    def query(self, kusto: str, timespan: str | None = None) -> QueryResult:
        """Run one KQL query against the workspace.

        timespan is an ISO-8601 duration such as P90D. When the query carries
        its own `where TimeGenerated > ago(...)`, passing a timespan as well is
        harmless: the server intersects them.
        """
        url = f"{LOGANALYTICS_ENDPOINT}/workspaces/{self.workspace_id}/query"
        body: dict = {"query": kusto}
        if timespan:
            body["timespan"] = timespan

        started = time.monotonic()
        try:
            resp = self._client.post(
                url,
                json=body,
                headers={
                    "Authorization": f"Bearer {self._bearer()}",
                    "Content-Type": "application/json",
                },
            )
        except httpx.RequestError as exc:
            raise SentinelError(f"query transport failure: {exc}") from exc
        elapsed = time.monotonic() - started

        if resp.status_code == 429:
            raise Throttled(f"rate limited; Retry-After={resp.headers.get('Retry-After')}")
        if resp.status_code == 403:
            raise SentinelError(
                "403 Forbidden: the identity needs the Log Analytics Reader role "
                "on this workspace"
            )
        if resp.status_code == 400:
            detail = _error_detail(resp)
            raise QuerySemanticError(f"query rejected: {detail}")
        if resp.status_code >= 400:
            raise SentinelError(f"HTTP {resp.status_code}: {resp.text[:300]}")

        payload = resp.json()

        # Log Analytics can return HTTP 200 with an error object for partial or
        # deferred failures. Treating that as an empty result would report a
        # broken query as zero hits.
        err = payload.get("error")
        if err:
            raise QuerySemanticError(
                f"200 with error payload: {err.get('code', '?')} "
                f"{err.get('message', '')}"
            )

        tables = payload.get("tables") or []
        if not tables:
            raise SentinelError(
                f"response carried no tables; keys were {sorted(payload.keys())}"
            )
        # Prefer the named result: some responses interleave diagnostic tables.
        table = next((t for t in tables if t.get("name") == "PrimaryResult"),
                     tables[0])
        columns = [c["name"] for c in table.get("columns") or []]
        return QueryResult(columns=columns, rows=table.get("rows") or [],
                           elapsed=elapsed)


def _error_detail(resp: httpx.Response) -> str:
    try:
        err = resp.json().get("error") or {}
    except json.JSONDecodeError:
        return resp.text[:300]
    parts = [err.get("message", "")]
    inner = err.get("innererror") or {}
    while inner:
        if inner.get("message"):
            parts.append(inner["message"])
        inner = inner.get("innererror") or {}
    return " | ".join(p for p in parts if p)[:400]


# ------------------------------------------------------------- disposition

# How old a recorded baseline may be before the probe re-measures. Column
# population is a stable property of the telemetry, not of any one article, so
# re-measuring per run is wasted work.
BASELINE_MAX_AGE_DAYS = 7


@dataclass
class ProbeOutcome:
    table: str
    total: int = 0
    # None means this table has no confirmed entity dimension (see
    # control_query._entity_column), so no breadth count was ever attempted --
    # distinct from a genuine zero, which means the dimension was measured and
    # found empty. Conflating the two prints a false "devices=0" for tables
    # like AuditLogs, which is worse than omitting the number.
    devices: int | None = None
    populated: dict[str, int] = field(default_factory=dict)
    dead_fields: list[str] = field(default_factory=list)
    elapsed: float = 0.0
    error: str = ""
    from_baseline: bool = False

    @property
    def disposition(self) -> str:
        """Only objective outcomes are verdicts.

        A column populated on a small share of rows is not a defect -- some
        columns are simply sparse by nature, and judging them against a fixed
        threshold produces warnings a reviewer learns to ignore. Shares are
        reported as measurements; what makes one meaningful is deviation from
        that column's own history, which the baseline table supplies.
        """
        if self.error:
            return "probe_error"
        if self.total == 0:
            return "no_telemetry"
        if self.dead_fields:
            return "dead_predicate"
        return "ok"

    def share(self, column: str) -> float:
        if not self.total:
            return 0.0
        return self.populated.get(column, 0) / self.total


def _fmt_devices(out: "ProbeOutcome") -> str:
    """'devices=N' when measured, 'devices=n/a' when this table has no
    confirmed entity dimension. Never prints a bare 0 for the unmeasured case."""
    return f"devices={out.devices:,}" if out.devices is not None else "devices=n/a"


def run_probe(client: SentinelClient, table: str, kusto: str) -> ProbeOutcome:
    """Execute one control probe and interpret the result.

    Total of zero means the table carries no data in the lookback, so any hit
    count from the rule is uninterpretable. A Pop_ column of zero means the rule
    tests a field this tenant never populates, so it can never fire regardless
    of how good the logic is.
    """
    out = ProbeOutcome(table=table)
    try:
        res = client.query(kusto)
    except QuerySemanticError as exc:
        out.error = f"semantic: {exc}"
        return out
    except SentinelError as exc:
        out.error = str(exc)
        return out

    row = res.first()
    if row is None:
        out.error = "probe returned no rows"
        return out

    out.total = int(row.get("Total") or 0)
    # control_query.py names this column Entities and omits it entirely for a
    # table with no confirmed breadth dimension (see _entity_column). The
    # Python-side attribute stays "devices" for continuity with the existing
    # baseline schema and print output -- it is really "distinct principal or
    # device, whichever this table's natural key is." "Entities" not in row
    # means the dimension was never requested, not that it measured zero.
    out.devices = int(row["Entities"]) if "Entities" in row else None
    out.elapsed = res.elapsed
    for key, value in row.items():
        if not key.startswith("Pop_"):
            continue
        col = key[4:]
        count = int(value or 0)
        out.populated[col] = count
        # Zero is the only share that is terminal on its own: the rule tests a
        # field this tenant never fills, so it can never match.
        if out.total > 0 and count == 0:
            out.dead_fields.append(col)
    return out


# -------------------------------------------------------------- baselines

BASELINE_TABLE = "telemetry_baseline"


def load_baselines(conn, table: str) -> dict[str, dict]:
    """Most recent recorded share per column for one table.

    Returns an empty mapping when the baseline table does not exist yet, so a
    caller can run before the DDL has been applied.
    """
    try:
        rows = conn.execute(
            f"SELECT DISTINCT ON (column_name) column_name, populated, share, "
            f"total_rows, devices, measured_at FROM {BASELINE_TABLE} "
            f"WHERE table_name = ? ORDER BY column_name, measured_at DESC",
            (table,),
        ).fetchall()
    except Exception as exc:
        logger.debug("baseline lookup skipped for %s: %s", table, exc)
        return {}
    return {r["column_name"]: dict(r) for r in rows}


def record_baseline(conn, out: ProbeOutcome, lookback_days: int) -> bool:
    """Append this probe's measurements. Returns False if persistence is absent.

    One row per column, plus a table-level row with an empty column name so the
    total and device count are recoverable on their own.
    """
    if out.error or out.from_baseline:
        return False
    rows = [("", out.total, out.total)]
    rows += [(col, n, out.total) for col, n in out.populated.items()]
    try:
        for col, populated, total in rows:
            share = (populated / total) if total else 0.0
            conn.execute(
                f"INSERT INTO {BASELINE_TABLE} "
                f"(table_name, column_name, total_rows, populated, share, "
                f" devices, lookback_days) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (out.table, col, out.total, populated, round(share, 5),
                 out.devices, lookback_days),
            )
        conn.commit()
        return True
    except Exception as exc:
        logger.debug("baseline write skipped for %s: %s", out.table, exc)
        return False


def baseline_is_fresh(baselines: dict[str, dict], columns: list[str],
                      max_age_days: int = BASELINE_MAX_AGE_DAYS) -> bool:
    """True when every needed column has a recent measurement."""
    if not baselines:
        return False
    cutoff = time.time() - max_age_days * 86400
    for col in columns:
        entry = baselines.get(col)
        if not entry:
            return False
        measured = entry.get("measured_at")
        ts = measured.timestamp() if hasattr(measured, "timestamp") else 0.0
        if ts < cutoff:
            return False
    return True


def outcome_from_baseline(table: str, columns: list[str],
                          baselines: dict[str, dict]) -> ProbeOutcome:
    """Reconstruct a probe outcome from recorded measurements.

    A missing `populated` value is treated as an error rather than as zero: a
    zero here would read as dead_predicate and terminate a rule that is
    perfectly fine, which is the worst possible way for a lookup bug to fail.
    """
    out = ProbeOutcome(table=table, from_baseline=True)
    table_row = baselines.get("") or {}
    out.total = int(table_row.get("total_rows") or 0)
    raw_devices = table_row.get("devices")
    out.devices = int(raw_devices) if raw_devices is not None else None
    for col in columns:
        entry = baselines.get(col)
        if entry is None or entry.get("populated") is None:
            out.error = (f"baseline row for {col} has no populated value; "
                         f"re-measure rather than trusting it")
            return out
        populated = int(entry["populated"])
        out.populated[col] = populated
        if out.total > 0 and populated == 0:
            out.dead_fields.append(col)
    return out


# ------------------------------------------------------------------ runner

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: sentinel.py <dump_dir> [--dry-run] [--days N]")
        print("  env: SENTINEL_WORKSPACE_ID (workspace customer id GUID)")
        return 2

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from control_query import build_plan, CONTROL_LOOKBACK_DAYS
    from static_gate import evaluate, _load_dump

    dump_dir = Path(argv[1])
    dry_run = "--dry-run" in argv
    days = CONTROL_LOOKBACK_DAYS
    if "--days" in argv:
        days = int(argv[argv.index("--days") + 1])

    # Only artifacts that clear the static gate are worth probing.
    candidates = []
    for f in sorted(dump_dir.glob("kql__*.txt")):
        title, body = _load_dump(f)
        gate = evaluate(body, artifact_id=f.name, title=title)
        if gate.verdict != "pass":
            continue
        plan = build_plan(body, artifact_id=f.name, title=title)
        if not plan.backtestable:
            continue
        candidates.append((title, body, plan))

    print(f"{len(candidates)} candidates cleared the static gate\n")

    if dry_run:
        for title, _body, plan in candidates:
            print("=" * 70)
            print(title[:66])
            for table, q in plan.queries(lookback_days=days):
                print(f"\n-- {table}")
                print(q)
            print()
        return 0

    client = SentinelClient()

    conn = None
    if "--no-baseline" not in argv:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
            import pgcompat
            conn = pgcompat.connect()
        except Exception as exc:
            print(f"baseline persistence unavailable ({exc}); measuring only\n")

    seen: dict[str, ProbeOutcome] = {}
    baseline_cache: dict[str, dict] = {}
    probes_run = 0

    for title, _body, plan in candidates:
        print("=" * 70)
        print(title[:66])
        for table, q in plan.queries(lookback_days=days):
            if q in seen:
                out = seen[q]
                print(f"  {table}: {out.disposition} (cached this run)")
                continue

            columns = [c for c in plan_columns(plan, table)]
            if conn is not None and table not in baseline_cache:
                baseline_cache[table] = load_baselines(conn, table)
            prior = baseline_cache.get(table, {})

            if baseline_is_fresh(prior, columns, BASELINE_MAX_AGE_DAYS):
                out = outcome_from_baseline(table, columns, prior)
                if out.error:
                    # A bad baseline row must never terminate a rule. Fall
                    # through and measure instead.
                    print(f"  {table}: baseline unusable ({out.error})")
                    out = run_probe(client, table, q)
                    probes_run += 1
                    if not out.error and conn is not None:
                        record_baseline(conn, out, days)
                    seen[q] = out
                    if out.error:
                        print(f"  {table}: ERROR {out.error}")
                        continue
                    print(f"  {table}: {out.disposition} total={out.total:,} "
                          f"{_fmt_devices(out)} ({out.elapsed:.1f}s)")
                else:
                    seen[q] = out
                    measured = (prior.get("") or {}).get("measured_at")
                    print(f"  {table}: {out.disposition} total={out.total:,} "
                          f"(baseline {measured})")
            else:
                out = run_probe(client, table, q)
                seen[q] = out
                probes_run += 1
                if out.error:
                    print(f"  {table}: ERROR {out.error}")
                    continue
                print(f"  {table}: {out.disposition} total={out.total:,} "
                      f"{_fmt_devices(out)} ({out.elapsed:.1f}s)")
                if conn is not None:
                    record_baseline(conn, out, days)

            for col, n in out.populated.items():
                pct = 100.0 * out.share(col)
                note = ""
                was = prior.get(col)
                if was and not out.from_baseline:
                    # Deviation from this column's own history is the signal.
                    # An absolute share is not: some columns are sparse by
                    # design, and a fixed threshold flags them forever.
                    delta = pct - 100.0 * float(was.get("share") or 0)
                    if abs(delta) >= 5.0:
                        note = f"  <-- shifted {delta:+.1f} pts"
                if n == 0:
                    note = "  <-- DEAD"
                print(f"      {col}: {n:,} ({pct:.1f}%){note}")
        print()

    total_seconds = sum(o.elapsed for o in seen.values())
    print(f"{len(seen)} probes ({probes_run} measured, "
          f"{len(seen) - probes_run} from baseline), {total_seconds:.1f}s")
    if conn is not None:
        conn.close()
    client.close()
    return 0


def plan_columns(plan, table: str) -> list[str]:
    """Probed column names for one table within a control plan."""
    for probe in plan.probes:
        if probe.table == table:
            return [c for c in probe.columns
                    if c not in ("DeviceName", "Timestamp", "TimeGenerated")]
    return []


if __name__ == "__main__":
    sys.exit(main(sys.argv))