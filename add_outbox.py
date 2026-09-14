"""Add the detection-pipeline outbox column and report what the gate would select.

Adds entries.emitted_at, then backfills every existing row so the pipeline
starts forward-only. Without the backfill the first run would process the whole
historical backlog and spend a detections.ai generation on each one.

Run with --dry-run first: it reports how many entries pass the gate, broken down
by why, without changing anything.

    $env:PG_DSN = "postgresql://tiapp:...@<your-postgres-server>.postgres.database.azure.com:5432/tiagg?sslmode=require"
    python add_outbox.py --dry-run
    python add_outbox.py --backfill

Re-running is safe. The column is added only if absent, and the backfill only
touches rows where emitted_at IS NULL.
"""

import argparse
import os
import sys

try:
    import psycopg
except ImportError:
    print("ERROR: psycopg is required.  pip install 'psycopg[binary]'", file=sys.stderr)
    raise SystemExit(2)

# The gate. An entry is a detection candidate when it is triaged, live, not a
# duplicate of another article, has at least one ATT&CK technique, and is either
# meaningfully severe or touches a real asset.
GATE = """
    e.triaged = 1
    AND e.archived = 0
    AND e.is_duplicate = 0
    AND e.ttps <> ''
    AND ( e.severity IN ('Critical', 'High', 'Medium')
          OR EXISTS (SELECT 1 FROM runzero_matches m WHERE m.entry_hash = e.hash) )
"""

DDL = [
    # Nullable with no default: NULL means "not yet emitted", which is what the
    # pipeline polls for.
    "ALTER TABLE entries ADD COLUMN IF NOT EXISTS emitted_at TEXT DEFAULT NULL",
    # Partial index: only unemitted rows are ever scanned, so the index stays
    # small even as entries grows.
    """CREATE INDEX IF NOT EXISTS idx_entries_pending_emit
       ON entries (emitted_at, triaged, archived, is_duplicate)
       WHERE emitted_at IS NULL""",
]


def report(conn) -> None:
    total = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    print(f"  entries total                {total:>8,}")

    rows = conn.execute(f"""
        SELECT
          COUNT(*) FILTER (WHERE e.triaged = 1)                            AS triaged,
          COUNT(*) FILTER (WHERE e.triaged = 1 AND e.archived = 0
                             AND e.is_duplicate = 0)                       AS live,
          COUNT(*) FILTER (WHERE e.triaged = 1 AND e.archived = 0
                             AND e.is_duplicate = 0 AND e.ttps <> '')      AS with_ttps,
          COUNT(*) FILTER (WHERE {GATE})                                   AS gate_pass
        FROM entries e
    """).fetchone()
    print(f"  triaged                      {rows[0]:>8,}")
    print(f"  live (not archived/dup)      {rows[1]:>8,}")
    print(f"  with ATT&CK techniques       {rows[2]:>8,}")
    print(f"  PASS THE GATE                {rows[3]:>8,}")

    print("\n  gate-passing by severity:")
    for sev, n in conn.execute(f"""
        SELECT e.severity, COUNT(*) FROM entries e
        WHERE {GATE} GROUP BY e.severity ORDER BY COUNT(*) DESC
    """).fetchall():
        print(f"    {sev:<18} {n:>8,}")

    asset_only = conn.execute(f"""
        SELECT COUNT(*) FROM entries e
        WHERE {GATE} AND e.severity NOT IN ('Critical', 'High', 'Medium')
    """).fetchone()[0]
    print(f"\n  admitted by RunZero asset match alone: {asset_only:,}")

    dropped = conn.execute("""
        SELECT COUNT(*) FROM entries e
        WHERE e.triaged = 1 AND e.archived = 0 AND e.is_duplicate = 0
          AND e.ttps = ''
          AND e.severity IN ('Critical', 'High', 'Medium')
    """).fetchone()[0]
    print(f"  severe but NO techniques (dropped):    {dropped:,}")
    if dropped:
        print("    Worth sampling before trusting the ttps gate: these are")
        print("    high-severity articles the pipeline will never see.")


def main() -> int:
    ap = argparse.ArgumentParser(description="Add and backfill the detection outbox")
    ap.add_argument("--dsn", default=os.environ.get("PG_DSN", ""))
    ap.add_argument("--dry-run", action="store_true",
                    help="report only; add no column and backfill nothing")
    ap.add_argument("--backfill", action="store_true",
                    help="mark all existing entries as already emitted, so the "
                         "pipeline starts forward-only")
    args = ap.parse_args()

    if not args.dsn:
        print("ERROR: no DSN. Set PG_DSN or pass --dsn", file=sys.stderr)
        return 2

    conn = psycopg.connect(args.dsn, autocommit=False)
    try:
        if not args.dry_run:
            for stmt in DDL:
                conn.execute(stmt)
            conn.commit()
            print("Schema: emitted_at column and partial index present\n")
        else:
            print("--dry-run: no schema changes\n")

        report(conn)

        if args.backfill and not args.dry_run:
            n = conn.execute(
                "UPDATE entries SET emitted_at = "
                "to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS') "
                "WHERE emitted_at IS NULL"
            ).rowcount
            conn.commit()
            print(f"\nBackfilled {n:,} entries as already emitted.")
            print("The pipeline will now only see articles ingested from here on.")
            print("To replay a specific entry later:")
            print("  UPDATE entries SET emitted_at = NULL WHERE hash = '<hash>';")
        elif args.backfill:
            print("\n--dry-run: backfill skipped")

        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
