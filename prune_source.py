"""Shrink a SQLite migration copy by dropping rows that need not be migrated.

Two tables hold the overwhelming majority of rows and neither needs its full
history carried into Postgres:

  runzero_vulns   rebuilt in full by the next RunZero sync
  feed_fetch_log  backs a 7-day feed-health dashboard; older rows are unread

Removing them makes the transfer small enough to survive a lossy link and
small enough to upload to Cloud Shell. This operates on a COPY of the source
database and never touches production.

    python prune_source.py --sqlite prod-copy.db --dry-run
    python prune_source.py --sqlite prod-copy.db --feed-log-days 7 --drop-vulns

VACUUM runs at the end, so the file on disk shrinks rather than just freeing
pages internally.
"""

import argparse
import os
import shutil
import sqlite3
import sys


def human(n: int) -> str:
    return f"{n / (1024 * 1024):.1f} MB"


def counts(conn: sqlite3.Connection) -> dict:
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%'")]
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in sorted(tables)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Prune a SQLite migration copy")
    ap.add_argument("--sqlite", required=True, help="path to the COPY, not production")
    ap.add_argument("--feed-log-days", type=int, default=7,
                    help="keep this many days of feed_fetch_log (default 7, "
                         "matching the dashboard window). 0 keeps everything")
    ap.add_argument("--drop-vulns", action="store_true",
                    help="delete all runzero_vulns rows; the next RunZero sync "
                         "repopulates them")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be removed and change nothing")
    ap.add_argument("--no-backup", action="store_true",
                    help="skip the .bak copy taken before modifying")
    args = ap.parse_args()

    if not os.path.exists(args.sqlite):
        print(f"ERROR: not found: {args.sqlite}", file=sys.stderr)
        return 2

    if "prod-copy" not in os.path.basename(args.sqlite) and not args.dry_run:
        print(f"WARNING: {args.sqlite} is not named like a copy.")
        print("         This script deletes rows. Confirm it is not production.")
        if input("         Type 'yes' to continue: ").strip().lower() != "yes":
            return 1

    size_before = os.path.getsize(args.sqlite)
    conn = sqlite3.connect(args.sqlite)
    before = counts(conn)

    print(f"File: {args.sqlite}  ({human(size_before)})")
    print(f"{'table':<22} {'rows':>10}")
    for t, n in before.items():
        print(f"  {t:<20} {n:>10,}")
    total_before = sum(before.values())
    print(f"  {'TOTAL':<20} {total_before:>10,}\n")

    plan = []

    if args.drop_vulns and before.get("runzero_vulns"):
        plan.append(("runzero_vulns", "DELETE FROM runzero_vulns", (),
                     before["runzero_vulns"]))

    if args.feed_log_days and before.get("feed_fetch_log"):
        cutoff_sql = ("SELECT COUNT(*) FROM feed_fetch_log "
                      "WHERE polled_at < datetime('now', ?)")
        param = f"-{args.feed_log_days} days"
        n = conn.execute(cutoff_sql, (param,)).fetchone()[0]
        if n:
            plan.append(("feed_fetch_log",
                         "DELETE FROM feed_fetch_log "
                         "WHERE polled_at < datetime('now', ?)",
                         (param,), n))

    if not plan:
        print("Nothing to prune.")
        conn.close()
        return 0

    removed = sum(p[3] for p in plan)
    print("Plan:")
    for table, _, _, n in plan:
        print(f"  {table:<20} remove {n:>10,}")
    print(f"  {'TOTAL':<20} remove {removed:>10,}  "
          f"({100.0 * removed / total_before:.0f}% of rows)")
    print(f"  remaining rows: {total_before - removed:,}\n")

    if args.dry_run:
        print("--dry-run: nothing was changed.")
        conn.close()
        return 0

    if not args.no_backup:
        bak = args.sqlite + ".bak"
        conn.close()
        shutil.copy2(args.sqlite, bak)
        print(f"Backup written: {bak}")
        conn = sqlite3.connect(args.sqlite)

    for table, sql, params, _ in plan:
        cur = conn.execute(sql, params)
        print(f"  {table:<20} deleted {cur.rowcount:,}")
    conn.commit()

    print("  running VACUUM to reclaim file space (this can take a minute)")
    conn.execute("VACUUM")
    conn.commit()

    after = counts(conn)
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    conn.close()

    size_after = os.path.getsize(args.sqlite)
    print(f"\n  integrity_check: {integrity}")
    print(f"  size: {human(size_before)} -> {human(size_after)}")
    print(f"  rows: {total_before:,} -> {sum(after.values()):,}")

    if integrity != "ok":
        print("  integrity check FAILED; restore the .bak", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
