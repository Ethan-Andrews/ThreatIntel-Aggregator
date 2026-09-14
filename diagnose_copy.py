"""Diagnose a COPY failure during the SQLite to Postgres migration.

Runs two passes:

  1. LOCAL  - scans the SQLite source for values Postgres rejects but SQLite
              accepts: NUL bytes, invalid UTF-8, and unusually large fields.
              Needs no network and no Postgres.

  2. REMOTE - if a DSN is available, copies the table in small chunks and
              reports the exact chunk that fails, then retries that chunk row
              by row with INSERT so the server's real error message surfaces
              instead of a generic lost connection.

    python diagnose_copy.py --sqlite prod-copy.db --table entries
    python diagnose_copy.py --sqlite prod-copy.db --table entries --remote
"""

import argparse
import os
import sqlite3
import sys

TEXTISH = ("TEXT", "VARCHAR", "CHAR", "CLOB", "")


def local_scan(path: str, table: str) -> bool:
    """Look for content Postgres will not accept in a text column."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.text_factory = bytes  # inspect raw bytes, not decoded strings

    info = conn.execute(f"PRAGMA table_info({table})").fetchall()
    cols = [(r[1].decode() if isinstance(r[1], bytes) else r[1],
             (r[2].decode() if isinstance(r[2], bytes) else r[2] or "").upper())
            for r in info]
    text_cols = [c for c, t in cols if any(t.startswith(p) for p in TEXTISH)]
    print(f"  scanning {len(text_cols)} text columns in {table}")

    nul_hits, utf8_hits, big_hits = [], [], []
    max_len = 0

    collist = ", ".join(f'"{c}"' for c in [c for c, _ in cols])
    pk = cols[0][0]
    for row in conn.execute(f"SELECT {collist} FROM {table}"):
        rowid = row[0]
        for (name, _), value in zip(cols, row):
            if not isinstance(value, bytes):
                continue
            if len(value) > max_len:
                max_len = len(value)
            if b"\x00" in value:
                nul_hits.append((rowid, name))
            else:
                try:
                    value.decode("utf-8")
                except UnicodeDecodeError:
                    utf8_hits.append((rowid, name))
            if len(value) > 1_000_000:
                big_hits.append((rowid, name, len(value)))
    conn.close()

    print(f"  largest single value: {max_len:,} bytes")
    ok = True

    if nul_hits:
        ok = False
        print(f"  FOUND {len(nul_hits)} value(s) containing NUL bytes (0x00).")
        print("        Postgres rejects NUL in text; SQLite allows it.")
        for rowid, name in nul_hits[:5]:
            r = rowid.decode(errors="replace") if isinstance(rowid, bytes) else rowid
            print(f"          {pk}={str(r)[:40]}  column={name}")
    else:
        print("  no NUL bytes")

    if utf8_hits:
        ok = False
        print(f"  FOUND {len(utf8_hits)} value(s) with invalid UTF-8.")
        for rowid, name in utf8_hits[:5]:
            r = rowid.decode(errors="replace") if isinstance(rowid, bytes) else rowid
            print(f"          {pk}={str(r)[:40]}  column={name}")
    else:
        print("  all text decodes as valid UTF-8")

    if big_hits:
        print(f"  NOTE {len(big_hits)} value(s) over 1 MB; large but legal")
        for rowid, name, n in big_hits[:5]:
            r = rowid.decode(errors="replace") if isinstance(rowid, bytes) else rowid
            print(f"          {pk}={str(r)[:40]}  column={name}  {n:,} bytes")

    return ok


def remote_probe(path: str, table: str, dsn: str, chunk: int) -> None:
    """Copy in small chunks to find where it breaks, then isolate the row."""
    import psycopg

    sconn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    cols = [r[1] for r in sconn.execute(f"PRAGMA table_info({table})")]
    collist = ", ".join(f'"{c}"' for c in cols)
    total = sconn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    print(f"  {total:,} rows, chunk size {chunk}")

    offset = 0
    while offset < total:
        rows = sconn.execute(
            f"SELECT {collist} FROM {table} LIMIT ? OFFSET ?", (chunk, offset)
        ).fetchall()
        if not rows:
            break
        try:
            with psycopg.connect(dsn, autocommit=False, keepalives=1,
                                 keepalives_idle=30, connect_timeout=15) as conn:
                with conn.cursor() as cur:
                    cur.execute("SET statement_timeout = 0")
                    with cur.copy(f"COPY {table} ({collist}) FROM STDIN") as cp:
                        for row in rows:
                            cp.write_row(row)
                conn.commit()
            print(f"    rows {offset:>8,} - {offset + len(rows):>8,}  ok")
        except Exception as exc:
            print(f"    rows {offset:>8,} - {offset + len(rows):>8,}  FAILED")
            print(f"      {type(exc).__name__}: {str(exc).splitlines()[0][:140]}")
            print("      isolating with single-row INSERTs to get the server error")
            placeholders = ", ".join(["%s"] * len(cols))
            for i, row in enumerate(rows):
                try:
                    with psycopg.connect(dsn, autocommit=True,
                                         connect_timeout=15) as c2:
                        c2.execute(
                            f"INSERT INTO {table} ({collist}) VALUES ({placeholders})",
                            tuple(row),
                        )
                except Exception as e2:
                    print(f"      row {offset + i}: {type(e2).__name__}: "
                          f"{str(e2).splitlines()[0][:160]}")
                    print(f"      first column value: {str(row[0])[:60]!r}")
                    return
            print("      every row inserted individually; the failure is not row data")
            return
        offset += len(rows)
    print("  all chunks copied without error")


def main() -> int:
    ap = argparse.ArgumentParser(description="Diagnose a COPY failure")
    ap.add_argument("--sqlite", required=True)
    ap.add_argument("--table", default="entries")
    ap.add_argument("--remote", action="store_true",
                    help="also probe the target server chunk by chunk")
    ap.add_argument("--dsn", default=os.environ.get("PG_DSN", ""))
    ap.add_argument("--chunk", type=int, default=250)
    args = ap.parse_args()

    print(f"Pass 1: local scan of {args.table}")
    clean = local_scan(args.sqlite, args.table)

    if not clean:
        print("\nSource data contains values Postgres will reject. "
              "Fix these before retrying the load.")

    if args.remote:
        if not args.dsn:
            print("\nno DSN; skipping remote probe", file=sys.stderr)
            return 1
        print(f"\nPass 2: chunked remote copy of {args.table}")
        print("  NOTE: this writes rows. Truncate the table first if you want a "
              "clean load afterwards.")
        remote_probe(args.sqlite, args.table, args.dsn, args.chunk)

    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())