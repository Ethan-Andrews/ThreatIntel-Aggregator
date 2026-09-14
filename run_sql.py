"""Execute a .sql file against a Postgres server.

A stand-in for `psql -f` on machines without the PostgreSQL client tools
installed. Uses psycopg, which is already a project dependency.

    $env:PG_DSN = "postgresql://user:pass@host:5432/db?sslmode=require"
    python run_sql.py backend\\pg_schema.sql
    python run_sql.py create_role.sql

Or pass the DSN explicitly:

    python run_sql.py create_role.sql --dsn "postgresql://..."

The whole file is sent as a single statement batch, so dollar-quoted function
bodies and multi-statement scripts execute correctly. Everything runs in one
transaction: any error rolls the entire file back.
"""

import argparse
import os
import sys

try:
    import psycopg
except ImportError:
    print("ERROR: psycopg is required.  pip install 'psycopg[binary]'", file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run a .sql file against Postgres")
    ap.add_argument("path", help="path to the .sql file")
    ap.add_argument("--dsn", default=os.environ.get("PG_DSN", ""),
                    help="Postgres DSN (default: PG_DSN environment variable)")
    ap.add_argument("--autocommit", action="store_true",
                    help="run outside a transaction, for statements such as "
                         "CREATE DATABASE that cannot run inside one")
    args = ap.parse_args()

    if not args.dsn:
        print("ERROR: no DSN. Set PG_DSN or pass --dsn", file=sys.stderr)
        return 2

    if not os.path.exists(args.path):
        print(f"ERROR: file not found: {args.path}", file=sys.stderr)
        return 2

    with open(args.path, "r", encoding="utf-8") as fh:
        sql = fh.read()

    # Never print the DSN itself; it carries the password.
    host = args.dsn.split("@")[-1].split("/")[0] if "@" in args.dsn else "server"
    print(f"Running {args.path} against {host}")

    try:
        conn = psycopg.connect(args.dsn, autocommit=args.autocommit, connect_timeout=15)
    except Exception as exc:
        print(f"FAIL: cannot connect: {exc}", file=sys.stderr)
        return 1

    # psycopg3 delivers server NOTICE messages through a callback, not through a
    # .notices list as psycopg2 did.
    notices: list[str] = []
    conn.add_notice_handler(lambda diag: notices.append(diag.message_primary or ""))

    try:
        with conn.cursor() as cur:
            cur.execute(sql)
        if not args.autocommit:
            conn.commit()
        for msg in notices[:25]:
            print(f"  NOTICE: {msg}")
        if len(notices) > 25:
            print(f"  ... and {len(notices) - 25} more notices")
        print("OK")
        return 0
    except Exception as exc:
        if not args.autocommit:
            conn.rollback()
            print("  transaction rolled back; no changes applied")
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
