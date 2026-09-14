"""Inspect a SQLite snapshot before migrating it."""

import sqlite3
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "prod-copy.db"
conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)

print("integrity :", conn.execute("PRAGMA integrity_check").fetchone()[0])

tables = sorted(
    r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%'"
    )
)
print(f"tables    : {len(tables)}")
for t in tables:
    n = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
    print(f"  {t:<22} {n}")

expected = {
    "entries", "sources", "stack_items", "users", "ioc_ledger",
    "runzero_assets", "runzero_vulns", "runzero_matches",
    "runzero_sync_log", "feed_fetch_log",
    "exposure_items", "exposure_audit_log",
}
missing = sorted(expected - set(tables))
print("missing   :", missing if missing else "none")

row = conn.execute("SELECT MIN(ingested), MAX(ingested) FROM entries").fetchone()
print("ingested  :", row[0], "->", row[1])

conn.close()