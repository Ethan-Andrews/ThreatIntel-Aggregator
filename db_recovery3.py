#!/usr/bin/env python3
"""Use sqlite3 backup API to copy clean recovered DB into corrupted DB in-place."""
import sqlite3
import os

DB_PATH = "/data/ti_feeds.db"
RECOVERED_PATH = "/data/ti_feeds_recovered.db"

# Check what files exist
for p in [DB_PATH, RECOVERED_PATH, DB_PATH + ".new"]:
    if os.path.exists(p):
        print(f"EXISTS: {p} ({os.path.getsize(p)} bytes)")
    else:
        print(f"MISSING: {p}")

# If recovered DB doesn't exist, create it
if not os.path.exists(RECOVERED_PATH):
    print("\nNo recovered DB found - creating from corrupted source...")
    try:
        src_corrupt = sqlite3.connect(DB_PATH)
        src_corrupt.row_factory = sqlite3.Row
        clean = sqlite3.connect(RECOVERED_PATH)
        clean.execute("PRAGMA journal_mode=DELETE")
        clean.execute("PRAGMA synchronous=FULL")

        # Copy schema
        tables = src_corrupt.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        indexes = src_corrupt.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL AND name NOT LIKE 'sqlite_%'"
        ).fetchall()

        for name, sql in tables:
            clean.execute(sql)
        clean.commit()

        # Copy data
        for name, _ in tables:
            try:
                rows = src_corrupt.execute(f"SELECT * FROM [{name}]").fetchall()
                if rows:
                    cols = len(rows[0])
                    ph = ",".join(["?"] * cols)
                    n_ok = 0
                    for row in rows:
                        try:
                            clean.execute(f"INSERT OR IGNORE INTO [{name}] VALUES ({ph})", tuple(row))
                            n_ok += 1
                        except Exception:
                            pass
                    clean.commit()
                    print(f"  {name}: {n_ok}/{len(rows)} rows copied")
            except Exception as e:
                print(f"  {name}: FAILED - {e}")

        # Create indexes on clean copy
        for idx_name, idx_sql in indexes:
            try:
                clean.execute(idx_sql)
            except Exception as e:
                print(f"  Index {idx_name} failed: {e}")
        clean.commit()

        r = clean.execute("PRAGMA integrity_check").fetchone()[0]
        print(f"  Clean DB integrity: {r}")
        clean.close()
        src_corrupt.close()

    except Exception as e:
        import traceback
        print(f"Failed to create clean DB: {e}")
        traceback.print_exc()
        exit(1)

# Now use sqlite3 backup API to overwrite the corrupted DB
print("\nUsing sqlite3 backup API to restore corrupted DB...")
try:
    def progress(status, remaining, total):
        if total > 0 and remaining % 100 == 0:
            print(f"  Progress: {total - remaining}/{total} pages")

    src_clean = sqlite3.connect(RECOVERED_PATH)
    dst_corrupt = sqlite3.connect(DB_PATH)

    print("  Starting backup (src=clean -> dst=corrupted)...")
    src_clean.backup(dst_corrupt, pages=50, progress=progress)
    print("  Backup complete!")

    # Verify
    result = dst_corrupt.execute("PRAGMA integrity_check").fetchone()[0]
    count = dst_corrupt.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    print(f"  Integrity: {result}")
    print(f"  Entries: {count}")

    dst_corrupt.close()
    src_clean.close()

    # Cleanup recovered temp file
    os.remove(RECOVERED_PATH)
    # Clean up .new file if it exists
    if os.path.exists(DB_PATH + ".new"):
        os.remove(DB_PATH + ".new")

    print("\n=== RECOVERY COMPLETE ===")

except Exception as e:
    import traceback
    print(f"Backup failed: {e}")
    traceback.print_exc()
    exit(1)
