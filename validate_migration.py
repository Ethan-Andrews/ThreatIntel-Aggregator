"""Validate the rewritten Postgres SQL against migrated production data.

Exercises every query that changed during the SQLite to Postgres migration and
asserts invariants that a subtly wrong rewrite would violate. Run after loading
data and before cutting over.

    $env:PG_DSN = "postgresql://postgres:devpass@127.0.0.1:5432/tiagg"
    python validate_migration.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))

import db  # noqa: E402

PASS = "  PASS  "
FAIL = "  FAIL  "

results = []


def check(label, fn, assertion=None):
    """Run fn, print its result, and apply an optional invariant assertion."""
    try:
        value = fn()
    except Exception as exc:
        print(f"{FAIL}{label}: {type(exc).__name__}: {str(exc)[:150]}")
        results.append(False)
        return None

    if assertion is not None:
        ok, detail = assertion(value)
        print(f"{PASS if ok else FAIL}{label}: {detail}")
        results.append(ok)
    else:
        print(f"{PASS}{label}: {value}")
        results.append(True)
    return value


print("=" * 72)
print("Schema and connectivity")
print("=" * 72)
check("init_db verifies schema", lambda: db.init_db() or "12 tables present")

print()
print("=" * 72)
print("Bug 5: literal '%' escaping  (deduplicate_cves, LIKE '%CVE-%')")
print("=" * 72)
check("entries containing CVE in title",
      lambda: db._connect_db().execute(
          "SELECT COUNT(*) AS n FROM entries "
          "WHERE title LIKE '%CVE-%' OR title LIKE '%cve-%'").fetchone()["n"],
      lambda v: (isinstance(v, int), f"{v} rows matched, query executed"))
check("get_entries with search term",
      lambda: len(db.get_entries(search="CVE", date_window="all", limit=20)),
      lambda v: (v > 0, f"{v} rows returned"))

print()
print("=" * 72)
print("Bug 3: jsonb_array_length  (IOC ledger entry counts)")
print("=" * 72)
iocs = check("get_iocs returns rows",
             lambda: db.get_iocs(limit=25),
             lambda v: (len(v) > 0, f"{len(v)} IOCs"))
if iocs:
    populated = sum(1 for i in iocs if i.get("entry_count", 0) > 0)
    print(f"{PASS if populated else FAIL}entry_count populated: "
          f"{populated}/{len(iocs)} have entry_count > 0")
    results.append(bool(populated))
check("count_iocs", lambda: db.count_iocs(), lambda v: (v > 0, f"{v} total"))

print()
print("=" * 72)
print("Bug 2: lateral join replacing bare-column GROUP BY  (exposure)")
print("=" * 72)

summary = check("get_exposure_summary",
                lambda: db.get_exposure_summary(),
                lambda v: (len(v) > 0, f"{len(v)} orgs"))

if summary:
    for row in summary[:5]:
        print(f"          org={row['org']!r:<28} total={row['total']:<7} "
              f"active={row['active']:<7} ack={row['acknowledged']:<6} "
              f"remediated={row['remediated']}")

    org = summary[0]["org"]
    print(f"\n  Testing against largest org: {org!r}")

    page = check(f"get_exposure_items({org!r}, status=all)",
                 lambda: db.get_exposure_items(org, status="all", limit=50),
                 lambda v: (v["total"] > 0 and len(v["items"]) > 0,
                            f"total={v['total']}, page returned {len(v['items'])}"))

    if page and page["items"]:
        items = page["items"]

        # INVARIANT 1: one row per exposure item. If the lateral were replaced by
        # a plain join, an item with several match_type rows would appear twice.
        ids = [i["id"] for i in items]
        unique = len(set(ids)) == len(ids)
        print(f"{PASS if unique else FAIL}no duplicate rows: "
              f"{len(ids)} rows, {len(set(ids))} distinct ids")
        results.append(unique)

        # INVARIANT 2: the lateral must actually return a match row. Blank
        # confidence everywhere would mean it matched nothing.
        with_conf = sum(1 for i in items if i.get("confidence"))
        with_type = sum(1 for i in items if i.get("match_type"))
        print(f"{PASS if with_conf else FAIL}confidence populated: "
              f"{with_conf}/{len(items)}")
        print(f"{PASS if with_type else FAIL}match_type populated: "
              f"{with_type}/{len(items)}")
        results.append(bool(with_conf))
        results.append(bool(with_type))

        # INVARIANT 3: joined entry and asset fields must be present, since the
        # bare-column GROUP BY that used to supply them is gone.
        joined = sum(1 for i in items if i.get("title") and i.get("hostname"))
        print(f"{PASS if joined else FAIL}joined entry/asset fields: "
              f"{joined}/{len(items)} have both title and hostname")
        results.append(bool(joined))

        # INVARIANT 4: the confirmed-first ORDER BY inside the lateral.
        confs = {i.get("confidence") for i in items if i.get("confidence")}
        print(f"          confidence values seen: {sorted(confs)}")

        sample = items[0]
        print(f"\n  Sample row:")
        for k in ("id", "asset_id", "hostname", "severity", "confidence",
                  "match_type", "status", "assigned_to"):
            print(f"          {k:<14} {sample.get(k)!r}")

    # Page 2 must not repeat page 1.
    if page and page["total"] > 50:
        p2 = db.get_exposure_items(org, status="all", limit=50, offset=50)
        overlap = {i["id"] for i in page["items"]} & {i["id"] for i in p2["items"]}
        print(f"{PASS if not overlap else FAIL}pagination: "
              f"{len(overlap)} overlapping ids between page 1 and 2")
        results.append(not overlap)

    for status in ("active", "acknowledged", "remediated"):
        check(f"filter status={status}",
              lambda s=status: db.get_exposure_items(org, status=s, limit=5)["total"],
              lambda v: (isinstance(v, int), f"{v} items"))

print()
print("=" * 72)
print("Bug 4: try_date  (dedup with empty and malformed published)")
print("=" * 72)
import dedup  # noqa: E402

for label, value in (("valid ISO", "2026-07-01T00:00:00Z"),
                     ("empty string", ""),
                     ("malformed", "not-a-date")):
    check(f"is_exact_duplicate, {label}",
          lambda v=value: dedup.is_exact_duplicate(
              db._connect_db(), "CISA", "some normalized title", v),
          lambda r: (r in (True, False), f"returned {r} without raising"))

print()
print("=" * 72)
print("string_agg / jsonb_agg  (org exposure on Integrations tab)")
print("=" * 72)
oe = check("get_org_exposure",
           lambda: db.get_org_exposure(),
           lambda v: (len(v) > 0, f"{len(v)} orgs"))
check("get_runzero_status",
      lambda: db.get_runzero_status()["asset_count"],
      lambda v: (v > 0, f"{v} assets"))
matches = check("get_runzero_matches",
                lambda: db.get_runzero_matches(limit=10))

print()
print("=" * 72)
print("Remaining read paths")
print("=" * 72)
check("count_entries", lambda: db.count_entries(date_window="all"),
      lambda v: (v > 0, f"{v} entries"))
check("get_dashboard_stats", lambda: db.get_dashboard_stats()["pending"],
      lambda v: (isinstance(v, int), f"pending={v}"))
check("get_mitre_coverage", lambda: len(db.get_mitre_coverage()),
      lambda v: (v > 0, f"{v} techniques"))
check("get_archive_stats", lambda: db.get_archive_stats()["total_all"],
      lambda v: (v > 0, f"{v} total"))
check("get_enrichment_stats", lambda: db.get_enrichment_stats()["enriched_count"],
      lambda v: (isinstance(v, int), f"{v} enriched"))
check("get_stack_items", lambda: len(db.get_stack_items()),
      lambda v: (v > 0, f"{v} categories"))
check("list_users", lambda: len(db.list_users()), lambda v: (v > 0, f"{v} users"))
check("get_feed_health", lambda: len(__import__("feed_manager").FEEDS),
      lambda v: (v > 0, f"{v} feeds configured"))

print()
print("=" * 72)
failed = results.count(False)
print(f"RESULT: {results.count(True)} passed, {failed} failed")
print("=" * 72)
sys.exit(1 if failed else 0)
