import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pg_helpers import pg_test_conn as _pg_test_conn, table_columns

from db import get_org_exposure, get_feed_health


def _make_exposure_db():
    """In-memory DB with enough schema for exposure + feed health tests."""
    conn = _pg_test_conn()
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_feed_fetch_log_name ON feed_fetch_log (feed_name, polled_at DESC)"
    )
    conn.commit()
    return conn


class TestGetOrgExposure(unittest.TestCase):
    def test_returns_empty_when_no_matches(self):
        conn = _make_exposure_db()
        result = get_org_exposure(conn=conn)
        self.assertEqual(result, [])
        conn.close()

    def test_single_org_confirmed_match(self):
        conn = _make_exposure_db()
        conn.execute(
            "INSERT INTO runzero_assets (id, org, hostname, alive) VALUES ('a1', 'FSC Corp', 'HOST-1', 1)"
        )
        conn.execute(
            "INSERT INTO entries (hash, title, source, severity) VALUES ('h1', 'Critical CVE', 'S', 'Critical')"
        )
        conn.execute(
            "INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence) "
            "VALUES ('h1', 'a1', 'cve', 'confirmed')"
        )
        conn.commit()
        result = get_org_exposure(conn=conn)
        self.assertEqual(len(result), 1)
        row = result[0]
        self.assertEqual(row["org"], "FSC Corp")
        self.assertEqual(row["confirmed"], 1)
        self.assertEqual(row["possible"], 0)
        self.assertEqual(row["total"], 1)
        self.assertEqual(row["critical"], 1)
        conn.close()

    def test_two_orgs_ordered_by_confirmed_desc(self):
        conn = _make_exposure_db()
        conn.execute("INSERT INTO runzero_assets (id, org, alive) VALUES ('a1', 'Org A', 1)")
        conn.execute("INSERT INTO runzero_assets (id, org, alive) VALUES ('a2', 'Org B', 1)")
        conn.execute("INSERT INTO entries (hash, title, source, severity) VALUES ('h1', 'E1', 'S', 'High')")
        conn.execute("INSERT INTO entries (hash, title, source, severity) VALUES ('h2', 'E2', 'S', 'High')")
        conn.execute("INSERT INTO entries (hash, title, source, severity) VALUES ('h3', 'E3', 'S', 'Medium')")
        # Org B: 2 confirmed
        conn.execute("INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence) VALUES ('h1', 'a2', 'cve', 'confirmed')")
        conn.execute("INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence) VALUES ('h2', 'a2', 'cve', 'confirmed')")
        # Org A: 1 confirmed
        conn.execute("INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence) VALUES ('h3', 'a1', 'software', 'confirmed')")
        conn.commit()
        result = get_org_exposure(conn=conn)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["org"], "Org B")  # most confirmed first
        self.assertEqual(result[0]["confirmed"], 2)
        self.assertEqual(result[1]["org"], "Org A")
        conn.close()

    def test_severity_counts(self):
        conn = _make_exposure_db()
        conn.execute("INSERT INTO runzero_assets (id, org, alive) VALUES ('a1', 'FSC', 1)")
        for h, sev in [("h1", "Critical"), ("h2", "High"), ("h3", "Medium"), ("h4", "Low")]:
            conn.execute(
                "INSERT INTO entries (hash, title, source, severity) VALUES (?, ?, 'S', ?)", (h, h, sev)
            )
            conn.execute(
                "INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence) VALUES (?, 'a1', 'cve', 'confirmed')",
                (h,),
            )
        conn.commit()
        result = get_org_exposure(conn=conn)
        row = result[0]
        self.assertEqual(row["critical"], 1)
        self.assertEqual(row["high"], 1)
        self.assertEqual(row["medium"], 1)
        self.assertEqual(row["low"], 1)
        conn.close()


class TestGetFeedHealth(unittest.TestCase):
    def test_returns_never_polled_for_unknown_feed(self):
        conn = _make_exposure_db()
        feeds = [{"name": "Test Feed", "tier": 1}]
        result = get_feed_health(feeds, conn=conn)
        self.assertEqual(len(result), 1)
        row = result[0]
        self.assertEqual(row["name"], "Test Feed")
        self.assertIsNone(row["last_polled"])
        self.assertEqual(row["consecutive_failures"], 0)
        self.assertEqual(row["items_last_7d"], 0)
        conn.close()

    def test_successful_poll_shows_zero_failures(self):
        conn = _make_exposure_db()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO feed_fetch_log (feed_name, polled_at, success, items_fetched, error_msg) VALUES (?, ?, 1, 5, '')",
            ("NVD CVE", now),
        )
        conn.commit()
        feeds = [{"name": "NVD CVE", "tier": 1}]
        result = get_feed_health(feeds, conn=conn)
        row = result[0]
        self.assertEqual(row["consecutive_failures"], 0)
        self.assertEqual(row["last_polled"], now)
        conn.close()

    def test_consecutive_failures_counted(self):
        conn = _make_exposure_db()
        rows = [
            ("CISA", "2026-06-28T10:00:00Z", 0, 0, "timeout"),
            ("CISA", "2026-06-28T09:45:00Z", 0, 0, "timeout"),
            ("CISA", "2026-06-28T09:30:00Z", 1, 3, ""),
        ]
        conn.executemany(
            "INSERT INTO feed_fetch_log (feed_name, polled_at, success, items_fetched, error_msg) VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
        feeds = [{"name": "CISA", "tier": 1}]
        result = get_feed_health(feeds, conn=conn)
        self.assertEqual(result[0]["consecutive_failures"], 2)
        conn.close()

    def test_items_last_7d_counts_active_entries(self):
        conn = _make_exposure_db()
        # sqlite's datetime('now', '-N day') has no Postgres equivalent --
        # ingested is stored as TEXT in the same
        # to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS') format
        # pg_schema.sql's own column default uses, so build it the same way.
        one_day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        ten_days_ago = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO entries (hash, title, source, ingested, archived, is_duplicate) "
            "VALUES ('h1', 'E1', 'CISA', ?, 0, 0)",
            (one_day_ago,),
        )
        conn.execute(
            "INSERT INTO entries (hash, title, source, ingested, archived, is_duplicate) "
            "VALUES ('h2', 'E2', 'CISA', ?, 0, 0)",
            (ten_days_ago,),
        )
        conn.commit()
        feeds = [{"name": "CISA", "tier": 1}]
        result = get_feed_health(feeds, conn=conn)
        self.assertEqual(result[0]["items_last_7d"], 1)
        conn.close()


if __name__ == "__main__":
    unittest.main()
