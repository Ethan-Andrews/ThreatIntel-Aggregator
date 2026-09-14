import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pg_helpers import pg_test_conn as _pg_test_conn

from db import (
    get_exposure_audit,
    get_exposure_items,
    get_exposure_summary,
    list_active_display_names,
    patch_exposure_item,
    reconcile_exposure,
)


def _make_db():
    """Freshly-truncated connection against the real Postgres schema
    (pg_schema.sql) -- replaces the old hand-rolled sqlite in-memory schema,
    which had drifted from production (e.g. entries.source, NOT NULL in the
    real schema, wasn't even a column here) and used LATERAL joins nowhere
    near what sqlite's parser accepts."""
    return _pg_test_conn()


class TestSchema(unittest.TestCase):
    def test_tables_exist(self):
        conn = _make_db()
        tables = {r[0] for r in conn.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = current_schema()"
        ).fetchall()}
        self.assertIn("exposure_items", tables)
        self.assertIn("exposure_audit_log", tables)
        conn.close()


class TestReconcile(unittest.TestCase):
    def _seed(self, conn, asset_id, entry_hash, org="FSC"):
        conn.execute(
            "INSERT INTO runzero_assets (id, org) VALUES (?, ?) ON CONFLICT (id) DO NOTHING",
            (asset_id, org),
        )
        conn.execute(
            "INSERT INTO entries (hash, source, title) VALUES (?, 'S', 'T') ON CONFLICT (hash) DO NOTHING",
            (entry_hash,),
        )
        conn.commit()

    def test_new_pair_creates_active_item(self):
        conn = _make_db()
        self._seed(conn, "a1", "h1")
        conn.execute(
            "INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence) VALUES ('h1','a1','cve','confirmed')"
        )
        conn.commit()
        result = reconcile_exposure(conn)
        self.assertEqual(result["new"], 1)
        row = conn.execute("SELECT status FROM exposure_items").fetchone()
        self.assertEqual(row[0], "active")
        conn.close()

    def test_continuing_pair_updates_last_seen(self):
        conn = _make_db()
        self._seed(conn, "a1", "h1")
        conn.execute(
            "INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence) VALUES ('h1','a1','cve','confirmed')"
        )
        conn.execute(
            "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen) "
            "VALUES ('a1','h1','active','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')"
        )
        conn.commit()
        result = reconcile_exposure(conn)
        self.assertEqual(result["new"], 0)
        self.assertEqual(result["updated"], 1)
        last_seen = conn.execute(
            "SELECT last_seen FROM exposure_items WHERE asset_id='a1'"
        ).fetchone()[0]
        self.assertNotEqual(last_seen, "2026-01-01T00:00:00Z")
        conn.close()

    def test_gone_pair_auto_remediates(self):
        conn = _make_db()
        self._seed(conn, "a1", "h1")
        # No match in runzero_matches — item was active
        conn.execute(
            "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen) "
            "VALUES ('a1','h1','active','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')"
        )
        conn.commit()
        result = reconcile_exposure(conn)
        self.assertEqual(result["remediated"], 1)
        row = conn.execute("SELECT status, remediated_at FROM exposure_items").fetchone()
        self.assertEqual(row[0], "remediated")
        self.assertIsNotNone(row[1])
        # Audit log entry created
        log = conn.execute("SELECT actor, action, detail FROM exposure_audit_log").fetchone()
        self.assertEqual(log[0], "system")
        self.assertEqual(log[1], "status_change")
        self.assertIn("remediated", log[2])
        conn.close()

    def test_acknowledged_item_also_auto_remediates(self):
        conn = _make_db()
        self._seed(conn, "a1", "h1")
        conn.execute(
            "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen) "
            "VALUES ('a1','h1','acknowledged','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')"
        )
        conn.commit()
        result = reconcile_exposure(conn)
        self.assertEqual(result["remediated"], 1)
        detail = conn.execute(
            "SELECT detail FROM exposure_audit_log"
        ).fetchone()[0]
        self.assertEqual(detail, "acknowledged → remediated")
        conn.close()

    def test_reappeared_remediated_item_reopened(self):
        conn = _make_db()
        self._seed(conn, "a1", "h1")
        conn.execute(
            "INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence) VALUES ('h1','a1','cve','confirmed')"
        )
        conn.execute(
            "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen, remediated_at) "
            "VALUES ('a1','h1','remediated','2026-01-01T00:00:00Z','2026-06-01T00:00:00Z','2026-06-15T00:00:00Z')"
        )
        conn.commit()
        result = reconcile_exposure(conn)
        self.assertEqual(result["reopened"], 1)
        row = conn.execute(
            "SELECT status, remediated_at FROM exposure_items"
        ).fetchone()
        self.assertEqual(row[0], "active")
        self.assertIsNone(row[1])
        log = conn.execute(
            "SELECT detail FROM exposure_audit_log"
        ).fetchone()[0]
        self.assertIn("reappeared", log)
        conn.close()


class TestSummary(unittest.TestCase):
    def test_empty_returns_empty_list(self):
        conn = _make_db()
        self.assertEqual(get_exposure_summary(conn=conn), [])
        conn.close()

    def test_counts_by_status(self):
        conn = _make_db()
        conn.execute("INSERT INTO runzero_assets (id, org) VALUES ('a1','FSC')")
        conn.execute("INSERT INTO runzero_assets (id, org) VALUES ('a2','FSC')")
        conn.execute("INSERT INTO runzero_assets (id, org) VALUES ('a3','FSC')")
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen) "
            "VALUES ('a1','h1','active',?,?)", (now, now)
        )
        conn.execute(
            "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen) "
            "VALUES ('a2','h2','acknowledged',?,?)", (now, now)
        )
        conn.execute(
            "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen, remediated_at) "
            "VALUES ('a3','h3','remediated',?,?,?)", (now, now, now)
        )
        conn.commit()
        result = get_exposure_summary(conn=conn)
        self.assertEqual(len(result), 1)
        row = result[0]
        self.assertEqual(row["org"], "FSC")
        self.assertEqual(row["total"], 3)
        self.assertEqual(row["active"], 1)
        self.assertEqual(row["acknowledged"], 1)
        self.assertEqual(row["remediated"], 1)
        conn.close()

    def test_two_orgs_ordered_by_total_desc(self):
        conn = _make_db()
        conn.execute("INSERT INTO runzero_assets (id, org) VALUES ('a1','Org A')")
        conn.execute("INSERT INTO runzero_assets (id, org) VALUES ('a2','Org B')")
        conn.execute("INSERT INTO runzero_assets (id, org) VALUES ('a3','Org B')")
        now = datetime.now(timezone.utc).isoformat()
        for aid, eh in [("a1","h1"), ("a2","h2"), ("a3","h3")]:
            conn.execute(
                "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen) "
                "VALUES (?,?,'active',?,?)", (aid, eh, now, now)
            )
        conn.commit()
        result = get_exposure_summary(conn=conn)
        self.assertEqual(result[0]["org"], "Org B")
        self.assertEqual(result[0]["total"], 2)
        self.assertEqual(result[1]["org"], "Org A")
        conn.close()

    def test_org_with_no_items_still_appears(self):
        conn = _make_db()
        # Two orgs — only OrgA has any exposure items
        conn.execute("INSERT INTO runzero_assets (id, org) VALUES ('a1','OrgA')")
        conn.execute("INSERT INTO runzero_assets (id, org) VALUES ('a2','OrgB')")
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen) "
            "VALUES ('a1','h1','active',?,?)", (now, now)
        )
        conn.commit()
        result = get_exposure_summary(conn=conn)
        orgs = {r["org"] for r in result}
        self.assertIn("OrgA", orgs)
        self.assertIn("OrgB", orgs)  # zero-hit org must appear
        orgb = next(r for r in result if r["org"] == "OrgB")
        self.assertEqual(orgb["total"], 0)
        self.assertEqual(orgb["active"], 0)
        self.assertEqual(orgb["acknowledged"], 0)
        self.assertEqual(orgb["remediated"], 0)
        conn.close()


class TestListActiveDisplayNames(unittest.TestCase):
    def test_returns_only_active_users(self):
        conn = _make_db()
        conn.execute(
            "INSERT INTO users (entra_oid, email, display_name, role, is_active) "
            "VALUES ('o1','a@b.com','Alice','viewer',1)"
        )
        conn.execute(
            "INSERT INTO users (entra_oid, email, display_name, role, is_active) "
            "VALUES ('o2','b@b.com','Bob','viewer',0)"
        )
        conn.commit()
        names = list_active_display_names(conn=conn)
        self.assertEqual(names, ["Alice"])
        conn.close()


class TestGetItems(unittest.TestCase):
    def _seed(self, conn):
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("INSERT INTO runzero_assets (id, org, hostname, site, os) VALUES ('a1','FSC','HOST-1','HQ','Windows 11')")
        conn.execute("INSERT INTO entries (hash, source, title, severity, link, ai_summary) VALUES ('h1','S','CVE Alert','Critical','https://nvd.nist.gov/','Summary text')")
        conn.execute(
            "INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence) "
            "VALUES ('h1','a1','cve','confirmed')"
        )
        conn.execute(
            "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen) "
            "VALUES ('a1','h1','active',?,?)", (now, now)
        )
        conn.commit()

    def test_returns_item_with_joined_data(self):
        conn = _make_db()
        self._seed(conn)
        result = get_exposure_items("FSC", conn=conn)
        self.assertEqual(result["total"], 1)
        item = result["items"][0]
        self.assertEqual(item["hostname"], "HOST-1")
        self.assertEqual(item["title"], "CVE Alert")
        self.assertEqual(item["severity"], "Critical")
        self.assertEqual(item["link"], "https://nvd.nist.gov/")
        self.assertEqual(item["confidence"], "confirmed")
        self.assertEqual(item["status"], "active")
        conn.close()

    def test_status_filter(self):
        conn = _make_db()
        self._seed(conn)
        # No acknowledged items
        result = get_exposure_items("FSC", status="acknowledged", conn=conn)
        self.assertEqual(result["total"], 0)
        # 'all' returns the active one
        result = get_exposure_items("FSC", status="all", conn=conn)
        self.assertEqual(result["total"], 1)
        conn.close()

    def test_org_filter(self):
        conn = _make_db()
        self._seed(conn)
        result = get_exposure_items("Other Org", conn=conn)
        self.assertEqual(result["total"], 0)
        conn.close()

    def test_pagination(self):
        conn = _make_db()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("INSERT INTO runzero_assets (id, org) VALUES ('a1','FSC')")
        conn.execute("INSERT INTO runzero_assets (id, org) VALUES ('a2','FSC')")
        conn.execute("INSERT INTO entries (hash, source, title) VALUES ('h1','S','E1')")
        conn.execute("INSERT INTO entries (hash, source, title) VALUES ('h2','S','E2')")
        conn.execute("INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence) VALUES ('h1','a1','cve','confirmed')")
        conn.execute("INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence) VALUES ('h2','a2','cve','confirmed')")
        conn.execute(
            "INSERT INTO exposure_items (asset_id,entry_hash,status,first_seen,last_seen) VALUES ('a1','h1','active',?,?)",
            (now, now),
        )
        conn.execute(
            "INSERT INTO exposure_items (asset_id,entry_hash,status,first_seen,last_seen) VALUES ('a2','h2','active',?,?)",
            (now, now),
        )
        conn.commit()
        page1 = get_exposure_items("FSC", limit=1, offset=0, conn=conn)
        page2 = get_exposure_items("FSC", limit=1, offset=1, conn=conn)
        self.assertEqual(page1["total"], 2)
        self.assertEqual(len(page1["items"]), 1)
        self.assertEqual(len(page2["items"]), 1)
        self.assertNotEqual(page1["items"][0]["id"], page2["items"][0]["id"])
        conn.close()


class TestPatch(unittest.TestCase):
    def _make_item(self, conn):
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("INSERT INTO runzero_assets (id, org) VALUES ('a1','FSC')")
        conn.execute("INSERT INTO entries (hash, source, title) VALUES ('h1','S','T')")
        conn.execute(
            "INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence) VALUES ('h1','a1','cve','confirmed')"
        )
        conn.execute(
            "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen) "
            "VALUES ('a1','h1','active',?,?)", (now, now)
        )
        conn.execute(
            "INSERT INTO users (entra_oid, email, display_name, role) VALUES ('o1','x@y.com','Alice','viewer')"
        )
        conn.commit()
        return conn.execute("SELECT id FROM exposure_items").fetchone()[0]

    def test_status_change_to_acknowledged(self):
        conn = _make_db()
        item_id = self._make_item(conn)
        patch_exposure_item(item_id, actor="jsmith", status="acknowledged", conn=conn)
        row = conn.execute("SELECT status FROM exposure_items WHERE id=?", (item_id,)).fetchone()
        self.assertEqual(row[0], "acknowledged")
        log = conn.execute(
            "SELECT actor, action, detail FROM exposure_audit_log WHERE exposure_item_id=?",
            (item_id,),
        ).fetchone()
        self.assertEqual(log[0], "jsmith")
        self.assertEqual(log[1], "status_change")
        self.assertEqual(log[2], "active → acknowledged")
        conn.close()

    def test_reopen_to_active(self):
        conn = _make_db()
        item_id = self._make_item(conn)
        conn.execute(
            "UPDATE exposure_items SET status='acknowledged' WHERE id=?", (item_id,)
        )
        conn.commit()
        patch_exposure_item(item_id, actor="jsmith", status="active", conn=conn)
        row = conn.execute("SELECT status FROM exposure_items WHERE id=?", (item_id,)).fetchone()
        self.assertEqual(row[0], "active")
        conn.close()

    def test_setting_remediated_raises(self):
        conn = _make_db()
        item_id = self._make_item(conn)
        with self.assertRaises(ValueError):
            patch_exposure_item(item_id, actor="jsmith", status="remediated", conn=conn)
        conn.close()

    def test_notes_update_writes_audit(self):
        conn = _make_db()
        item_id = self._make_item(conn)
        patch_exposure_item(item_id, actor="jsmith", notes="Patch scheduled.", conn=conn)
        row = conn.execute("SELECT notes FROM exposure_items WHERE id=?", (item_id,)).fetchone()
        self.assertEqual(row[0], "Patch scheduled.")
        log = conn.execute(
            "SELECT action, detail FROM exposure_audit_log WHERE exposure_item_id=?",
            (item_id,),
        ).fetchone()
        self.assertEqual(log[0], "note_added")
        self.assertIn("Patch scheduled.", log[1])
        conn.close()

    def test_assignment_validates_user(self):
        conn = _make_db()
        item_id = self._make_item(conn)
        with self.assertRaises(ValueError):
            patch_exposure_item(item_id, actor="jsmith", assigned_to="Unknown Person", conn=conn)
        conn.close()

    def test_assignment_writes_audit(self):
        conn = _make_db()
        item_id = self._make_item(conn)
        patch_exposure_item(item_id, actor="jsmith", assigned_to="Alice", conn=conn)
        row = conn.execute(
            "SELECT assigned_to FROM exposure_items WHERE id=?", (item_id,)
        ).fetchone()
        self.assertEqual(row[0], "Alice")
        log = conn.execute(
            "SELECT action, detail FROM exposure_audit_log WHERE exposure_item_id=?",
            (item_id,),
        ).fetchone()
        self.assertEqual(log[0], "assigned")
        self.assertIn("Alice", log[1])
        conn.close()

    def test_unassign_writes_audit(self):
        conn = _make_db()
        item_id = self._make_item(conn)
        conn.execute(
            "UPDATE exposure_items SET assigned_to='Alice' WHERE id=?", (item_id,)
        )
        conn.commit()
        patch_exposure_item(item_id, actor="jsmith", assigned_to=None, conn=conn)
        row = conn.execute(
            "SELECT assigned_to FROM exposure_items WHERE id=?", (item_id,)
        ).fetchone()
        self.assertIsNone(row[0])
        log = conn.execute(
            "SELECT detail FROM exposure_audit_log WHERE exposure_item_id=?",
            (item_id,),
        ).fetchone()
        self.assertIn("unassigned", log[0])
        conn.close()

    def test_returns_updated_item(self):
        conn = _make_db()
        item_id = self._make_item(conn)
        result = patch_exposure_item(
            item_id, actor="jsmith", status="acknowledged", conn=conn
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(result["status"], "acknowledged")
        conn.close()


class TestAudit(unittest.TestCase):
    def test_returns_log_newest_first(self):
        conn = _make_db()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("INSERT INTO runzero_assets (id, org) VALUES ('a1','FSC')")
        conn.execute("INSERT INTO entries (hash, source, title) VALUES ('h1','S','T')")
        conn.execute(
            "INSERT INTO runzero_matches (entry_hash, asset_id, match_type, confidence) VALUES ('h1','a1','cve','confirmed')"
        )
        conn.execute(
            "INSERT INTO exposure_items (asset_id, entry_hash, status, first_seen, last_seen) "
            "VALUES ('a1','h1','acknowledged',?,?)", (now, now)
        )
        conn.commit()
        item_id = conn.execute("SELECT id FROM exposure_items").fetchone()[0]
        conn.execute(
            "INSERT INTO exposure_audit_log (exposure_item_id, actor, action, detail, created_at) "
            "VALUES (?, 'system', 'status_change', 'active → acknowledged', '2026-07-01T10:00:00Z')",
            (item_id,),
        )
        conn.execute(
            "INSERT INTO exposure_audit_log (exposure_item_id, actor, action, detail, created_at) "
            "VALUES (?, 'alice', 'note_added', 'Patch scheduled.', '2026-07-02T09:00:00Z')",
            (item_id,),
        )
        conn.commit()
        log = get_exposure_audit(item_id, conn=conn)
        self.assertEqual(len(log), 2)
        self.assertEqual(log[0]["actor"], "alice")  # newest first
        self.assertEqual(log[1]["actor"], "system")
        conn.close()


if __name__ == "__main__":
    unittest.main()
