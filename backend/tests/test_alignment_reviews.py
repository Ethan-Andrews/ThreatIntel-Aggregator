"""Tests for alignment_reviews.py -- the dashboard-facing read/write layer
main.py's /api/detections/alignment/* endpoints call."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import alignment_reviews
import hunts


def _seed_strategy(conn, technique_id="T1053.005"):
    row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, "Scheduled Task", "Detect scheduled task creation", []),
    ).fetchone()
    conn.commit()
    return row["id"]


def _seed_review(conn, strategy_id, verdict="diverges", status="pending_review", suggested_kql=None):
    row = conn.execute(
        "INSERT INTO alignment_reviews (strategy_id, verdict, ai_reasoning, suggested_kql, status) "
        "VALUES (?, ?, 'test reasoning', ?, ?) RETURNING id",
        (strategy_id, verdict, suggested_kql, status),
    ).fetchone()
    conn.commit()
    return row["id"]


def test_get_pending_reviews_returns_only_pending(db_conn):
    strategy_id = _seed_strategy(db_conn)
    pending_id = _seed_review(db_conn, strategy_id, status="pending_review")
    _seed_review(db_conn, strategy_id, status="accepted")

    result = alignment_reviews.get_pending_reviews(db_conn, limit=50, offset=0)

    assert result["total"] == 1
    assert result["items"][0]["id"] == pending_id
    assert result["items"][0]["technique_id"] == "T1053.005"


def _seed_analytic(conn, strategy_id, name=None, description=None, kql_body="X | take 1",
                   target=None, hunt_id=None):
    import json
    control_probe_result = json.dumps({"target": target}) if target else None
    row = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, name, description, "
        " control_probe_result, hunt_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
        (strategy_id, "hash-" + str(strategy_id), kql_body, name, description,
         control_probe_result, hunt_id),
    ).fetchone()
    conn.commit()
    return row["id"]


def test_get_pending_reviews_includes_detection_name_when_analytic_linked(db_conn):
    """A pending review must carry the deployed analytic's actual name/
    description, not just the shared MITRE technique -- the whole point of
    this fix is letting an analyst triage the review without a separate
    lookup."""
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(
        db_conn, strategy_id, name="Suspicious Scheduled Task Creation",
        description="Flags schtasks.exe creating a new scheduled task.",
        kql_body="DeviceProcessEvents | where FileName == 'schtasks.exe'",
    )
    review_id = _seed_review(db_conn, strategy_id)
    db_conn.execute(
        "UPDATE alignment_reviews SET analytic_id = ? WHERE id = ?",
        (analytic_id, review_id),
    )
    db_conn.commit()

    result = alignment_reviews.get_pending_reviews(db_conn, limit=50, offset=0)
    item = result["items"][0]
    assert item["detection_name"] == "Suspicious Scheduled Task Creation"
    assert item["detection_description"] == "Flags schtasks.exe creating a new scheduled task."
    assert item["deployed_kql_body"] == "DeviceProcessEvents | where FileName == 'schtasks.exe'"


def test_get_pending_reviews_handles_review_with_no_linked_analytic(db_conn):
    """Not every review has an analytic_id yet (e.g. a freshly-detected
    divergence on a strategy with no prior analytic) -- must not error, and
    must return None rather than a missing key."""
    strategy_id = _seed_strategy(db_conn)
    _seed_review(db_conn, strategy_id)

    result = alignment_reviews.get_pending_reviews(db_conn, limit=50, offset=0)
    item = result["items"][0]
    assert item["detection_name"] is None
    assert item["detection_description"] is None
    assert item["deployed_kql_body"] is None


def test_get_partial_reviews_returns_only_queued(db_conn):
    strategy_id = _seed_strategy(db_conn)
    queued_id = _seed_review(db_conn, strategy_id, verdict="partial", status="queued_for_rereview")
    _seed_review(db_conn, strategy_id, verdict="partial", status="rereview_resolved")

    result = alignment_reviews.get_partial_reviews(db_conn, limit=50, offset=0)

    assert result["total"] == 1
    assert result["items"][0]["id"] == queued_id


def test_get_pending_reviews_filters_by_detection_type_sentinel_vs_mde(db_conn):
    strategy_id = _seed_strategy(db_conn)
    sentinel_analytic = _seed_analytic(db_conn, strategy_id, target="sentinel")
    mde_analytic = _seed_analytic(db_conn, strategy_id, target="mde")
    sentinel_review = _seed_review(db_conn, strategy_id)
    mde_review = _seed_review(db_conn, strategy_id)
    db_conn.execute("UPDATE alignment_reviews SET analytic_id = ? WHERE id = ?",
                    (sentinel_analytic, sentinel_review))
    db_conn.execute("UPDATE alignment_reviews SET analytic_id = ? WHERE id = ?",
                    (mde_analytic, mde_review))
    db_conn.commit()

    sentinel_result = alignment_reviews.get_pending_reviews(db_conn, detection_type="sentinel",
                                                             limit=50, offset=0)
    assert sentinel_result["total"] == 1
    assert sentinel_result["items"][0]["id"] == sentinel_review

    mde_result = alignment_reviews.get_pending_reviews(db_conn, detection_type="mde",
                                                        limit=50, offset=0)
    assert mde_result["total"] == 1
    assert mde_result["items"][0]["id"] == mde_review


def test_get_pending_reviews_filters_by_detection_type_hunt(db_conn):
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts.get_or_create_hunt(db_conn, "hash-hunt-ar", title="Some hunt")
    hunt_analytic = _seed_analytic(db_conn, strategy_id, hunt_id=hunt_id)
    hunt_review = _seed_review(db_conn, strategy_id)
    other_review = _seed_review(db_conn, strategy_id)
    db_conn.execute("UPDATE alignment_reviews SET analytic_id = ? WHERE id = ?",
                    (hunt_analytic, hunt_review))
    db_conn.commit()

    result = alignment_reviews.get_pending_reviews(db_conn, detection_type="hunt",
                                                    limit=50, offset=0)
    assert result["total"] == 1
    assert result["items"][0]["id"] == hunt_review
    assert result["items"][0]["hunt_id"] == hunt_id


def test_get_partial_reviews_filters_by_detection_type(db_conn):
    strategy_id = _seed_strategy(db_conn)
    sentinel_analytic = _seed_analytic(db_conn, strategy_id, target="sentinel")
    sentinel_review = _seed_review(db_conn, strategy_id, verdict="partial",
                                   status="queued_for_rereview")
    other_review = _seed_review(db_conn, strategy_id, verdict="partial",
                                status="queued_for_rereview")
    db_conn.execute("UPDATE alignment_reviews SET analytic_id = ? WHERE id = ?",
                    (sentinel_analytic, sentinel_review))
    db_conn.commit()

    result = alignment_reviews.get_partial_reviews(db_conn, detection_type="sentinel",
                                                    limit=50, offset=0)
    assert result["total"] == 1
    assert result["items"][0]["id"] == sentinel_review


def test_get_pending_reviews_ready_only_excludes_rows_with_no_suggested_kql(db_conn):
    """ready_only is the round-4 'ready to accept' filter -- it should keep
    only rows accept_review() would actually be able to act on."""
    strategy_id = _seed_strategy(db_conn)
    ready_id = _seed_review(db_conn, strategy_id, suggested_kql="DeviceProcessEvents | take 1")
    _seed_review(db_conn, strategy_id, suggested_kql=None)
    _seed_review(db_conn, strategy_id, suggested_kql="")

    result = alignment_reviews.get_pending_reviews(db_conn, ready_only=True, limit=50, offset=0)

    assert result["total"] == 1
    assert result["items"][0]["id"] == ready_id


def test_get_pending_reviews_ready_only_false_returns_everything(db_conn):
    strategy_id = _seed_strategy(db_conn)
    _seed_review(db_conn, strategy_id, suggested_kql="DeviceProcessEvents | take 1")
    _seed_review(db_conn, strategy_id, suggested_kql=None)

    result = alignment_reviews.get_pending_reviews(db_conn, ready_only=False, limit=50, offset=0)
    assert result["total"] == 2


def test_get_partial_reviews_ready_only_excludes_unassessable_rows(db_conn):
    """Every queued_for_rereview row is written by _write_partial(), which
    never populates suggested_kql -- both 'AI response was not valid JSON'
    and 'MITRE has no published Detection Strategy' land here and are
    correctly excluded by the same NULL/empty check, with no separate
    reasoning-text check needed."""
    strategy_id = _seed_strategy(db_conn)
    _seed_review(db_conn, strategy_id, verdict="partial", status="queued_for_rereview",
                suggested_kql=None)

    result = alignment_reviews.get_partial_reviews(db_conn, ready_only=True, limit=50, offset=0)
    assert result["total"] == 0


import pytest


def test_accept_review_registers_analytic_and_marks_accepted(db_conn):
    strategy_id = _seed_strategy(db_conn)
    review_id = _seed_review(db_conn, strategy_id, suggested_kql="DeviceProcessEvents | take 1")

    result = alignment_reviews.accept_review(db_conn, review_id, reviewed_by="alice@example.com")

    assert result["status"] == "accepted"
    new_analytic_id = result["new_analytic_id"]
    analytic_row = db_conn.execute(
        "SELECT kql_body, review_state, strategy_id FROM analytics WHERE id = ?",
        (new_analytic_id,),
    ).fetchone()
    assert analytic_row["kql_body"] == "DeviceProcessEvents | take 1"
    assert analytic_row["review_state"] == "approved"
    assert analytic_row["strategy_id"] == strategy_id

    review_row = db_conn.execute(
        "SELECT status, reviewed_by FROM alignment_reviews WHERE id = ?", (review_id,)
    ).fetchone()
    assert review_row["status"] == "accepted"
    assert review_row["reviewed_by"] == "alice@example.com"


def test_accept_review_inherits_name_description_hunt_from_linked_analytic(db_conn):
    """Confirmed live 2026-09-02: accepting a review's suggested fix never
    passed name/description/hunt_id through at all, so the replacement
    analytic showed as permanently 'Unnamed' -- even brand new, unlike
    orchestrator.py's own register_analytic() call. The fix is a fix FOR
    the linked analytic, so it should inherit that analytic's identity."""
    import hunts
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts.get_or_create_hunt(db_conn, "hash-accept-review", title="Some hunt")
    prior_analytic_id = _seed_analytic(
        db_conn, strategy_id, name="Suspicious Scheduled Task Creation",
        description="Flags schtasks.exe creating a new scheduled task.",
        hunt_id=hunt_id,
    )
    review_id = _seed_review(db_conn, strategy_id, suggested_kql="DeviceProcessEvents | take 1")
    db_conn.execute(
        "UPDATE alignment_reviews SET analytic_id = ? WHERE id = ?",
        (prior_analytic_id, review_id),
    )
    db_conn.commit()

    result = alignment_reviews.accept_review(db_conn, review_id, reviewed_by="alice@example.com")

    new_analytic = db_conn.execute(
        "SELECT name, description, hunt_id FROM analytics WHERE id = ?",
        (result["new_analytic_id"],),
    ).fetchone()
    assert new_analytic["name"] == "Suspicious Scheduled Task Creation"
    assert new_analytic["description"] == "Flags schtasks.exe creating a new scheduled task."
    assert new_analytic["hunt_id"] == hunt_id


def test_accept_review_with_no_linked_analytic_leaves_name_null(db_conn):
    """A fresh divergence with no prior analytic (analytic_id nullable) has
    nothing to inherit from -- must not error, just fall back to the
    existing 'Unnamed' convention."""
    strategy_id = _seed_strategy(db_conn)
    review_id = _seed_review(db_conn, strategy_id, suggested_kql="DeviceProcessEvents | take 1")

    result = alignment_reviews.accept_review(db_conn, review_id, reviewed_by="alice@example.com")

    new_analytic = db_conn.execute(
        "SELECT name, hunt_id FROM analytics WHERE id = ?",
        (result["new_analytic_id"],),
    ).fetchone()
    assert new_analytic["name"] is None
    assert new_analytic["hunt_id"] is None


def test_accept_review_rejects_when_not_pending(db_conn):
    strategy_id = _seed_strategy(db_conn)
    review_id = _seed_review(db_conn, strategy_id, suggested_kql="x", status="accepted")

    with pytest.raises(ValueError, match="not pending_review"):
        alignment_reviews.accept_review(db_conn, review_id, reviewed_by="alice@example.com")


def test_accept_review_rejects_when_no_suggested_kql(db_conn):
    strategy_id = _seed_strategy(db_conn)
    review_id = _seed_review(db_conn, strategy_id, verdict="partial", status="pending_review",
                             suggested_kql=None)

    with pytest.raises(ValueError, match="no suggested_kql"):
        alignment_reviews.accept_review(db_conn, review_id, reviewed_by="alice@example.com")


def test_reject_review_marks_rejected(db_conn):
    strategy_id = _seed_strategy(db_conn)
    review_id = _seed_review(db_conn, strategy_id, suggested_kql="DeviceProcessEvents | take 1")

    result = alignment_reviews.reject_review(db_conn, review_id, reviewed_by="bob@example.com")

    assert result["status"] == "rejected"
    review_row = db_conn.execute(
        "SELECT status, reviewed_by FROM alignment_reviews WHERE id = ?", (review_id,)
    ).fetchone()
    assert review_row["status"] == "rejected"
    assert review_row["reviewed_by"] == "bob@example.com"

    count = db_conn.execute(
        "SELECT COUNT(*) FROM analytics WHERE strategy_id = ?", (strategy_id,)
    ).fetchone()[0]
    assert count == 0
