"""Tests for tuning_suggestions.py -- the apply/dismiss orchestration behind
POST /api/detections/tuning-suggestions/{apply,dismiss}. HTTP to Sentinel is
mocked via httpx.MockTransport (same technique as test_sentinel_hunting.py)
so this runs without real Azure credentials."""

import json
import sys
import types
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import hunt_sync_settings
import hunts as hunts_module
import sentinel_hunting
import tuning_actions
import tuning_suggestions


class _FakeCredential:
    def get_token(self, scope):
        return types.SimpleNamespace(token="fake-arm-token", expires_on=9999999999)


def _client_factory(handler=None):
    def factory():
        client = sentinel_hunting.SentinelHuntingClient(
            subscription_id="sub-1", resource_group="rg-1", workspace_name="ws-1",
            credential=_FakeCredential(),
        )
        client._client = httpx.Client(
            transport=httpx.MockTransport(handler or (lambda req: httpx.Response(200, json={})))
        )
        return client
    return factory


def _seed_strategy(conn, technique_id="T1053.005"):
    row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, "Scheduled Task", "Detect it", []),
    ).fetchone()
    conn.commit()
    return row["id"]


def _seed_analytic(conn, strategy_id, hunt_id=None, name="Suspicious Task",
                   description="desc", tune_history=None):
    row = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, name, "
        " description, hunt_id, tune_history) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
        (strategy_id, "hash-" + str(strategy_id), "SomeTable | take 1", name,
         description, hunt_id, json.dumps(tune_history) if tune_history is not None else None),
    ).fetchone()
    conn.commit()
    return row["id"]


_TUNED_HISTORY = {
    "disposition": "tuned",
    "final_body": 'SomeTable | where AccountName != @"bob"',
}


def _enable_sync(conn, mode="manual"):
    hunt_sync_settings.set_settings(conn, mode, True, "tester")


# --- apply_suggestions(): eligibility / skip reasons ----------------------

def test_apply_unknown_analytic_id_reports_not_found(db_conn):
    results = tuning_suggestions.apply_suggestions(db_conn, [999999])
    assert results == [{"analytic_id": 999999, "success": False, "reason": "analytic not found"}]


def test_apply_analytic_with_no_tune_history_is_skipped(db_conn):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id, tune_history=None)

    results = tuning_suggestions.apply_suggestions(db_conn, [analytic_id])
    assert results[0]["success"] is False
    assert "no tuning suggestion" in results[0]["reason"]


def test_apply_analytic_with_no_final_body_is_skipped(db_conn):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(
        db_conn, strategy_id, tune_history={"disposition": "needs_human_tuning", "final_body": None},
    )
    results = tuning_suggestions.apply_suggestions(db_conn, [analytic_id])
    assert results[0]["success"] is False
    assert "no tuning suggestion" in results[0]["reason"]


def test_apply_analytic_not_in_a_hunt_is_skipped(db_conn):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id, hunt_id=None, tune_history=_TUNED_HISTORY)
    _enable_sync(db_conn, "manual")

    results = tuning_suggestions.apply_suggestions(db_conn, [analytic_id])
    assert results[0]["success"] is False
    assert "does not belong to a hunt" in results[0]["reason"]


def test_apply_skipped_when_sync_mode_is_off(db_conn):
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "hash-1", title="Hunt")
    analytic_id = _seed_analytic(db_conn, strategy_id, hunt_id=hunt_id, tune_history=_TUNED_HISTORY)
    _enable_sync(db_conn, "off")

    results = tuning_suggestions.apply_suggestions(db_conn, [analytic_id])
    assert results[0]["success"] is False
    assert "Sentinel sync is off" in results[0]["reason"]


def test_apply_skipped_when_mode_on_but_master_kill_switch_disabled(db_conn, monkeypatch):
    """mode != 'off' alone must not report success -- the
    SENTINEL_HUNTING_SYNC_ENABLED master switch also gates whether a push
    can actually reach Sentinel."""
    monkeypatch.delenv("SENTINEL_HUNTING_SYNC_ENABLED", raising=False)
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "hash-1", title="Hunt")
    analytic_id = _seed_analytic(db_conn, strategy_id, hunt_id=hunt_id, tune_history=_TUNED_HISTORY)
    _enable_sync(db_conn, "manual")

    results = tuning_suggestions.apply_suggestions(db_conn, [analytic_id])
    assert results[0]["success"] is False
    assert "Sentinel sync is off" in results[0]["reason"]


# --- apply_suggestions(): real push path (mocked transport) --------------

def test_apply_success_records_applied_action_and_pushes_full_attributes(db_conn, monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "hash-1", title="Hunt")
    analytic_id = _seed_analytic(db_conn, strategy_id, hunt_id=hunt_id, tune_history=_TUNED_HISTORY)
    _enable_sync(db_conn, "manual")

    captured = {}
    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read())
        return httpx.Response(200, json={"id": "ok"})

    results = tuning_suggestions.apply_suggestions(
        db_conn, [analytic_id], performed_by="admin@example.com",
        client_factory=_client_factory(handler),
    )

    assert results == [{"analytic_id": analytic_id, "success": True, "reason": None}]
    # Every attribute re-sent, not a partial PUT: query is the tuned body,
    # but displayName/description/tags still carry the analytic's stored
    # name/description/technique -- confirming this isn't a bare query swap.
    props = captured["body"]["properties"]
    # append_entity_mapping_extends() appends an entity-mapping extend line
    # for AccountName -- expected, same as sync_hunt()'s own push path.
    assert props["query"].startswith(_TUNED_HISTORY["final_body"])
    assert "Account_0_Name = AccountName" in props["query"]
    assert props["displayName"] == "Suspicious Task"
    tag_names = {t["Name"]: t["Value"] for t in props["tags"]}
    assert tag_names["description"] == "desc"
    assert "tactics" in tag_names

    row = db_conn.execute(
        "SELECT * FROM tuning_suggestion_actions WHERE analytic_id = ?", (analytic_id,)
    ).fetchone()
    assert row["action"] == "applied"
    assert row["applied_kql_body"] == _TUNED_HISTORY["final_body"]
    assert row["sentinel_push_result"] == {"status": "success"}
    assert row["performed_by"] == "admin@example.com"


def test_apply_push_failure_records_error_without_applied_body(db_conn, monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "hash-1", title="Hunt")
    analytic_id = _seed_analytic(db_conn, strategy_id, hunt_id=hunt_id, tune_history=_TUNED_HISTORY)
    _enable_sync(db_conn, "manual")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="Forbidden")

    results = tuning_suggestions.apply_suggestions(
        db_conn, [analytic_id], client_factory=_client_factory(handler),
    )

    assert results[0]["success"] is False
    assert "403" in results[0]["reason"]

    row = db_conn.execute(
        "SELECT * FROM tuning_suggestion_actions WHERE analytic_id = ?", (analytic_id,)
    ).fetchone()
    assert row["action"] == "applied"
    assert row["applied_kql_body"] is None
    assert row["sentinel_push_result"]["status"] == "error"


def test_apply_client_construction_failure_reports_reason_without_pushing(db_conn, monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "hash-1", title="Hunt")
    analytic_id = _seed_analytic(db_conn, strategy_id, hunt_id=hunt_id, tune_history=_TUNED_HISTORY)
    _enable_sync(db_conn, "manual")

    def _boom():
        raise sentinel_hunting.SentinelHuntingError("missing required config: AZURE_SUBSCRIPTION_ID")

    results = tuning_suggestions.apply_suggestions(db_conn, [analytic_id], client_factory=_boom)
    assert results[0]["success"] is False
    assert "AZURE_SUBSCRIPTION_ID" in results[0]["reason"]


# --- apply_suggestions(): batch never all-or-nothing ----------------------

def test_apply_batch_reports_independent_outcomes_per_id(db_conn, monkeypatch):
    monkeypatch.setenv("SENTINEL_HUNTING_SYNC_ENABLED", "true")
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts_module.get_or_create_hunt(db_conn, "hash-1", title="Hunt")
    good_id = _seed_analytic(db_conn, strategy_id, hunt_id=hunt_id, tune_history=_TUNED_HISTORY)
    no_suggestion_id = _seed_analytic(db_conn, strategy_id, hunt_id=hunt_id, tune_history=None)
    not_in_hunt_id = _seed_analytic(db_conn, strategy_id, hunt_id=None, tune_history=_TUNED_HISTORY)
    _enable_sync(db_conn, "manual")

    results = tuning_suggestions.apply_suggestions(
        db_conn, [good_id, no_suggestion_id, not_in_hunt_id, 999999],
        client_factory=_client_factory(),
    )

    by_id = {r["analytic_id"]: r for r in results}
    assert by_id[good_id]["success"] is True
    assert by_id[no_suggestion_id]["success"] is False
    assert by_id[not_in_hunt_id]["success"] is False
    assert by_id[999999]["success"] is False
    # A batch of 4 with 3 ineligible/missing never blocks the one real success.
    assert sum(r["success"] for r in results) == 1


# --- dismiss_suggestions() --------------------------------------------------

def test_dismiss_records_dismissed_action(db_conn):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id, tune_history=_TUNED_HISTORY)

    results = tuning_suggestions.dismiss_suggestions(
        db_conn, [analytic_id], performed_by="admin@example.com",
    )
    assert results == [{"analytic_id": analytic_id, "success": True, "reason": None}]

    row = db_conn.execute(
        "SELECT * FROM tuning_suggestion_actions WHERE analytic_id = ?", (analytic_id,)
    ).fetchone()
    assert row["action"] == "dismissed"
    assert row["applied_kql_body"] is None
    assert row["sentinel_push_result"] is None
    assert row["performed_by"] == "admin@example.com"


def test_dismiss_does_not_require_hunt_or_sync_enabled(db_conn):
    """Dismissing never touches Sentinel, so it must not be gated by
    hunt_id or hunt_sync_settings the way apply is."""
    strategy_id = _seed_strategy(db_conn)
    analytic_id = _seed_analytic(db_conn, strategy_id, hunt_id=None, tune_history=_TUNED_HISTORY)
    # sync explicitly off/unconfigured
    results = tuning_suggestions.dismiss_suggestions(db_conn, [analytic_id])
    assert results[0]["success"] is True


def test_dismiss_unknown_or_no_suggestion_reports_failure(db_conn):
    strategy_id = _seed_strategy(db_conn)
    no_suggestion_id = _seed_analytic(db_conn, strategy_id, tune_history=None)

    results = tuning_suggestions.dismiss_suggestions(db_conn, [999999, no_suggestion_id])
    assert results[0]["success"] is False
    assert results[0]["reason"] == "analytic not found"
    assert results[1]["success"] is False
    assert "no tuning suggestion" in results[1]["reason"]
