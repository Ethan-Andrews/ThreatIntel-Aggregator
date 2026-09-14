-- Audit trail for admin actions (apply/dismiss) on stage-7 tuning
-- suggestions -- tune.py's run_tune_loop() output, persisted as
-- analytics.tune_history.final_body (see pg_detection_strategies.sql).
-- See detection_pipeline/tuning_actions.py (read/write) and
-- detection_pipeline/tuning_suggestions.py (the apply/dismiss orchestration
-- that writes here).
--
-- Deliberately keyed only on analytic_id, not on a hunt or a catalog-view
-- concept -- Hunts and the flat Detections/Analytics-Rules catalog both
-- render the same underlying `analytics` rows, just grouped differently, so
-- one audit table serves both surfaces without caring which panel
-- triggered the action.
--
-- suggested_kql_body is a SNAPSHOT of tune_history.final_body taken at the
-- moment of the action, not a live re-read: tune_history can be overwritten
-- by a later tuning pass (a fresh orchestrator run re-tunes the same
-- analytic), and the audit trail must record what was actually reviewed/
-- applied at the time, not whatever tune_history happens to say today.
--
-- Append-only from the app's perspective, matching analytics/
-- disposition_checks' convention: an action, once recorded, is never edited
-- or deleted. A later change of mind (e.g. dismiss after an earlier apply)
-- is a NEW row, not a correction of the old one -- the point-in-time
-- history is the product, not just the latest state.
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent:
-- safe to re-run.

CREATE TABLE IF NOT EXISTS tuning_suggestion_actions (
    id                   bigserial   PRIMARY KEY,
    analytic_id          bigint      NOT NULL REFERENCES analytics(id),
    suggested_kql_body   text        NOT NULL,
    action               text        NOT NULL
                         CHECK (action IN ('applied', 'dismissed')),
    -- Only ever set when action='applied' AND the Sentinel push actually
    -- succeeded -- a failed apply attempt still gets action='applied' (that
    -- was what was requested) but leaves this NULL, with the failure detail
    -- in sentinel_push_result instead. Never set for a 'dismissed' row.
    applied_kql_body     text,
    -- {"status": "success"} or {"status": "error", "detail": "..."}.
    -- NULL for 'dismissed' rows, which never touch Sentinel.
    sentinel_push_result jsonb,
    performed_by         text,
    performed_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_tuning_suggestion_actions_applied_body
        CHECK (action = 'applied' OR applied_kql_body IS NULL)
);

CREATE INDEX IF NOT EXISTS ix_tuning_suggestion_actions_analytic
    ON tuning_suggestion_actions (analytic_id, performed_at DESC);

GRANT SELECT, INSERT ON tuning_suggestion_actions TO tiapp;
GRANT USAGE, SELECT ON SEQUENCE tuning_suggestion_actions_id_seq TO tiapp;
