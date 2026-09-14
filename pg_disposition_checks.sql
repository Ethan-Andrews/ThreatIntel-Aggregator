-- Stage 9: periodic re-confirmation that a shipped 'clean'-disposition
-- analytic hasn't silently rotted -- either it started firing, or its
-- telemetry died underneath it (which also reports zero hits and would
-- otherwise look identical to "still clean"). See disposition_tracker.py.
--
-- Append-only from the app's perspective, matching analytics/
-- coverage_evidence's convention -- one row per recheck, never updated.
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent:
-- safe to re-run.

CREATE TABLE IF NOT EXISTS disposition_checks (
    id                          bigserial   PRIMARY KEY,
    analytic_id                 bigint      NOT NULL REFERENCES analytics(id),
    checked_at                  timestamptz NOT NULL DEFAULT now(),
    hits                        integer,
    window_hours                numeric,
    control_probe_disposition   text        NOT NULL,
    backtest_disposition        text,
    outcome                     text        NOT NULL
                                CHECK (outcome IN ('still_clean', 'now_firing',
                                                    'telemetry_decayed', 'check_error')),
    detail                      jsonb
);

CREATE INDEX IF NOT EXISTS ix_disposition_checks_analytic
    ON disposition_checks (analytic_id, checked_at DESC);

GRANT SELECT, INSERT ON disposition_checks TO tiapp;
GRANT USAGE, SELECT ON SEQUENCE disposition_checks_id_seq TO tiapp;
