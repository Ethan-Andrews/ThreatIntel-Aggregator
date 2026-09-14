-- Column population baselines for the detection backtest pipeline.
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent: safe
-- to re-run.
--
-- One row per (table, column) measurement, appended rather than updated, so a
-- column's population history is recoverable. The table-level row carries an
-- empty column_name and holds the row and device counts on their own.
--
-- Why history rather than a current value: an absolute share means little on
-- its own, because some columns are sparse by design. What is meaningful is a
-- column moving away from where it has been -- that indicates an ingestion or
-- sensor change, and it is the difference between "this rule found nothing
-- because the behaviour is rare" and "this rule found nothing because the data
-- stopped arriving".

CREATE TABLE IF NOT EXISTS telemetry_baseline (
    id             bigserial PRIMARY KEY,
    table_name     text        NOT NULL,
    column_name    text        NOT NULL DEFAULT '',  -- '' = table-level row
    total_rows     bigint      NOT NULL,
    populated      bigint      NOT NULL,
    share          numeric(6,5) NOT NULL,
    devices        integer,
    lookback_days  integer     NOT NULL,
    measured_at    timestamptz NOT NULL DEFAULT now()
);

-- Supports the DISTINCT ON (column_name) ... ORDER BY measured_at DESC lookup
-- the client uses to fetch the most recent measurement per column.
CREATE INDEX IF NOT EXISTS ix_telemetry_baseline_lookup
    ON telemetry_baseline (table_name, column_name, measured_at DESC);

GRANT SELECT, INSERT ON telemetry_baseline TO tiapp;
GRANT USAGE, SELECT ON SEQUENCE telemetry_baseline_id_seq TO tiapp;

-- No DELETE or UPDATE grant: measurements are append-only. Prune from an
-- admin session if the table ever needs trimming, for example:
--   DELETE FROM telemetry_baseline WHERE measured_at < now() - interval '1 year';
