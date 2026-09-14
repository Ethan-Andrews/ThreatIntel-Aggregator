-- Per-entity hit-frequency baseline for fired detections.
--
-- Distinct from telemetry_baseline (column population across a whole table)
-- and from detection_strategies/analytics (does a rule exist and validate).
-- This tracks a narrower question: for a SPECIFIC shipped analytic, how
-- often has a SPECIFIC entity (an account, a file, a folder path) triggered
-- it historically -- so a new firing can be judged against that entity's
-- own history rather than against an absolute threshold or a literal-value
-- match, which would carry the same fragility as artifact-keyed detection
-- one layer up.
--
-- One row per (analytic, dimension, entity value, day). Deliberately daily
-- rather than a running total: a time series is what lets a later check
-- compute an average and compare a new day against it, rather than only
-- ever accumulating a number nothing can be judged against.
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent:
-- safe to re-run.

CREATE TABLE IF NOT EXISTS hit_baseline (
    id            bigserial PRIMARY KEY,
    analytic_id   bigint      NOT NULL REFERENCES analytics(id),
    dimension     text        NOT NULL,   -- e.g. 'InitiatingProcessAccountName'
    entity_value  text        NOT NULL,   -- e.g. 'svc_bwapp'
    window_start  date        NOT NULL,   -- the day this count covers
    hit_count     integer     NOT NULL,
    recorded_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (analytic_id, dimension, entity_value, window_start)
);

CREATE INDEX IF NOT EXISTS ix_hit_baseline_lookup
    ON hit_baseline (analytic_id, dimension, entity_value, window_start DESC);

GRANT SELECT, INSERT, UPDATE ON hit_baseline TO tiapp;
GRANT USAGE, SELECT ON SEQUENCE hit_baseline_id_seq TO tiapp;

-- UPDATE is granted (unlike the append-only convention on analytics and
-- coverage_evidence) because a day's count may legitimately be re-recorded
-- if the job re-runs the same day -- ON CONFLICT ... DO UPDATE in the
-- application layer relies on this.
