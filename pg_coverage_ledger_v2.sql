-- Additions to detection_strategies for trust-building: revalidation state
-- (point 2) and a place to record a human's MITRE Detection Strategies
-- cross-reference (point 3). Corroboration count (point 1) needs no schema
-- change -- coverage_evidence already exists and already holds it.
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent:
-- safe to re-run.

ALTER TABLE detection_strategies
    ADD COLUMN IF NOT EXISTS last_validated_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_validation_result text,
    ADD COLUMN IF NOT EXISTS mitre_detection_strategy_id text;

-- Constraint added separately with IF NOT EXISTS-style safety: Postgres has
-- no ADD CONSTRAINT IF NOT EXISTS, so guard with a catalog check instead of
-- letting a re-run fail on a duplicate constraint name.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_last_validation_result'
    ) THEN
        ALTER TABLE detection_strategies
            ADD CONSTRAINT chk_last_validation_result
            CHECK (last_validation_result IN ('ok', 'degraded', 'error') OR last_validation_result IS NULL);
    END IF;
END $$;

-- mitre_detection_strategy_id is deliberately just a text field, not a
-- foreign key into any local MITRE catalog table -- there is no local MITRE
-- catalog. This records a human's manual cross-reference (e.g. 'DET0740'),
-- looked up on MITRE's own site, not an automated match.
