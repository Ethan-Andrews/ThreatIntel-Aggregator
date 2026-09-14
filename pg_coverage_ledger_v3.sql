-- Widen last_validation_result's allowed values so revalidate_strategy()
-- can report an alignment-only divergence distinctly from a telemetry
-- degradation or probe error. See alignment_check.py and coverage_ledger.py.
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent:
-- safe to re-run.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_last_validation_result'
    ) THEN
        ALTER TABLE detection_strategies DROP CONSTRAINT chk_last_validation_result;
    END IF;
    ALTER TABLE detection_strategies
        ADD CONSTRAINT chk_last_validation_result
        CHECK (last_validation_result IN ('ok', 'degraded', 'error', 'alignment_diverges')
               OR last_validation_result IS NULL);
END $$;
