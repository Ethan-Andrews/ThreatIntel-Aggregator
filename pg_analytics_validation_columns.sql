-- Stage 5/6 validation columns for analytics, so a static-gate verdict and a
-- control-probe result have somewhere to land -- static_gate.py's
-- GateResult.to_row() previously pointed at a "detection_backtests" table
-- that was never created; that comment was stale. backtest_disposition
-- already exists (pg_detection_strategies.sql) and stays backtest-specific
-- vocabulary (clean | tunable | needs_tuning | backtest_error): mixing
-- gate/probe/backtest semantics into one column would make it impossible
-- for a reviewer to tell which stage did or didn't run.
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent:
-- safe to re-run.

ALTER TABLE analytics
    ADD COLUMN IF NOT EXISTS static_gate_verdict   text,
    ADD COLUMN IF NOT EXISTS static_gate_findings   jsonb,
    ADD COLUMN IF NOT EXISTS control_probe_result   jsonb;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_static_gate_verdict'
    ) THEN
        ALTER TABLE analytics
            ADD CONSTRAINT chk_static_gate_verdict
            CHECK (static_gate_verdict IN ('pass', 'reject') OR static_gate_verdict IS NULL);
    END IF;
END $$;

-- No GRANT changes: analytics stays INSERT-only for tiapp. These columns
-- are populated at INSERT time via register_analytic()'s new kwargs, never
-- UPDATEd afterward -- see coverage_ledger.py's register_analytic().
