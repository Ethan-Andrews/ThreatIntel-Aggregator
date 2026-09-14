-- Adds admin-configurable interval/window/day-of-week controls on top of
-- the existing enabled/disabled soft gate (pg_orchestrator_settings.sql).
-- See orchestrator_settings.py's is_due() for how these combine.
--
-- Real constraint (documented in the UI, not just here): Azure's own
-- Container Apps Job schedule trigger is a fixed outer cron
-- (infra/apps.bicep's orchestratorSchedule param, deployed as */30 * * * *
-- -- confirm this hasn't been overridden before trusting it) that this
-- table cannot change. A DB-driven "effective interval" can only ever be
-- a MULTIPLE of that outer cron (skip N-1 of every N fires) -- it can
-- lengthen the effective interval but never shorten it below the outer
-- cron's own cadence.
--
--   interval_minutes     -- minimum minutes that must elapse since
--                            last_run_at before the next fire actually
--                            does work. Default 30 preserves today's
--                            behavior (fire every outer-cron tick).
--   window_start_minute  -- minutes since midnight UTC the daily window
--                            opens. NULL (with window_end_minute also
--                            NULL) means "no window restriction, any time
--                            of day" -- must be set/cleared together.
--   window_end_minute    -- minutes since midnight UTC the daily window
--                            closes. A window that wraps past midnight
--                            (start > end, e.g. 22:00-02:00) is valid --
--                            is_due() interprets that as spanning
--                            midnight, not rejects it.
--   days_of_week         -- smallint[] using Postgres's own
--                            date_part('dow', ...) numbering (0=Sunday ..
--                            6=Saturday), so is_due()'s comparison needs
--                            no translation layer. NULL/empty means
--                            "every day."
--   last_run_at          -- when the orchestrator last actually did work
--                            (set at the top of run(), once the gate
--                            passes -- not at the end, so a long-running
--                            batch doesn't skew the next fire's elapsed-
--                            time check).
--
-- Single row (id=1), UPDATE in place, same convention as
-- pg_orchestrator_settings.sql. The app user (tiapp) is DML only, so this
-- runs as pgadmin. Idempotent: safe to re-run.

ALTER TABLE orchestrator_settings
    ADD COLUMN IF NOT EXISTS interval_minutes    integer     NOT NULL DEFAULT 30,
    ADD COLUMN IF NOT EXISTS window_start_minute smallint,
    ADD COLUMN IF NOT EXISTS window_end_minute   smallint,
    ADD COLUMN IF NOT EXISTS days_of_week        smallint[],
    ADD COLUMN IF NOT EXISTS last_run_at         timestamptz;

-- Postgres has no ADD CONSTRAINT IF NOT EXISTS -- guard with a catalog
-- check instead of letting a re-run fail on a duplicate constraint name,
-- same idiom as pg_coverage_ledger_v2.sql/pg_analytics_validation_columns.sql.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_orchestrator_settings_interval_positive'
    ) THEN
        ALTER TABLE orchestrator_settings
            ADD CONSTRAINT chk_orchestrator_settings_interval_positive
            CHECK (interval_minutes > 0 AND interval_minutes <= 10080);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_orchestrator_settings_window_minutes'
    ) THEN
        ALTER TABLE orchestrator_settings
            ADD CONSTRAINT chk_orchestrator_settings_window_minutes
            CHECK (
                (window_start_minute IS NULL) = (window_end_minute IS NULL)
                AND (window_start_minute IS NULL OR window_start_minute BETWEEN 0 AND 1439)
                AND (window_end_minute IS NULL OR window_end_minute BETWEEN 0 AND 1439)
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_orchestrator_settings_days_of_week'
    ) THEN
        ALTER TABLE orchestrator_settings
            ADD CONSTRAINT chk_orchestrator_settings_days_of_week
            CHECK (days_of_week IS NULL OR days_of_week <@ ARRAY[0,1,2,3,4,5,6]::smallint[]);
    END IF;
END $$;
