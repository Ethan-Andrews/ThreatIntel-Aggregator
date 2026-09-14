-- Adds admin-configurable severity gate + interval/window/day-of-week
-- cadence to hunt_sync_settings (pg_hunt_sync_settings.sql), mirroring
-- the identical cadence shape pg_orchestrator_settings_interval.sql
-- already proved out for the orchestrator's own schedule -- see
-- hunt_sync_settings.py's set_schedule() and orchestrator_settings.is_due(),
-- which this table's cadence columns are deliberately shaped to reuse
-- as-is rather than duplicating the same interval/window/day-of-week
-- algorithm a second time.
--
--   severities           -- text[] of 'critical'|'high'|'medium'|'low'
--                            (lowercase, matching hunt_sync_settings.mode's
--                            own lowercase-enum convention). NULL means "no
--                            severity restriction" -- every eligible hunt
--                            auto-syncs regardless of hunts.source_severity,
--                            preserving today's behavior exactly. A hunt
--                            whose source_severity isn't in this set is
--                            simply skipped this cycle (not marked failed).
--   interval_minutes     -- same semantics as orchestrator_settings'
--                            column: minimum minutes since the last auto-
--                            sync attempt before the next one actually
--                            runs. Default 30 preserves today's "sync
--                            every time process_one() reaches this block"
--                            behavior (same as the orchestrator's own
--                            30-minute outer cron cadence).
--   window_start_minute  -- minutes since midnight UTC the daily window
--   window_end_minute    -- opens/closes. Both NULL (default) means no
--                            window restriction. Must be set/cleared
--                            together, same CHECK shape as orchestrator_
--                            settings.
--   days_of_week         -- smallint[], Postgres's own date_part('dow', ...)
--                            numbering (0=Sunday..6=Saturday). NULL/empty
--                            means every day.
--   last_run_at          -- when hunt auto-sync last actually attempted a
--                            push (set right before sync_hunt() is called,
--                            not after -- same "don't let a slow sync skew
--                            the next fire's elapsed-time check" reasoning
--                            as the orchestrator's own last_run_at).
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent.

ALTER TABLE hunt_sync_settings
    ADD COLUMN IF NOT EXISTS severities          text[],
    ADD COLUMN IF NOT EXISTS interval_minutes    integer     NOT NULL DEFAULT 30,
    ADD COLUMN IF NOT EXISTS window_start_minute smallint,
    ADD COLUMN IF NOT EXISTS window_end_minute   smallint,
    ADD COLUMN IF NOT EXISTS days_of_week        smallint[],
    ADD COLUMN IF NOT EXISTS last_run_at         timestamptz;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_hunt_sync_settings_severities'
    ) THEN
        ALTER TABLE hunt_sync_settings
            ADD CONSTRAINT chk_hunt_sync_settings_severities
            CHECK (severities IS NULL OR severities <@ ARRAY['critical','high','medium','low']::text[]);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_hunt_sync_settings_interval_positive'
    ) THEN
        ALTER TABLE hunt_sync_settings
            ADD CONSTRAINT chk_hunt_sync_settings_interval_positive
            CHECK (interval_minutes > 0 AND interval_minutes <= 10080);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_hunt_sync_settings_window_minutes'
    ) THEN
        ALTER TABLE hunt_sync_settings
            ADD CONSTRAINT chk_hunt_sync_settings_window_minutes
            CHECK (
                (window_start_minute IS NULL) = (window_end_minute IS NULL)
                AND (window_start_minute IS NULL OR window_start_minute BETWEEN 0 AND 1439)
                AND (window_end_minute IS NULL OR window_end_minute BETWEEN 0 AND 1439)
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_hunt_sync_settings_days_of_week'
    ) THEN
        ALTER TABLE hunt_sync_settings
            ADD CONSTRAINT chk_hunt_sync_settings_days_of_week
            CHECK (days_of_week IS NULL OR days_of_week <@ ARRAY[0,1,2,3,4,5,6]::smallint[]);
    END IF;
END $$;
