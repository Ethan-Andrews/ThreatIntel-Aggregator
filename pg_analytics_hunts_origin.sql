-- Tags where a detection/hunt actually came from: an AI-drafted candidate
-- (detections.ai, via orchestrator.py's process_one()) or a hand-imported
-- rule a user pointed the app at directly (see the Local Detections Import
-- feature). NOT NULL DEFAULT 'ai_generated' so every existing row backfills
-- to the only origin that could have produced it before this migration --
-- local import didn't exist yet, so there is nothing to reclassify.
--
-- No new GRANT needed: analytics already has INSERT (its own INSERT-only
-- convention, see pg_detection_strategies.sql) which covers writing this
-- column at insert time, and hunts already has whatever UPDATE grant
-- mark_hunt_synced() relies on (see pg_hunts_target_sentinel_hunt.sql),
-- which covers this new column too.

ALTER TABLE analytics ADD COLUMN IF NOT EXISTS origin text NOT NULL DEFAULT 'ai_generated';
ALTER TABLE hunts     ADD COLUMN IF NOT EXISTS origin text NOT NULL DEFAULT 'ai_generated';
