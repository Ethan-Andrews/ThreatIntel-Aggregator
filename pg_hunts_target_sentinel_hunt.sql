-- Lets an admin point one of our own `hunts` rows at a Sentinel Hunt that
-- already exists (e.g. "In the News V2"), instead of always creating/
-- managing a dedicated 1:1 Sentinel Hunt per our hunt row (sentinel_hunting.
-- sync_hunt()'s default). NULL (the default) keeps today's behavior.
--
-- Value is the target Sentinel Hunt's ARM resource name (the GUID segment
-- in .../providers/Microsoft.SecurityInsights/hunts/{this}), not its
-- display name -- display names aren't unique and aren't stable ARM
-- identifiers. The picker in the UI resolves a chosen display name to this
-- id via SentinelHuntingClient.list_hunts().
--
-- No new GRANT needed: tiapp already has UPDATE on the whole hunts table
-- (mark_hunt_synced() already updates sentinel_hunt_id/sentinel_synced_at/
-- sentinel_sync_error on it), which covers this new column too.

ALTER TABLE hunts ADD COLUMN IF NOT EXISTS target_sentinel_hunt_id text;
