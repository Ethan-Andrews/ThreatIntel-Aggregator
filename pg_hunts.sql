-- A "hunt" groups every detection/query generated from the same TI
-- article/detections.ai project into one unit -- the container concept
-- Microsoft Sentinel's own "Hunts" feature (Microsoft.SecurityInsights/hunts,
-- public preview) uses natively: a hunt has a name/description and contains
-- its own queries, kept separately from every other hunt's queries. See
-- detection_pipeline/sentinel_hunting.py for the ARM client that syncs a
-- hunt row (and its child analytics) into that real Sentinel object once
-- RBAC is granted.
--
-- Every `analytics` row already carried `source_entry_hash` (= the
-- originating TI entry's hash) with no grouping table behind it -- this
-- table gives that implicit grouping a real identity. `source_entry_hash`
-- is UNIQUE here because orchestrator.py's process_one() runs once per
-- candidate/article; every analytic generated from that one run shares the
-- same hash and therefore the same hunt.
CREATE TABLE IF NOT EXISTS hunts (
    id                  bigserial PRIMARY KEY,
    source_entry_hash   text NOT NULL UNIQUE,
    title               text NOT NULL,
    description         text,
    source_title        text,
    source_link         text,
    source_name         text,
    source_severity     text,
    -- Populated once SENTINEL_HUNTING_SYNC_ENABLED is on and the sync
    -- actually succeeds against a real workspace. NULL means "not yet
    -- synced" (sync disabled, or every attempt so far failed) -- the
    -- pipeline never blocks on this, see sentinel_hunting.py.
    sentinel_hunt_id    text,
    sentinel_synced_at  timestamptz,
    sentinel_sync_error text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE analytics ADD COLUMN IF NOT EXISTS hunt_id bigint REFERENCES hunts(id);
CREATE INDEX IF NOT EXISTS idx_analytics_hunt_id ON analytics (hunt_id);

-- Backfill: reconstruct hunts for every analytics row that predates this
-- migration, purely from data already on hand (source_entry_hash + a best-
-- effort join back to `entries` for display fields). No dependency on
-- detections.ai -- if the originating entry has since been archived/
-- deleted, the hunt still gets created with a fallback title rather than
-- being silently skipped.
INSERT INTO hunts (source_entry_hash, title, source_title, source_link, source_name, source_severity, created_at)
SELECT a.source_entry_hash,
       COALESCE(MIN(e.title), 'Untitled hunt'),
       MIN(e.title), MIN(e.link), MIN(e.source), MIN(e.severity),
       MIN(a.created_at)
FROM analytics a
LEFT JOIN entries e ON e.hash = a.source_entry_hash
WHERE a.hunt_id IS NULL
GROUP BY a.source_entry_hash
ON CONFLICT (source_entry_hash) DO NOTHING;

UPDATE analytics a
SET hunt_id = h.id
FROM hunts h
WHERE a.hunt_id IS NULL AND h.source_entry_hash = a.source_entry_hash;
