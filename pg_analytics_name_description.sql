-- Every generated analytic already carries a human-readable title and
-- description from detections.ai at generation time (detections_client.py's
-- Detection dataclass -- det.title / det.description), but orchestrator.py
-- discarded both before writing the analytics row. Every downstream
-- consumer (disposition alerts, alignment review, the detections catalog)
-- was left identifying rows purely by MITRE technique, which is shared
-- across every analytic implementing that technique and useless for
-- triaging a specific alert. This adds storage for the name/description so
-- they can be threaded through register_analytic() and surfaced everywhere.
--
-- Nullable: analytics rows created before this migration have no stored
-- name/description (detections.ai wasn't asked to return them at read
-- time, and re-fetching by artifact_id for every historical row is a
-- separate backfill decision, not bundled into this migration). Callers
-- must handle NULL and fall back to technique_id/technique_name for
-- display, not assume every row has a name.
ALTER TABLE analytics ADD COLUMN IF NOT EXISTS name text;
ALTER TABLE analytics ADD COLUMN IF NOT EXISTS description text;
