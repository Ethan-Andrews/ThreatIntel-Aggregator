-- Local cache of MITRE ATT&CK's own Detection Strategy + Analytic + Data
-- Component catalog. Populated by mitre_sync.py's sync_all(), which
-- downloads the current STIX bundle once and upserts all three tables in
-- full -- built for a future cadence (daily/weekly scheduled job), not
-- fetched per-technique on alignment_check.py's hot path. See mitre_sync.py
-- and the design doc's "cadence-based sync" section.
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent:
-- safe to re-run.

CREATE TABLE IF NOT EXISTS mitre_detection_strategies (
    id              text PRIMARY KEY,        -- STIX id, e.g. 'x-mitre-detection-strategy--...'
    det_id          text,                    -- e.g. 'DET0210'; external_references[].external_id
    technique_id    text,                    -- e.g. 'T1053.005', resolved via the 'detects' relationship
    name            text,
    objective       text,                    -- MITRE's description field
    synced_at       timestamptz NOT NULL DEFAULT now(),
    catalog_version text                     -- attack-stix-data x_mitre_version at sync time
);

CREATE INDEX IF NOT EXISTS ix_mitre_detection_strategies_technique
    ON mitre_detection_strategies (technique_id);

CREATE TABLE IF NOT EXISTS mitre_analytics (
    id                     text PRIMARY KEY,  -- STIX id, e.g. 'x-mitre-analytic--...'
    detection_strategy_id  text NOT NULL REFERENCES mitre_detection_strategies(id),
    name                   text,
    description            text,
    platform               text,              -- x_mitre_platforms[0] -- see design doc's open questions
    log_source_references  jsonb,             -- [{data_component_id, name, channel}, ...]
    mutable_elements       jsonb,             -- [{field, description}, ...] -- MITRE's own tuning knobs
    synced_at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_mitre_analytics_strategy
    ON mitre_analytics (detection_strategy_id);

CREATE TABLE IF NOT EXISTS mitre_data_components (
    id          text PRIMARY KEY,             -- STIX id, e.g. 'x-mitre-data-component--...'
    name        text,
    description text,
    log_sources jsonb,                        -- [{name, channel}, ...] e.g. {"name": "sysmon", "channel": "1"}
    synced_at   timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE ON mitre_detection_strategies TO tiapp;
GRANT SELECT, INSERT, UPDATE ON mitre_analytics TO tiapp;
GRANT SELECT, INSERT, UPDATE ON mitre_data_components TO tiapp;

-- No sequence grants: all three tables use the STIX id itself (text) as
-- primary key, not a bigserial id -- upserts key on it directly.
