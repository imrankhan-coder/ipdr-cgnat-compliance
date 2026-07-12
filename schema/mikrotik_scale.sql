-- ============================================================================
-- IPDR — tiered collection seam for scaling to 100+ MikroTiks.
--
-- Two collection roles per NAS:
--   'local'  — small NAS (150-200 users) logs syslog directly to THIS box;
--              its translations live in mikrotik_translations here.
--   'remote' — big NAS (1500+ users) has its OWN dedicated IPDR logger; this
--              box does NOT ingest its logs. At LEA query time, central fans
--              out to the logger's query endpoint and merges the answer.
--
-- Central (this box) queries local data + fans out to every 'remote' logger.
-- Idempotent.  Run: PGPASSWORD=... psql ... -f mikrotik_scale.sql
-- ============================================================================

ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS collection_role TEXT NOT NULL DEFAULT 'local';
-- 'local' | 'remote'
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS region TEXT;              -- optional grouping label
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS logger_url TEXT;          -- remote: https://host:port base
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS logger_token_enc TEXT;    -- remote: Fernet-encrypted API token
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS logger_last_ok TIMESTAMP; -- remote: last successful reach
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS logger_status TEXT;       -- remote: 'ok'|'unreachable'|'auth_error'

-- Constrain role to known values.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_collection_role') THEN
        ALTER TABLE nas_devices ADD CONSTRAINT chk_collection_role
            CHECK (collection_role IN ('local', 'remote'));
    END IF;
END $$;

-- Existing NAS default to 'local' (they log here) — correct for NAS-EXAMPLE.
CREATE INDEX IF NOT EXISTS idx_nas_role ON nas_devices (collection_role) WHERE enabled;

-- Per-NAS volume rollup: a materialized-ish view over today's partition +
-- recent activity, so operators can see which NAS are heavy (decide local vs
-- remote / Model-A vs Model-B). Cheap: counts by nas_id in a time window.
CREATE OR REPLACE VIEW nas_volume_stats AS
SELECT
    n.id                AS nas_id,
    n.name              AS nas_name,
    n.collection_role,
    n.region,
    COALESCE(v.rows_1h, 0)  AS rows_last_1h,
    COALESCE(v.rows_1h, 0) * 24  AS est_rows_per_day,
    v.last_log
FROM nas_devices n
LEFT JOIN (
    SELECT nas_id,
           COUNT(*) AS rows_1h,
           MAX(log_time) AS last_log
    FROM mikrotik_translations
    WHERE log_time > now() - interval '1 hour'
    GROUP BY nas_id
) v ON v.nas_id = n.id
WHERE n.enabled;
