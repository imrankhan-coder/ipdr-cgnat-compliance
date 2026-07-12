-- ============================================================================
-- IPDR MikroTik — cached /ppp/secret data for LEA enrichment
-- Synced periodically from each MikroTik NAS via the read-only API user.
-- Run: PGPASSWORD=... psql ... -f mikrotik_secrets.sql   (idempotent)
-- ============================================================================

CREATE TABLE IF NOT EXISTS mikrotik_secrets (
    id           BIGSERIAL PRIMARY KEY,
    nas_id       INTEGER REFERENCES nas_devices(id) ON DELETE CASCADE,
    username     TEXT NOT NULL,          -- ppp secret 'name' (== log username)
    comment      TEXT,                   -- free-text: name/address/date/phone
    phone        TEXT,                   -- extracted 03xx-xxxxxxx if present
    caller_id    TEXT,                   -- bound MAC (if secret pins one)
    last_caller_id TEXT,                 -- last MAC seen
    profile      TEXT,
    service      TEXT,
    disabled     BOOLEAN DEFAULT false,
    last_logged_out TEXT,               -- router-reported, kept as text
    synced_at    TIMESTAMP DEFAULT now(),
    CONSTRAINT uq_secret UNIQUE (nas_id, username)
);

-- LEA enrichment lookup: (nas_id, username) -> identity. Also a username-only
-- index for cross-NAS fallback.
CREATE INDEX IF NOT EXISTS idx_secrets_nas_user ON mikrotik_secrets (nas_id, username);
CREATE INDEX IF NOT EXISTS idx_secrets_user     ON mikrotik_secrets (username);
