-- ============================================================================
-- IPDR — CDN / app classification via router address-lists.
-- Synced from /ip/firewall/address-list on each MikroTik NAS. Each entry maps
-- an IP or CIDR prefix to an app label (the address-list NAME is the label,
-- e.g. list 'Netflix' -> app 'Netflix'). Analytics classifies a connection's
-- dest_ip by subnet-containment against these prefixes.
-- Run: PGPASSWORD=... psql ... -f mikrotik_cdn.sql   (idempotent)
-- ============================================================================

CREATE TABLE IF NOT EXISTS mikrotik_cdn_prefixes (
    id         BIGSERIAL PRIMARY KEY,
    nas_id     INTEGER REFERENCES nas_devices(id) ON DELETE CASCADE,
    app        TEXT NOT NULL,          -- address-list name = app label
    prefix     CIDR NOT NULL,          -- single IP stored as /32
    comment    TEXT,
    synced_at  TIMESTAMP DEFAULT now(),
    CONSTRAINT uq_cdn UNIQUE (nas_id, app, prefix)
);

-- GiST index enables fast containment lookups: prefix >>= dest_ip.
CREATE INDEX IF NOT EXISTS idx_cdn_prefix_gist
    ON mikrotik_cdn_prefixes USING gist (prefix inet_ops);

CREATE INDEX IF NOT EXISTS idx_cdn_app ON mikrotik_cdn_prefixes (app);

-- Optional label normalization: map raw address-list names to display names.
-- If a list name is already clean (e.g. 'Netflix'), no row needed here.
CREATE TABLE IF NOT EXISTS mikrotik_cdn_labels (
    list_name   TEXT PRIMARY KEY,      -- e.g. 'oca-list'
    app_label   TEXT NOT NULL          -- e.g. 'Netflix'
);

-- Seed common MikroTik conventions (safe if unused).
INSERT INTO mikrotik_cdn_labels (list_name, app_label) VALUES
    ('oca-list', 'Netflix'),
    ('tt-list', 'TikTok'),
    ('yt-list', 'YouTube'),
    ('fb-list', 'Facebook'),
    ('google-list', 'Google'),
    ('akamai-list', 'Akamai'),
    ('cloudflare-list', 'Cloudflare')
ON CONFLICT (list_name) DO NOTHING;
