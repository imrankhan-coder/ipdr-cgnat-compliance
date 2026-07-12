-- ============================================================================
-- IPDR MikroTik Edition — schema
-- DB: ipdr  (already on the clone; these are additive to the shell)
-- Run:  PGPASSWORD=... psql -h 127.0.0.1 -U ipdr -d ipdr -f mikrotik_schema.sql
-- Fully idempotent — safe to re-run.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- nas_devices — MikroTik columns (additive; leaves existing cols alone).
-- NOTE: the table already has `source_ip` (varchar) and `nas_type` (vendor);
-- we reuse those. We only add MikroTik-specific fields not already present.
-- ---------------------------------------------------------------------------
ALTER TABLE nas_devices
  ADD COLUMN IF NOT EXISTS syslog_port      INTEGER DEFAULT 514,
  ADD COLUMN IF NOT EXISTS model            TEXT,          -- syslog | deterministic | both
  ADD COLUMN IF NOT EXISTS api_enabled      BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS api_host         VARCHAR(45),
  ADD COLUMN IF NOT EXISTS api_port         INTEGER,
  ADD COLUMN IF NOT EXISTS api_ssl          BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS api_user         VARCHAR(64),
  ADD COLUMN IF NOT EXISTS api_password_enc TEXT;

-- Fast source-IP -> nas_id attribution for the ingest daemon.
CREATE INDEX IF NOT EXISTS idx_nas_source_ip ON nas_devices (source_ip);

-- ---------------------------------------------------------------------------
-- Model B — per-connection syslog translations
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mikrotik_translations (
    id            BIGSERIAL PRIMARY KEY,
    nas_id        INTEGER REFERENCES nas_devices(id) ON DELETE SET NULL,
    log_time      TIMESTAMP NOT NULL,          -- router event time (authoritative for LEA)
    collector_ts  TIMESTAMP,                   -- when this box received it
    router_ip     INET,
    hostname      TEXT,
    iface         TEXT,                         -- pppoe-XXX  == subscriber identity
    private_ip    INET NOT NULL,
    private_port  INTEGER NOT NULL,
    public_ip     INET NOT NULL,
    public_port   INTEGER NOT NULL,
    dest_ip       INET,
    dest_port     INTEGER,
    protocol      TEXT,
    tcp_flags     TEXT,
    conn_state    TEXT,
    raw_log       TEXT NOT NULL                 -- verbatim, forensic fidelity
);

-- The one LEA question this table must answer fast:
--   "who held public_ip:public_port at time T?"
-- Composite index ordered public_ip, public_port, log_time = index-only range scan.
CREATE INDEX IF NOT EXISTS idx_mt_lea
    ON mikrotik_translations (public_ip, public_port, log_time);

-- Secondary: subscriber-centric queries ("all activity for pppoe-b162").
CREATE INDEX IF NOT EXISTS idx_mt_iface_time
    ON mikrotik_translations (iface, log_time);

-- Purge / retention scans by time (storage guard).
CREATE INDEX IF NOT EXISTS idx_mt_logtime
    ON mikrotik_translations (log_time);

-- Per-NAS filtering in the browse UI.
CREATE INDEX IF NOT EXISTS idx_mt_nas
    ON mikrotik_translations (nas_id);


-- ---------------------------------------------------------------------------
-- Model A — deterministic NAT rules (static port ranges, NO per-conn logs)
-- LEA answer is pure math: find the rule whose [port_start,port_end] contains
-- the queried port on the queried public_ip.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mikrotik_det_rules (
    id            BIGSERIAL PRIMARY KEY,
    nas_id        INTEGER REFERENCES nas_devices(id) ON DELETE CASCADE,
    private_ip    INET NOT NULL,
    public_ip     INET NOT NULL,
    port_start    INTEGER NOT NULL,
    port_end      INTEGER NOT NULL,
    protocol      TEXT DEFAULT 'any',           -- tcp / udp / any
    imported_at   TIMESTAMP DEFAULT now(),
    CONSTRAINT det_port_range CHECK (port_start <= port_end)
);

-- LEA lookup: public_ip = X AND port_start <= P AND port_end >= P.
-- Index on (public_ip, port_start) narrows to the public IP then range-scans.
CREATE INDEX IF NOT EXISTS idx_det_lea
    ON mikrotik_det_rules (public_ip, port_start, port_end);

CREATE INDEX IF NOT EXISTS idx_det_nas
    ON mikrotik_det_rules (nas_id);

-- Guard against overlapping duplicate imports of the same mapping.
CREATE UNIQUE INDEX IF NOT EXISTS uq_det_rule
    ON mikrotik_det_rules (nas_id, private_ip, public_ip, port_start, port_end, protocol);


-- ---------------------------------------------------------------------------
-- Identity enrichment — static IP / iface -> customer map (optional, per client)
-- LEA correlation order: RADIUS (if present) -> static_subscribers -> raw iface.
-- Keyed on EITHER private_ip OR iface depending on how the client identifies subs.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS static_subscribers (
    id            BIGSERIAL PRIMARY KEY,
    nas_id        INTEGER REFERENCES nas_devices(id) ON DELETE CASCADE,
    private_ip    INET,                          -- static-IP clients
    iface         TEXT,                          -- pppoe-XXX clients
    customer_name TEXT,
    address       TEXT,
    cnic          TEXT,
    updated_at    TIMESTAMP DEFAULT now(),
    CONSTRAINT sub_has_key CHECK (private_ip IS NOT NULL OR iface IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_sub_privip ON static_subscribers (nas_id, private_ip);
CREATE INDEX IF NOT EXISTS idx_sub_iface  ON static_subscribers (nas_id, iface);
