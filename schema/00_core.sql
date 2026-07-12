-- ============================================================================
-- IPDR — PostgreSQL Schema
-- Example ISP — CGNAT IPDR & LEA Compliance
-- ============================================================================

-- Drop existing tables if re-initializing
DROP TABLE IF EXISTS nat_flow_logs CASCADE;
DROP TABLE IF EXISTS nat_logs CASCADE;
DROP TABLE IF EXISTS radius_accounting CASCADE;
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS system_config CASCADE;

-- ============================================================================
-- Users (portal access)
-- ============================================================================
CREATE TABLE users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(64) UNIQUE NOT NULL,
    password_hash   VARCHAR(256) NOT NULL,
    full_name       VARCHAR(128) NOT NULL,
    role            VARCHAR(20) NOT NULL DEFAULT 'operator'
                    CHECK (role IN ('admin', 'lea', 'operator', 'readonly')),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_login      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Default admin user  —  username: admin   password: changeme
-- !!  CHANGE THIS IMMEDIATELY on first login  !!
-- Either log in and change it under Settings -> Users, or run:
--     IPDR_ENV=/opt/ipdr/.env python3 scripts/init_admin.py
-- ============================================================================
INSERT INTO users (username, password_hash, full_name, role)
VALUES (
    'admin',
    -- werkzeug hash of the placeholder password 'changeme' (CHANGE ON FIRST LOGIN)
    'scrypt:32768:8:1$oFDMtUyf1gfXohoY$46bf4e54e2c55a1b0edc453ccc516d52907a05c18cd2aa41bffcc97aa35cf7d6eef47ec75ba0b15fc2bea0bd083e5afdb3eccf6123ea9bcb876bb9b8ece91344',
    'System Administrator',
    'admin'
);

-- ============================================================================
-- NAT PBA Logs (Port Block Allocation / Release / Interim)
-- These are the compliance-critical records
-- ============================================================================
CREATE TABLE nat_logs (
    id              BIGSERIAL PRIMARY KEY,
    log_time        TIMESTAMPTZ NOT NULL,
    log_type        VARCHAR(20) NOT NULL
                    CHECK (log_type IN ('PBA_ALLOC', 'PBA_RELEASE', 'PBA_INTERIM', 'RULE_MATCH')),
    subscriber_ip   INET NOT NULL,
    public_ip       INET NOT NULL,
    port_block_start INTEGER,
    port_block_end  INTEGER,
    blocks_used     INTEGER,
    blocks_max      INTEGER,
    nat_pool        VARCHAR(64),
    epoch           VARCHAR(32),
    release_time    TIMESTAMPTZ,
    raw_log         TEXT,
    nas_hostname    VARCHAR(64),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for fast LEA queries
CREATE INDEX idx_nat_public_ip_time ON nat_logs (public_ip, log_time);
CREATE INDEX idx_nat_subscriber_ip ON nat_logs (subscriber_ip, log_time);
CREATE INDEX idx_nat_port_range ON nat_logs (public_ip, port_block_start, port_block_end);
CREATE INDEX idx_nat_log_type ON nat_logs (log_type, log_time);
CREATE INDEX idx_nat_log_time ON nat_logs (log_time);

-- ============================================================================
-- NAT Per-Flow Logs (RT_NAT_RULE_MATCH — optional granular records)
-- ============================================================================
CREATE TABLE nat_flow_logs (
    id              BIGSERIAL PRIMARY KEY,
    log_time        TIMESTAMPTZ NOT NULL,
    protocol        VARCHAR(10),
    protocol_name   VARCHAR(20),
    application     VARCHAR(64),
    source_ip       INET NOT NULL,
    source_port     INTEGER,
    destination_ip  INET NOT NULL,
    destination_port INTEGER,
    public_ip       INET,
    translated_port INTEGER,
    rule_set        VARCHAR(64),
    rule_name       VARCHAR(64),
    interface_name  VARCHAR(64),
    raw_log         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_flow_public_ip ON nat_flow_logs (public_ip, log_time);
CREATE INDEX idx_flow_source_ip ON nat_flow_logs (source_ip, log_time);
CREATE INDEX idx_flow_time ON nat_flow_logs (log_time);

-- ============================================================================
-- RADIUS Accounting (subscriber sessions — from FreeRADIUS)
-- ============================================================================
CREATE TABLE radius_accounting (
    id                  BIGSERIAL PRIMARY KEY,
    acct_session_id     VARCHAR(64),
    acct_status         VARCHAR(20) NOT NULL,
    username            VARCHAR(128) NOT NULL,
    framed_ip           INET,
    framed_ipv6_prefix  VARCHAR(64),
    calling_station_id  VARCHAR(64),     -- MAC address
    called_station_id   VARCHAR(64),
    nas_ip_address      INET,
    nas_port            INTEGER,
    nas_port_id         VARCHAR(64),     -- VLAN / interface
    nas_port_type       VARCHAR(32),
    service_type        VARCHAR(32),
    session_start       TIMESTAMPTZ NOT NULL,
    session_stop        TIMESTAMPTZ,
    session_duration    INTEGER,         -- seconds
    input_octets        BIGINT DEFAULT 0,
    output_octets       BIGINT DEFAULT 0,
    terminate_cause     VARCHAR(64),
    delegated_ipv6      VARCHAR(64),
    raw_record          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_radius_username ON radius_accounting (username, session_start);
CREATE INDEX idx_radius_framed_ip ON radius_accounting (framed_ip, session_start);
CREATE INDEX idx_radius_session_time ON radius_accounting (session_start, session_stop);
CREATE INDEX idx_radius_acct_session ON radius_accounting (acct_session_id);
CREATE INDEX idx_radius_mac ON radius_accounting (calling_station_id);

-- ============================================================================
-- Audit Log (every query, login, admin action)
-- ============================================================================
CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    user_id         INTEGER,
    username        VARCHAR(64),
    action          VARCHAR(32) NOT NULL,
    detail          TEXT,
    target_user     VARCHAR(64),
    ip_address      INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_action ON audit_log (action, created_at);
CREATE INDEX idx_audit_user ON audit_log (username, created_at);
CREATE INDEX idx_audit_time ON audit_log (created_at);

-- ============================================================================
-- System Configuration
-- ============================================================================
CREATE TABLE system_config (
    key             VARCHAR(64) PRIMARY KEY,
    value           TEXT NOT NULL,
    description     TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO system_config (key, value, description) VALUES
    ('retention_months', '13', 'Minimum data retention period in months (local regulation may require a minimum)'),
    ('auto_purge_enabled', 'false', 'Automatically purge data older than retention period'),
    ('nas_hostname', 'SITE-B-BNG-01', 'Expected NAS hostname in syslog'),
    ('nat_pool_name', 'EXAMPLE_POOL', 'NAT pool name for reference'),
    ('nat_pool_range', '203.0.113.0/25', 'NAT public IP pool range'),
    ('cgn_subnet', '100.64.0.0/18', 'CGN subscriber address space'),
    ('syslog_listen_port', '514', 'Port for NAT syslog ingestion (rsyslog forwards here)'),
    ('company_name', 'Example ISP', 'Company name for reports'),
    ('company_as', 'AS64500', 'BGP AS number');

-- ============================================================================
-- Partitioning hint: For production, consider partitioning nat_logs and
-- radius_accounting by month for efficient purging:
--   CREATE TABLE nat_logs (...) PARTITION BY RANGE (log_time);
--   CREATE TABLE nat_logs_2026_06 PARTITION OF nat_logs
--     FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
-- ============================================================================

-- ============================================================================
-- Helper view: Combined LEA lookup
-- ============================================================================
CREATE OR REPLACE VIEW v_lea_combined AS
SELECT
    nl.id as nat_log_id,
    nl.log_time as nat_time,
    nl.log_type,
    nl.subscriber_ip,
    nl.public_ip,
    nl.port_block_start,
    nl.port_block_end,
    nl.release_time,
    ra.username,
    ra.calling_station_id as mac_address,
    ra.nas_port_id as vlan,
    ra.session_start,
    ra.session_stop,
    ra.framed_ipv6_prefix
FROM nat_logs nl
LEFT JOIN radius_accounting ra
    ON ra.framed_ip = nl.subscriber_ip
    AND ra.session_start <= nl.log_time
    AND (ra.session_stop IS NULL OR ra.session_stop >= nl.log_time)
WHERE nl.log_type IN ('PBA_ALLOC', 'PBA_RELEASE', 'PBA_INTERIM');
