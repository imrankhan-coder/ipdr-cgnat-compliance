-- DHCP lease tracking for MikroTik NAS.
-- Identity anchor is the MAC (IP changes over time in DHCP); device name/
-- hostname is the human label. IP history is the forensic record so a past
-- DHCP IP resolves to the MAC that held it at that time.

-- Current lease state: one row per (nas_id, mac).
CREATE TABLE IF NOT EXISTS mikrotik_dhcp_leases (
    nas_id      integer NOT NULL REFERENCES nas_devices(id) ON DELETE CASCADE,
    mac         text    NOT NULL,
    ip          inet,
    hostname    text,               -- Active Host-Name / host-name
    comment     text,               -- lease comment (often the customer/device name)
    server      text,               -- which dhcp-server
    is_static   boolean NOT NULL DEFAULT false,  -- Make Static (dynamic=false)
    status      text,               -- bound / waiting / etc.
    first_seen  timestamp without time zone NOT NULL,
    last_seen   timestamp without time zone NOT NULL,
    active      boolean NOT NULL DEFAULT true,    -- seen in the most recent poll
    PRIMARY KEY (nas_id, mac)
);
CREATE INDEX IF NOT EXISTS idx_dhcp_nas_active ON mikrotik_dhcp_leases (nas_id, active);
CREATE INDEX IF NOT EXISTS idx_dhcp_ip     ON mikrotik_dhcp_leases (ip);
CREATE INDEX IF NOT EXISTS idx_dhcp_static ON mikrotik_dhcp_leases (nas_id, is_static);

-- IP-over-time history: MAC held IP from seen_from to seen_to (NULL = current).
-- Lets an LEA query for a DHCP IP at time T find the MAC that held it then.
CREATE TABLE IF NOT EXISTS mikrotik_dhcp_ip_history (
    id          bigserial PRIMARY KEY,
    nas_id      integer NOT NULL REFERENCES nas_devices(id) ON DELETE CASCADE,
    mac         text    NOT NULL,
    ip          inet    NOT NULL,
    seen_from   timestamp without time zone NOT NULL,
    seen_to     timestamp without time zone          -- NULL = still current
);
CREATE INDEX IF NOT EXISTS idx_dhcphist_ip_time ON mikrotik_dhcp_ip_history (ip, seen_from);
CREATE INDEX IF NOT EXISTS idx_dhcphist_open    ON mikrotik_dhcp_ip_history (nas_id, mac, seen_to) WHERE seen_to IS NULL;

-- Poll state (mirrors mikrotik_ppp_poll_state).
CREATE TABLE IF NOT EXISTS mikrotik_dhcp_poll_state (
    nas_id        integer PRIMARY KEY REFERENCES nas_devices(id) ON DELETE CASCADE,
    last_poll     timestamp without time zone,
    polling_since timestamp without time zone DEFAULT now()
);
