-- ============================================================================
-- IPDR — PPP session history, built by polling /ppp/active over time.
-- A session row is opened when a login first appears in a poll and closed when
-- it disappears. Gives real session_start/stop/duration/framed_ip/mac that
-- MikroTik firewall syslog cannot provide.
-- Run: PGPASSWORD=... psql ... -f mikrotik_ppp_sessions.sql   (idempotent)
-- ============================================================================

CREATE TABLE IF NOT EXISTS mikrotik_ppp_sessions (
    id            BIGSERIAL PRIMARY KEY,
    nas_id        INTEGER REFERENCES nas_devices(id) ON DELETE CASCADE,
    username      TEXT NOT NULL,
    framed_ip     INET,                       -- address on the PPP interface
    caller_id     TEXT,                       -- MAC / caller-id
    ppp_service   TEXT,                       -- pppoe / pptp / etc.
    router_session_id TEXT,                   -- RouterOS .id of the active entry
    session_start TIMESTAMP NOT NULL,         -- first poll it appeared (approx)
    session_stop  TIMESTAMP,                  -- poll it vanished (NULL = online)
    last_seen     TIMESTAMP NOT NULL,         -- most recent poll it was present
    uptime_seconds INTEGER,                   -- router-reported uptime at last poll
    bytes_in      BIGINT,
    bytes_out     BIGINT,
    CONSTRAINT uq_open_session UNIQUE (nas_id, username, session_start)
);

-- Timeline / username history: sessions for a subscriber, newest first.
CREATE INDEX IF NOT EXISTS idx_ppp_user_time
    ON mikrotik_ppp_sessions (username, session_start DESC);

-- "Who is online now" = open sessions (session_stop IS NULL).
CREATE INDEX IF NOT EXISTS idx_ppp_open
    ON mikrotik_ppp_sessions (nas_id, session_stop)
    WHERE session_stop IS NULL;

-- Retention scans by stop time.
CREATE INDEX IF NOT EXISTS idx_ppp_stop
    ON mikrotik_ppp_sessions (session_stop);

-- Records when polling began per NAS, so the UI can say "history since X".
CREATE TABLE IF NOT EXISTS mikrotik_ppp_poll_state (
    nas_id        INTEGER PRIMARY KEY REFERENCES nas_devices(id) ON DELETE CASCADE,
    polling_since TIMESTAMP NOT NULL DEFAULT now(),
    last_poll     TIMESTAMP
);
