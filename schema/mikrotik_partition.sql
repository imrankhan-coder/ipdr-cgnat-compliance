-- ============================================================================
-- IPDR — convert mikrotik_translations to a DAILY-PARTITIONED table.
-- "Start fresh": keep only the recent tail (last 6 hours), drop the rest,
-- reclaim all bloated disk by dropping the old table at the end.
--
-- Handles the nat_flow_logs VIEW dependency (drop inside txn, recreate against
-- the new table) and adds a DEFAULT partition so a clock-skewed row can never
-- break ingest. Cutover is a fast rename; the ingest daemon's INSERT just waits
-- for the brief lock — no data loss, no daemon change.
--
-- If anything fails before COMMIT, the live table is untouched (txn rolls back).
--   PGPASSWORD=... psql -h 127.0.0.1 -U ipdr -d ipdr -f mikrotik_partition.sql
-- ============================================================================

\set ON_ERROR_STOP on
\timing on
\set keep_interval '6 hours'

BEGIN;

-- 0. Release the view's dependency on the current table (recreated post-swap).
DROP VIEW IF EXISTS nat_flow_logs;

-- 1. New partitioned parent (same columns as mikrotik_translations).
CREATE TABLE mikrotik_translations_p (
    id            BIGSERIAL,
    nas_id        INTEGER,
    log_time      TIMESTAMP NOT NULL,
    collector_ts  TIMESTAMP,
    router_ip     INET,
    hostname      TEXT,
    iface         TEXT,
    username      TEXT,
    private_ip    INET NOT NULL,
    private_port  INTEGER NOT NULL,
    public_ip     INET NOT NULL,
    public_port   INTEGER NOT NULL,
    dest_ip       INET,
    dest_port     INTEGER,
    protocol      TEXT,
    tcp_flags     TEXT,
    conn_state    TEXT,
    raw_log       TEXT NOT NULL,
    PRIMARY KEY (id, log_time)
) PARTITION BY RANGE (log_time);

CREATE INDEX idx_mtp_lea      ON mikrotik_translations_p (public_ip, public_port, log_time);
CREATE INDEX idx_mtp_username ON mikrotik_translations_p (username, log_time);
CREATE INDEX idx_mtp_logtime  ON mikrotik_translations_p (log_time);
CREATE INDEX idx_mtp_nas      ON mikrotik_translations_p (nas_id);

-- 2. Daily partitions: yesterday .. +7 days, plus a DEFAULT catch-all.
DO $$
DECLARE
    d date := (now() - interval '1 day')::date;
    end_d date := (now() + interval '7 days')::date;
    pname text;
BEGIN
    WHILE d <= end_d LOOP
        pname := 'mikrotik_translations_p_' || to_char(d, 'YYYYMMDD');
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF mikrotik_translations_p '
            'FOR VALUES FROM (%L) TO (%L)',
            pname, d::timestamp, (d + 1)::timestamp);
        d := d + 1;
    END LOOP;
END $$;

CREATE TABLE mikrotik_translations_p_default
    PARTITION OF mikrotik_translations_p DEFAULT;

-- 3. Carry over the recent tail only (start fresh).
INSERT INTO mikrotik_translations_p
    (id, nas_id, log_time, collector_ts, router_ip, hostname, iface, username,
     private_ip, private_port, public_ip, public_port, dest_ip, dest_port,
     protocol, tcp_flags, conn_state, raw_log)
SELECT
     id, nas_id, log_time, collector_ts, router_ip, hostname, iface, username,
     private_ip, private_port, public_ip, public_port, dest_ip, dest_port,
     protocol, tcp_flags, conn_state, raw_log
FROM mikrotik_translations
WHERE log_time > now() - :'keep_interval'::interval;

SELECT setval(
    pg_get_serial_sequence('mikrotik_translations_p', 'id'),
    GREATEST((SELECT COALESCE(max(id), 1) FROM mikrotik_translations_p), 1));

-- 4. Cutover swap (fast metadata rename; ingest INSERT waits for the lock).
ALTER TABLE mikrotik_translations   RENAME TO mikrotik_translations_old;
ALTER TABLE mikrotik_translations_p RENAME TO mikrotik_translations;

-- 5. Recreate the analytics compatibility view against the NEW table.
CREATE VIEW nat_flow_logs AS
SELECT
    id, log_time,
    private_ip   AS source_ip,      private_port AS source_port,
    dest_ip      AS destination_ip, dest_port    AS destination_port,
    public_ip    AS translated_ip,  public_port  AS translated_port,
    protocol     AS protocol_name,  NULL::text   AS application,
    tcp_flags, username, nas_id, log_time AS created_at
FROM mikrotik_translations;

COMMIT;

-- 6. Fresh planner stats on the new table.
ANALYZE mikrotik_translations;

-- 7. Report, then reclaim disk by dropping the old table (no dependents now).
\echo '--- new table row count (recent tail) ---'
SELECT count(*) FROM mikrotik_translations;
\echo '--- partitions ---'
SELECT inhrelid::regclass AS partition
FROM pg_inherits WHERE inhparent = 'mikrotik_translations'::regclass ORDER BY 1;
\echo '--- old table size before drop ---'
SELECT pg_size_pretty(pg_total_relation_size('mikrotik_translations_old')) AS old_size;

DROP TABLE mikrotik_translations_old;

\echo '--- done: partitioned, disk reclaimed ---'
SELECT pg_size_pretty(pg_total_relation_size('mikrotik_translations')) AS new_size;
