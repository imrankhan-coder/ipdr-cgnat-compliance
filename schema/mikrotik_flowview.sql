-- ============================================================================
-- IPDR MikroTik — analytics compatibility view
-- The analytics route queries nat_flow_logs with columns:
--   log_time, source_ip, destination_ip, destination_port, protocol_name,
--   application, source_port
-- mikrotik_translations has the same data under different names. We expose a
-- VIEW so the analytics route (and any other flow-log reader) works unchanged
-- on this box WITHOUT touching Python.
--
-- Strategy: the real nat_flow_logs table is empty on this box. We rename it out
-- of the way and create a view in its place. Idempotent-ish (guarded).
--
-- Run: PGPASSWORD=... psql -h 127.0.0.1 -U ipdr -d ipdr -f mikrotik_flowview.sql
-- ============================================================================

DO $$
BEGIN
    -- Only do the swap if nat_flow_logs is still a (empty) TABLE, not already a view.
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'nat_flow_logs' AND table_type = 'BASE TABLE'
    ) THEN
        -- Safety: refuse if the table somehow has rows (don't clobber real data).
        IF (SELECT COUNT(*) FROM nat_flow_logs) = 0 THEN
            ALTER TABLE nat_flow_logs RENAME TO nat_flow_logs_juniper_unused;
            RAISE NOTICE 'renamed empty nat_flow_logs -> nat_flow_logs_juniper_unused';
        ELSE
            RAISE EXCEPTION 'nat_flow_logs has rows; aborting to avoid data loss';
        END IF;
    END IF;
END $$;

-- Create/replace the view presenting MikroTik translations under flow-log names.
CREATE OR REPLACE VIEW nat_flow_logs AS
SELECT
    id,
    log_time,
    private_ip        AS source_ip,
    private_port      AS source_port,
    dest_ip           AS destination_ip,
    dest_port         AS destination_port,
    public_ip         AS translated_ip,
    public_port       AS translated_port,
    protocol          AS protocol_name,
    NULL::text        AS application,
    tcp_flags,
    username,
    nas_id,
    log_time          AS created_at
FROM mikrotik_translations;

-- Note: TABLESAMPLE in the analytics route only works on real tables, not views.
-- On a view, Postgres will error on `TABLESAMPLE`. The analytics route uses it
-- for long ranges (12h+). If that errors, we switch those to plain scans in the
-- route (small follow-up patch) — flagged, not blocking short-range analytics.
