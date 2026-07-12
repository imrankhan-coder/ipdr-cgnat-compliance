-- ============================================================================
-- IPDR — autovacuum tuning for high-write mikrotik_translations partitions.
-- Default autovacuum waits for 20% of rows to change before acting; on daily
-- partitions of ~2.4M rows that means stale stats and drifting plans (the
-- "gets slow over time" symptom). We make autovacuum act on fixed thresholds.
--
-- NOTE: Postgres does NOT allow storage params on a partitioned PARENT
-- ("cannot specify storage parameters for a partitioned table"), and new
-- partitions do NOT inherit them — so params go on each LEAF partition. The
-- daily maintenance script sets them on partitions it creates going forward;
-- this script covers all EXISTING partitions.
-- ============================================================================

DO $$
DECLARE r record;
BEGIN
    FOR r IN
        SELECT c.relname
        FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = 'mikrotik_translations'::regclass
    LOOP
        EXECUTE format(
            'ALTER TABLE %I SET ('
            'autovacuum_vacuum_scale_factor=0.0, autovacuum_vacuum_threshold=50000, '
            'autovacuum_analyze_scale_factor=0.0, autovacuum_analyze_threshold=20000, '
            'autovacuum_vacuum_cost_delay=2)', r.relname);
        RAISE NOTICE 'tuned %', r.relname;
    END LOOP;
END $$;

-- Refresh stats now so plans are good immediately.
ANALYZE mikrotik_translations;
