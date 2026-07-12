-- ============================================================================
-- IPDR MikroTik — LEA support: normalized PPPoE username
-- Additive + idempotent. Run:
--   PGPASSWORD=... psql -h 127.0.0.1 -U ipdr -d ipdr -f mikrotik_lea_username.sql
-- ============================================================================

-- The stable subscriber key across the whole fleet is the PPPoE username
-- itself (b169, G0620), NOT the interface form (pppoe-b169). We derive it once
-- at ingest so LEA queries and enrichment key on an indexed column instead of
-- re-parsing iface on every read.
ALTER TABLE mikrotik_translations
  ADD COLUMN IF NOT EXISTS username TEXT;

-- Backfill existing rows: strip a leading 'pppoe-' (and any '<...>' wrapper the
-- parser may have left). Rows whose iface isn't pppoe-form keep iface as-is.
UPDATE mikrotik_translations
SET username = regexp_replace(iface, '^<?pppoe-([^>]+)>?$', '\1')
WHERE username IS NULL AND iface IS NOT NULL;

-- Index for username-centric LEA / reporting ("all activity for b169").
CREATE INDEX IF NOT EXISTS idx_mt_username_time
  ON mikrotik_translations (username, log_time);
