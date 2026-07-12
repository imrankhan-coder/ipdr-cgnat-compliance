-- Add src_mac to mikrotik_translations for DHCP/routed client identity.
-- Nullable: PPPoE rows have no MAC; DHCP/routed rows carry the client MAC.
-- The parent partitioned table + new partitions inherit this automatically.
ALTER TABLE mikrotik_translations ADD COLUMN IF NOT EXISTS src_mac TEXT;

-- Index for LEA lookups by MAC (partial: only rows that have a MAC).
CREATE INDEX IF NOT EXISTS idx_mtp_srcmac ON mikrotik_translations (src_mac)
    WHERE src_mac IS NOT NULL;
