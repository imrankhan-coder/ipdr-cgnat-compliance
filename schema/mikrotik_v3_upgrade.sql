-- v3.0 schema additions (ALTERs on nas_devices for version detection + bogon status)
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS routeros_version TEXT;
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS routeros_major   INT;
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS routeros_seen_at TIMESTAMP;
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS bogon_mitigation_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS bogon_configured BOOLEAN;
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS bogon_local_devices INT;
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS bogon_has_drop BOOLEAN;
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS bogon_has_accept BOOLEAN;
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS bogon_has_script BOOLEAN;
ALTER TABLE nas_devices ADD COLUMN IF NOT EXISTS bogon_checked_at TIMESTAMP;
