ALTER TABLE ui_settings ADD COLUMN forward_mode TEXT NOT NULL DEFAULT 'shared';
ALTER TABLE ui_settings ADD COLUMN forward_min INTEGER NOT NULL DEFAULT 1;
ALTER TABLE ui_settings ADD COLUMN forward_preferred INTEGER NOT NULL DEFAULT 1;
ALTER TABLE ui_settings ADD COLUMN forward_max INTEGER NOT NULL DEFAULT 4;
ALTER TABLE ui_settings ADD COLUMN ban_action TEXT NOT NULL DEFAULT 'none';
ALTER TABLE ui_settings ADD COLUMN ban_cidr TEXT NOT NULL DEFAULT '';

UPDATE access_policies
SET max_active = COALESCE(max_active, 32),
    max_pending = COALESCE(max_pending, 8),
    max_per_ip = COALESCE(max_per_ip, 4),
    rate_per_sec = COALESCE(rate_per_sec, 10),
    burst = COALESCE(burst, 20),
    bandwidth = COALESCE(bandwidth, 104857600)
WHERE scope = 'global' AND scope_key = '';
