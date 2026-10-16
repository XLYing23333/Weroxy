ALTER TABLE weroxy_devices ADD COLUMN client_key TEXT NOT NULL DEFAULT '';
ALTER TABLE legacy_devices ADD COLUMN client_key TEXT NOT NULL DEFAULT '';
