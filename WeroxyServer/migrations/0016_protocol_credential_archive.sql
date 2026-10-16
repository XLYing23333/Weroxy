-- Preserve an original Legacy Client Key while the device uses Weroxy v1.
-- client_key is already sealed with device-seal.key and bound to device_name.
CREATE TABLE protocol_credential_archive (
    device_name TEXT PRIMARY KEY,
    legacy_client_key TEXT NOT NULL,
    created_at TEXT NOT NULL
);
