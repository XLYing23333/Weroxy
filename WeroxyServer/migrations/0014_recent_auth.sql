ALTER TABLE admin_sessions ADD COLUMN reauthenticated_at TEXT;
UPDATE admin_sessions SET reauthenticated_at = created_at WHERE reauthenticated_at IS NULL;
