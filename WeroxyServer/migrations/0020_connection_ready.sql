ALTER TABLE connection_details ADD COLUMN ready_at TEXT;
ALTER TABLE connection_details ADD COLUMN setup_ms INTEGER CHECK (setup_ms >= 0);
