-- Audit retention is independent of diagnostic log rotation.
CREATE TABLE audit_retention (
 id INTEGER PRIMARY KEY CHECK (id = 1),
 retained_rows INTEGER NOT NULL CHECK (retained_rows >= 0),
 max_rows INTEGER NOT NULL DEFAULT 100000 CHECK (max_rows = 100000),
 retain_days INTEGER NOT NULL DEFAULT 180 CHECK (retain_days = 180),
 removed_rows INTEGER NOT NULL DEFAULT 0 CHECK (removed_rows >= 0),
 last_trim TEXT NOT NULL DEFAULT '',
 last_reason TEXT NOT NULL DEFAULT '',
 last_run TEXT NOT NULL DEFAULT '',
 failure_reason TEXT NOT NULL DEFAULT ''
);
INSERT INTO audit_retention(id,retained_rows) SELECT 1,COUNT(*) FROM audit_events;
CREATE INDEX audit_events_created_at ON audit_events(created_at);
CREATE TRIGGER audit_retention_delete AFTER DELETE ON audit_events BEGIN
 UPDATE audit_retention SET retained_rows=retained_rows-1, removed_rows=removed_rows+1,
 last_trim=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=1;
END;
UPDATE audit_retention SET last_reason='migration_capacity' WHERE retained_rows>max_rows;
DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT -1 OFFSET 100000);
CREATE TRIGGER audit_retention_insert AFTER INSERT ON audit_events BEGIN
 UPDATE audit_retention SET retained_rows=retained_rows+1 WHERE id=1;
 UPDATE audit_retention SET last_reason='row_budget' WHERE id=1 AND retained_rows>max_rows;
 DELETE FROM audit_events WHERE id=(SELECT id FROM audit_events
 WHERE (SELECT retained_rows>max_rows FROM audit_retention WHERE id=1) ORDER BY id LIMIT 1);
END;
