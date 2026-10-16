-- Preserve existing IDs, but prevent reuse after age retention empties the table.
DROP TRIGGER audit_retention_insert;
DROP TRIGGER audit_retention_delete;
ALTER TABLE audit_events RENAME TO audit_events_previous;
CREATE TABLE audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 action TEXT NOT NULL,
 outcome TEXT NOT NULL,
 detail TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
INSERT INTO audit_events(id,action,outcome,detail,created_at)
 SELECT id,action,outcome,detail,created_at FROM audit_events_previous ORDER BY id;
DROP TABLE audit_events_previous;
CREATE INDEX audit_events_created_at ON audit_events(created_at);
CREATE TRIGGER audit_retention_delete AFTER DELETE ON audit_events BEGIN
 UPDATE audit_retention SET retained_rows=retained_rows-1, removed_rows=removed_rows+1,
 last_trim=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=1;
END;
CREATE TRIGGER audit_retention_insert AFTER INSERT ON audit_events BEGIN
 UPDATE audit_retention SET retained_rows=retained_rows+1 WHERE id=1;
 UPDATE audit_retention SET last_reason='row_budget' WHERE id=1 AND retained_rows>max_rows;
 DELETE FROM audit_events WHERE id=(SELECT id FROM audit_events
 WHERE (SELECT retained_rows>max_rows FROM audit_retention WHERE id=1) ORDER BY id LIMIT 1);
END;
