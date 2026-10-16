-- When below capacity, the old subquery scanned every audit ID looking for
-- a row satisfying a false constant condition. Probe only the oldest ID.
DROP TRIGGER audit_retention_insert;
CREATE TRIGGER audit_retention_insert AFTER INSERT ON audit_events BEGIN
 UPDATE audit_retention SET retained_rows=retained_rows+1 WHERE id=1;
 UPDATE audit_retention SET last_reason='row_budget' WHERE id=1 AND retained_rows>max_rows;
 DELETE FROM audit_events WHERE id=(SELECT id FROM audit_events ORDER BY id LIMIT 1)
 AND (SELECT retained_rows>max_rows FROM audit_retention WHERE id=1);
END;
