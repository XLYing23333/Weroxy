-- Row budgets supplement age retention. Lifetime totals are never evicted.
CREATE TABLE metric_row_budgets (
 table_name TEXT PRIMARY KEY,
 retained_rows INTEGER NOT NULL CHECK (retained_rows >= 0),
 max_rows INTEGER NOT NULL CHECK (max_rows > 0)
);
DELETE FROM metric_samples WHERE rowid IN (SELECT rowid FROM metric_samples ORDER BY sampled_at DESC, rowid DESC LIMIT -1 OFFSET 86400);
DELETE FROM metric_batches WHERE rowid IN (SELECT rowid FROM metric_batches ORDER BY written_at DESC, rowid DESC LIMIT -1 OFFSET 172800);
DELETE FROM metric_minutes WHERE rowid IN (SELECT rowid FROM metric_minutes ORDER BY bucket_at DESC, rowid DESC LIMIT -1 OFFSET 1440);
DELETE FROM metric_five_minutes WHERE rowid IN (SELECT rowid FROM metric_five_minutes ORDER BY bucket_at DESC, rowid DESC LIMIT -1 OFFSET 2016);
DELETE FROM metric_hours WHERE rowid IN (SELECT rowid FROM metric_hours ORDER BY bucket_at DESC, rowid DESC LIMIT -1 OFFSET 2160);
INSERT INTO metric_row_budgets SELECT 'metric_samples', COUNT(*), 86400 FROM metric_samples;
CREATE TRIGGER metric_samples_budget_insert AFTER INSERT ON metric_samples BEGIN
 UPDATE metric_row_budgets SET retained_rows = retained_rows + 1 WHERE table_name = 'metric_samples';
 DELETE FROM metric_samples WHERE rowid = (
  SELECT rowid FROM metric_samples WHERE (SELECT retained_rows > max_rows FROM metric_row_budgets WHERE table_name = 'metric_samples')
  ORDER BY sampled_at, rowid LIMIT 1
 );
END;
CREATE TRIGGER metric_samples_budget_delete AFTER DELETE ON metric_samples BEGIN
 UPDATE metric_row_budgets SET retained_rows = retained_rows - 1 WHERE table_name = 'metric_samples';
END;
INSERT INTO metric_row_budgets SELECT 'metric_batches', COUNT(*), 172800 FROM metric_batches;
CREATE TRIGGER metric_batches_budget_insert AFTER INSERT ON metric_batches BEGIN
 UPDATE metric_row_budgets SET retained_rows = retained_rows + 1 WHERE table_name = 'metric_batches';
 DELETE FROM metric_batches WHERE rowid = (
  SELECT rowid FROM metric_batches WHERE (SELECT retained_rows > max_rows FROM metric_row_budgets WHERE table_name = 'metric_batches')
  ORDER BY written_at, rowid LIMIT 1
 );
END;
CREATE TRIGGER metric_batches_budget_delete AFTER DELETE ON metric_batches BEGIN
 UPDATE metric_row_budgets SET retained_rows = retained_rows - 1 WHERE table_name = 'metric_batches';
END;
INSERT INTO metric_row_budgets SELECT 'metric_minutes', COUNT(*), 1440 FROM metric_minutes;
CREATE TRIGGER metric_minutes_budget_insert AFTER INSERT ON metric_minutes BEGIN
 UPDATE metric_row_budgets SET retained_rows = retained_rows + 1 WHERE table_name = 'metric_minutes';
 DELETE FROM metric_minutes WHERE rowid = (
  SELECT rowid FROM metric_minutes WHERE (SELECT retained_rows > max_rows FROM metric_row_budgets WHERE table_name = 'metric_minutes')
  ORDER BY bucket_at, rowid LIMIT 1
 );
END;
CREATE TRIGGER metric_minutes_budget_delete AFTER DELETE ON metric_minutes BEGIN
 UPDATE metric_row_budgets SET retained_rows = retained_rows - 1 WHERE table_name = 'metric_minutes';
END;
INSERT INTO metric_row_budgets SELECT 'metric_five_minutes', COUNT(*), 2016 FROM metric_five_minutes;
CREATE TRIGGER metric_five_minutes_budget_insert AFTER INSERT ON metric_five_minutes BEGIN
 UPDATE metric_row_budgets SET retained_rows = retained_rows + 1 WHERE table_name = 'metric_five_minutes';
 DELETE FROM metric_five_minutes WHERE rowid = (
  SELECT rowid FROM metric_five_minutes WHERE (SELECT retained_rows > max_rows FROM metric_row_budgets WHERE table_name = 'metric_five_minutes')
  ORDER BY bucket_at, rowid LIMIT 1
 );
END;
CREATE TRIGGER metric_five_minutes_budget_delete AFTER DELETE ON metric_five_minutes BEGIN
 UPDATE metric_row_budgets SET retained_rows = retained_rows - 1 WHERE table_name = 'metric_five_minutes';
END;
INSERT INTO metric_row_budgets SELECT 'metric_hours', COUNT(*), 2160 FROM metric_hours;
CREATE TRIGGER metric_hours_budget_insert AFTER INSERT ON metric_hours BEGIN
 UPDATE metric_row_budgets SET retained_rows = retained_rows + 1 WHERE table_name = 'metric_hours';
 DELETE FROM metric_hours WHERE rowid = (
  SELECT rowid FROM metric_hours WHERE (SELECT retained_rows > max_rows FROM metric_row_budgets WHERE table_name = 'metric_hours')
  ORDER BY bucket_at, rowid LIMIT 1
 );
END;
CREATE TRIGGER metric_hours_budget_delete AFTER DELETE ON metric_hours BEGIN
 UPDATE metric_row_budgets SET retained_rows = retained_rows - 1 WHERE table_name = 'metric_hours';
END;
