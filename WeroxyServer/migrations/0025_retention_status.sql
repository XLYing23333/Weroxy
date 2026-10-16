CREATE TABLE retention_status (
 task TEXT PRIMARY KEY CHECK (task IN ('metric_history', 'connection_history')),
 last_run TEXT NOT NULL DEFAULT '',
 next_run TEXT NOT NULL DEFAULT '',
 deleted_rows INTEGER NOT NULL DEFAULT 0 CHECK (deleted_rows >= 0),
 failure_reason TEXT NOT NULL DEFAULT ''
);
INSERT INTO retention_status(task) VALUES ('metric_history'), ('connection_history');
