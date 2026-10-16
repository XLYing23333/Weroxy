ALTER TABLE config_revisions RENAME TO config_revisions_previous;
CREATE TABLE config_revisions (
 domain TEXT PRIMARY KEY CHECK (domain IN ('listener','policy','credential','ui','storage','logging')),
 desired_revision INTEGER NOT NULL DEFAULT 0 CHECK (desired_revision>=0),
 applied_revision INTEGER NOT NULL DEFAULT 0 CHECK (applied_revision>=0),
 failure_reason TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL
);
INSERT INTO config_revisions SELECT * FROM config_revisions_previous;
DROP TABLE config_revisions_previous;
INSERT INTO config_revisions(domain,updated_at) VALUES ('logging',strftime('%Y-%m-%dT%H:%M:%fZ','now'));
CREATE TABLE log_settings (
 id INTEGER PRIMARY KEY CHECK(id=1),
 max_file_mib INTEGER NOT NULL CHECK(max_file_mib BETWEEN 1 AND 128),
 max_total_mib INTEGER NOT NULL CHECK(max_total_mib BETWEEN 16 AND 1024 AND max_total_mib>=max_file_mib),
 max_files INTEGER NOT NULL CHECK(max_files BETWEEN 2 AND 64),
 retain_days INTEGER NOT NULL CHECK(retain_days BETWEEN 1 AND 365)
);
INSERT INTO log_settings VALUES (1,32,256,16,30);
