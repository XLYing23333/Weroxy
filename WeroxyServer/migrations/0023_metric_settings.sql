CREATE TABLE metric_settings (
 id INTEGER PRIMARY KEY CHECK (id = 1),
 sample_sec INTEGER NOT NULL CHECK (sample_sec BETWEEN 1 AND 60),
 refresh_sec INTEGER NOT NULL CHECK (refresh_sec BETWEEN 1 AND 60)
);
INSERT INTO metric_settings VALUES (1, 5, 5);
