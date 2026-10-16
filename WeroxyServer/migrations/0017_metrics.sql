-- Lifetime counters are independent of time bucket retention.
CREATE TABLE metric_totals (
    scope TEXT NOT NULL CHECK (scope IN ('global', 'device', 'forward')),
    protocol TEXT NOT NULL CHECK (protocol IN ('all', 'legacy', 'weroxy')),
    entity_id INTEGER NOT NULL,
    up_bytes INTEGER NOT NULL DEFAULT 0 CHECK (up_bytes >= 0),
    down_bytes INTEGER NOT NULL DEFAULT 0 CHECK (down_bytes >= 0),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (scope, protocol, entity_id)
);
CREATE TABLE metric_batches (
    batch_id TEXT PRIMARY KEY,
    sampled_at TEXT NOT NULL,
    written_at TEXT NOT NULL
);
CREATE INDEX metric_batches_time ON metric_batches(written_at);
CREATE TABLE metric_samples (
    batch_id TEXT PRIMARY KEY REFERENCES metric_batches(batch_id) ON DELETE CASCADE,
    sampled_at TEXT NOT NULL,
    interval_ms INTEGER NOT NULL CHECK (interval_ms >= 0),
    up_bytes INTEGER NOT NULL CHECK (up_bytes >= 0),
    down_bytes INTEGER NOT NULL CHECK (down_bytes >= 0),
    gap INTEGER NOT NULL CHECK (gap IN (0, 1))
);
CREATE INDEX metric_samples_time ON metric_samples(sampled_at);
CREATE TABLE metric_minutes (
    bucket_at TEXT PRIMARY KEY,
    up_bytes INTEGER NOT NULL CHECK (up_bytes >= 0),
    down_bytes INTEGER NOT NULL CHECK (down_bytes >= 0),
    samples INTEGER NOT NULL CHECK (samples >= 0),
    gaps INTEGER NOT NULL CHECK (gaps >= 0)
);
CREATE TABLE metric_five_minutes (
    bucket_at TEXT PRIMARY KEY,
    up_bytes INTEGER NOT NULL CHECK (up_bytes >= 0),
    down_bytes INTEGER NOT NULL CHECK (down_bytes >= 0),
    samples INTEGER NOT NULL CHECK (samples >= 0),
    gaps INTEGER NOT NULL CHECK (gaps >= 0)
);
CREATE TABLE metric_hours (
    bucket_at TEXT PRIMARY KEY,
    up_bytes INTEGER NOT NULL CHECK (up_bytes >= 0),
    down_bytes INTEGER NOT NULL CHECK (down_bytes >= 0),
    samples INTEGER NOT NULL CHECK (samples >= 0),
    gaps INTEGER NOT NULL CHECK (gaps >= 0)
);
