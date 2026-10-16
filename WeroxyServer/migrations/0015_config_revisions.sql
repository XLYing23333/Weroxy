CREATE TABLE config_revisions (
    domain TEXT PRIMARY KEY CHECK (domain IN ('listener', 'policy', 'credential', 'ui', 'storage')),
    desired_revision INTEGER NOT NULL DEFAULT 0 CHECK (desired_revision >= 0),
    applied_revision INTEGER NOT NULL DEFAULT 0 CHECK (applied_revision >= 0),
    failure_reason TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
INSERT INTO config_revisions(domain, updated_at) VALUES
    ('listener', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('policy', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('credential', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('ui', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('storage', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

CREATE TABLE config_operations (
    domain TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    request_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (domain, operation_id)
);
CREATE INDEX config_operations_created ON config_operations(created_at);
