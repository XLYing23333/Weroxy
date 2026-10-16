ALTER TABLE weroxy_devices ADD COLUMN max_data_ports INTEGER;

ALTER TABLE weroxy_forwards ADD COLUMN sharing_mode TEXT NOT NULL DEFAULT 'shared';
ALTER TABLE weroxy_forwards ADD COLUMN min_ports INTEGER NOT NULL DEFAULT 1;
ALTER TABLE weroxy_forwards ADD COLUMN preferred_ports INTEGER NOT NULL DEFAULT 1;
ALTER TABLE weroxy_forwards ADD COLUMN max_ports INTEGER NOT NULL DEFAULT 4;
ALTER TABLE weroxy_forwards ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;
ALTER TABLE weroxy_forwards ADD COLUMN use_reserved INTEGER NOT NULL DEFAULT 0;

CREATE TABLE port_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    forward_first INTEGER NOT NULL DEFAULT 20000,
    forward_last INTEGER NOT NULL DEFAULT 20099,
    data_first INTEGER NOT NULL DEFAULT 21000,
    data_last INTEGER NOT NULL DEFAULT 21099,
    reserved INTEGER NOT NULL DEFAULT 10,
    bind_host TEXT NOT NULL DEFAULT '0.0.0.0'
);

INSERT INTO port_settings(id) VALUES (1);

CREATE TABLE data_assignments (
    id INTEGER PRIMARY KEY,
    forward_id INTEGER NOT NULL REFERENCES weroxy_forwards(id),
    port INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('serving', 'draining')),
    UNIQUE(forward_id, port)
);

CREATE TABLE access_policies (
    id INTEGER PRIMARY KEY,
    scope TEXT NOT NULL CHECK (scope IN ('global', 'device', 'forward')),
    scope_key TEXT NOT NULL DEFAULT '',
    max_active INTEGER,
    max_pending INTEGER,
    max_per_ip INTEGER,
    rate_per_sec INTEGER,
    burst INTEGER,
    UNIQUE(scope, scope_key)
);

CREATE TABLE access_rules (
    id INTEGER PRIMARY KEY,
    scope TEXT NOT NULL CHECK (scope IN ('global', 'device', 'forward')),
    scope_key TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL CHECK (action IN ('ban', 'allow')),
    cidr TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE quick_tokens (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    token_mac BLOB NOT NULL UNIQUE,
    device_name TEXT NOT NULL DEFAULT '',
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
