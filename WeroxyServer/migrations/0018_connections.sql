CREATE TABLE connection_details (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('legacy', 'weroxy')),
    session_id TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    forward_id INTEGER NOT NULL,
    device_name TEXT NOT NULL DEFAULT '',
    forward_listen TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    client_os TEXT NOT NULL DEFAULT '',
    data_port INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL,
    last_at TEXT NOT NULL,
    closed_at TEXT,
    close_reason TEXT NOT NULL DEFAULT '',
    up_bytes INTEGER NOT NULL DEFAULT 0 CHECK (up_bytes >= 0),
    down_bytes INTEGER NOT NULL DEFAULT 0 CHECK (down_bytes >= 0),
    UNIQUE(run_id, protocol, session_id)
);
CREATE INDEX connection_details_device ON connection_details(protocol, device_name, id DESC);
CREATE INDEX connection_details_closed ON connection_details(closed_at, id);
