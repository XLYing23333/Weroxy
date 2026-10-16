CREATE TABLE weroxy_devices (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    device_uid TEXT NOT NULL UNIQUE,
    token_mac BLOB NOT NULL UNIQUE,
    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE TABLE weroxy_forwards (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES weroxy_devices(id),
    listen TEXT NOT NULL UNIQUE,
    target TEXT NOT NULL,
    created_at TEXT NOT NULL
);
