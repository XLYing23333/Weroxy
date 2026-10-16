CREATE TABLE legacy_devices (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    key_mac BLOB NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE legacy_forwards (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES legacy_devices(id),
    listen TEXT NOT NULL UNIQUE,
    target TEXT NOT NULL,
    created_at TEXT NOT NULL
);
