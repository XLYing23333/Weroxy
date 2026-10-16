-- Retain exact existing Legacy binds; no whole range is implicitly opened.
CREATE TABLE forward_port_exceptions (
    listen TEXT PRIMARY KEY,
    origin TEXT NOT NULL CHECK (origin IN ('existing_legacy', 'lanproxy_import', 'manual_import')),
    created_at TEXT NOT NULL
);
INSERT INTO forward_port_exceptions(listen, origin, created_at)
SELECT DISTINCT listen, 'existing_legacy', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM legacy_forwards;
