CREATE TABLE listener_reservations (
 role TEXT PRIMARY KEY CHECK (role IN ('legacy', 'legacy-tls', 'weroxy-control', 'weroxy-data', 'web')),
 host TEXT NOT NULL,
 port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535)
);
-- Defaults apply offline until startup registers its configured entrances.
INSERT INTO listener_reservations(role, host, port) VALUES
('legacy', '::', 4900), ('legacy-tls', '::', 4993),
('weroxy-control', '::', 29999), ('web', '::', 9415);
