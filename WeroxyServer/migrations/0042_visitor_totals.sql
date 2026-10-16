CREATE TABLE visitor_totals (
 protocol TEXT NOT NULL, device_id INTEGER NOT NULL, source_ip TEXT NOT NULL,
 connections INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
 client_os TEXT NOT NULL DEFAULT '', last_unix INTEGER NOT NULL DEFAULT 0,
 cumulative_since TEXT NOT NULL, hidden INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(protocol,device_id,source_ip)
);
CREATE TABLE visitor_checkpoints (
 run_id TEXT NOT NULL, protocol TEXT NOT NULL, device_id INTEGER NOT NULL, source_ip TEXT NOT NULL,
 connections INTEGER NOT NULL, bytes INTEGER NOT NULL, version INTEGER NOT NULL,
 PRIMARY KEY(run_id,protocol,device_id,source_ip)
);
