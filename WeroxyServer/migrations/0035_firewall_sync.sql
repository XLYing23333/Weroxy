CREATE TABLE firewall_sync (
 id INTEGER PRIMARY KEY CHECK(id=1),
 enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
 managed INTEGER NOT NULL DEFAULT 0 CHECK(managed IN (0,1)),
 generation INTEGER NOT NULL DEFAULT 0 CHECK(generation>=0),
 status TEXT NOT NULL DEFAULT 'not_requested',
 failure_reason TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL DEFAULT ''
);
INSERT INTO firewall_sync(id) VALUES(1);
