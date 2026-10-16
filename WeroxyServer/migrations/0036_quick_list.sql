CREATE TABLE quick_list_settings (
    id INTEGER PRIMARY KEY CHECK(id=1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1))
);
INSERT INTO quick_list_settings(id,enabled) VALUES(1,0);
