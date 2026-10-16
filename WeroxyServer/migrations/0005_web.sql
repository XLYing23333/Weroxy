CREATE TABLE admin_sessions (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    token_mac BLOB NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE ui_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    locale TEXT NOT NULL DEFAULT 'zh',
    theme TEXT NOT NULL DEFAULT 'system'
);

INSERT INTO ui_settings(id) VALUES (1);

UPDATE port_settings
SET forward_first = 29000,
    forward_last = 29099,
    data_first = 29100,
    data_last = 29199,
    bind_host = '127.0.0.1'
WHERE id = 1
  AND forward_first = 20000
  AND forward_last = 20099
  AND data_first = 21000
  AND data_last = 21099;
