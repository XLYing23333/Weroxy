CREATE TABLE credential_store (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    seal_check BLOB NOT NULL
);
