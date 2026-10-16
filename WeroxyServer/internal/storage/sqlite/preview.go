package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// OpenPreview copies a consistent SQLite snapshot into a temporary directory.
// The returned DB is writable only in that directory. The caller must close it
// and run cleanup, regardless of whether the preview succeeds.
func OpenPreview(path string) (*DB, func(), error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("preview requires an initialized database")
	}
	dir, err := os.MkdirTemp("", "weroxy-import-preview-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	abs, err := filepath.Abs(path)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	u := url.URL{Scheme: "file", Path: abs}
	q := u.Query()
	q.Set("mode", "ro")
	// Immutable avoids creating WAL sidecars for a closed database. A live
	// database needs SQLite's normal read-only WAL handling to include commits.
	if _, walErr := os.Stat(path + "-wal"); os.IsNotExist(walErr) {
		q.Set("immutable", "1")
	} else if walErr != nil {
		cleanup()
		return nil, nil, walErr
	}
	u.RawQuery = q.Encode()
	source, err := sql.Open("sqlite", u.String())
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	defer source.Close()
	conn, err := source.Conn(context.Background())
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	err = backupTo(conn, filepath.Join(dir, "weroxy.db"))
	_ = conn.Close()
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	key, err := readSeal(filepath.Join(filepath.Dir(abs), sealFile), false)
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, sealFile), key, 0o600)
	} else if !os.IsNotExist(err) {
		cleanup()
		return nil, nil, err
	} else {
		err = nil
	}
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	preview, err := Open(filepath.Join(dir, "weroxy.db"), DefaultQueue)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return preview, cleanup, nil
}
