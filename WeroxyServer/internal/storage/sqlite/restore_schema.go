package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"

	"weroxy/server/migrations"
)

type migrationScript struct {
	version int
	body    string
	sum     string
}

func migrationScripts() ([]migrationScript, error) {
	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var scripts []migrationScript
	for _, name := range names {
		version, err := migrationVersion(name)
		if err != nil {
			return nil, err
		}
		body, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return nil, err
		}
		scripts = append(scripts, migrationScript{version, string(body), fmt.Sprintf("%x", sha256.Sum256(body))})
	}
	return scripts, nil
}

var schemaCache = struct {
	sync.Mutex
	hashes map[int]string
}{hashes: map[int]string{}}

// The expected schema comes from compiled migrations, never from the live DB
// or migration rows supplied by an uploaded backup.
func expectedSchema(ctx context.Context, version int) (string, error) {
	schemaCache.Lock()
	defer schemaCache.Unlock()
	if hash, ok := schemaCache.hashes[version]; ok {
		return hash, nil
	}
	canonical, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return "", err
	}
	defer canonical.Close()
	canonical.SetMaxOpenConns(1)
	scripts, err := migrationScripts()
	if err != nil {
		return "", err
	}
	for _, script := range scripts {
		if script.version > version {
			break
		}
		if _, err := canonical.ExecContext(ctx, script.body); err != nil {
			return "", err
		}
	}
	hash, err := actualSchema(ctx, canonical)
	if err == nil {
		schemaCache.hashes[version] = hash
	}
	return hash, err
}

func actualSchema(ctx context.Context, db *sql.DB) (string, error) {
	rows, err := db.QueryContext(ctx, `SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_master ORDER BY type,name`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	digest := sha256.New()
	encoder := json.NewEncoder(digest)
	n := 0
	for rows.Next() {
		var item [4]string
		if err := rows.Scan(&item[0], &item[1], &item[2], &item[3]); err != nil {
			return "", err
		}
		n++
		if n > 512 || len(item[1]) > 256 || len(item[2]) > 256 || len(item[3]) > 32768 {
			return "", errors.New("backup schema exceeds budget")
		}
		if err := encoder.Encode(item); err != nil {
			return "", err
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", digest.Sum(nil)), nil
}

// Refuse an already tampered live database after an upgrade or restart too;
// rejecting future uploaded files alone would leave an old injected trigger active.
func validateCompiledSchema(ctx context.Context, db *sql.DB) error {
	scripts, err := migrationScripts()
	if err != nil {
		return err
	}
	expected, err := expectedSchema(ctx, scripts[len(scripts)-1].version)
	if err != nil {
		return err
	}
	actual, err := actualSchema(ctx, db)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("database schema differs from compiled schema; offline recovery required")
	}
	return nil
}

func validatedBackupVersion(ctx context.Context, backup *sql.DB) (int, error) {
	scripts, err := migrationScripts()
	if err != nil {
		return 0, err
	}
	rows, err := backup.QueryContext(ctx, `SELECT version,checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return 0, err
	}
	index := 0
	version := 0
	for rows.Next() {
		var sum string
		if err := rows.Scan(&version, &sum); err != nil {
			rows.Close()
			return 0, err
		}
		if index >= len(scripts) || scripts[index].version != version || scripts[index].sum != sum {
			rows.Close()
			return 0, errors.New("backup schema migration mismatch")
		}
		index++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	// Published 0.3.0 snapshots can be upgraded in the isolated candidate.
	if version < 39 {
		return 0, errors.New("backup schema is not supported")
	}
	expected, err := expectedSchema(ctx, version)
	if err != nil {
		return 0, err
	}
	actual, err := actualSchema(ctx, backup)
	if err != nil {
		return 0, err
	}
	if actual != expected {
		return 0, errors.New("backup schema differs from compiled schema")
	}
	return version, nil
}

func (db *DB) checkBackupSchema(ctx context.Context, path string) error {
	u, err := readOnlyDB(path)
	if err != nil {
		return err
	}
	defer u.Close()
	_, err = validatedBackupVersion(ctx, u)
	return err
}

func readOnlyDB(path string) (*sql.DB, error) {
	// dsn safely URL-escapes file names; backups are opened read-only.
	name, err := dsn(path)
	if err != nil {
		return nil, err
	}
	if strings.Contains(name, "?") {
		name += "&mode=ro"
	} else {
		name += "?mode=ro"
	}
	return sql.Open("sqlite", name)
}
