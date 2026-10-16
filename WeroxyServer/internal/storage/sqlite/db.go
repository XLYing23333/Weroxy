// Package sqlite opens the single server database and serializes writes.
package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"modernc.org/sqlite"
	_ "modernc.org/sqlite"

	"weroxy/server/migrations"
)

const (
	// MinVersion is the oldest SQLite build this server will open.
	MinVersion = "3.51.3"
	// DefaultQueue is the bounded write queue capacity.
	DefaultQueue = 32

	writeAttempts = 3
)

// ErrQueueFull means the single writer queue rejected a new job.
var ErrQueueFull = errors.New("write queue full")

// ErrDatabaseBusy means SQLite stayed busy or full after a bounded retry.
var ErrDatabaseBusy = errors.New("database busy")

// ErrAdminExists means bootstrap was asked to create a second administrator.
var ErrAdminExists = errors.New("administrator already exists")

// ErrNoAdmin means reset was asked to change a missing administrator.
var ErrNoAdmin = errors.New("administrator not found")

// DB is the process-wide SQLite handle.
type DB struct {
	path             string
	seal             []byte
	sql              *sql.DB
	write            *sql.Conn
	high             chan job
	low              chan job
	done             chan struct{}
	once             sync.Once
	queueMu          sync.RWMutex
	closing          bool
	recoveryRequired atomic.Bool
	recoveryOnce     sync.Once
	recoveryFailed   chan struct{}
	checkpointMu     sync.Mutex
	checkpoint       CheckpointStatus
	disk             DiskStatus
}

type job struct {
	ctx    context.Context
	fn     func(*sql.Tx) error
	connFn func(*sql.Conn) error
	res    chan error
}

// Probe opens an in-memory database and reports the linked SQLite and driver versions.
func Probe() (sqliteVersion, driverVersion string, err error) {
	db, err := sql.Open("sqlite", "file::memory:")
	if err != nil {
		return "", "", err
	}
	defer db.Close()
	if err := db.QueryRow(`SELECT sqlite_version()`).Scan(&sqliteVersion); err != nil {
		return "", "", err
	}
	if err := checkVersion(sqliteVersion); err != nil {
		return sqliteVersion, driverModule(), err
	}
	return sqliteVersion, driverModule(), nil
}

// Open creates or opens path, checks the SQLite build, and applies migrations.
func Open(path string, queue int) (*DB, error) {
	if queue <= 0 {
		queue = DefaultQueue
	}
	dsn, err := dsn(path)
	if err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(3)
	sqlDB.SetMaxIdleConns(2)
	ctx := context.Background()
	var version string
	if err := sqlDB.QueryRowContext(ctx, `SELECT sqlite_version()`).Scan(&version); err != nil {
		sqlDB.Close()
		return nil, err
	}
	if err := checkVersion(version); err != nil {
		sqlDB.Close()
		return nil, err
	}
	write, err := sqlDB.Conn(ctx)
	if err != nil {
		sqlDB.Close()
		return nil, err
	}
	handle := &DB{
		path:           path,
		sql:            sqlDB,
		write:          write,
		high:           make(chan job, queue),
		low:            make(chan job, queue),
		done:           make(chan struct{}),
		recoveryFailed: make(chan struct{}),
	}
	go handle.loop()
	if err := handle.migrate(ctx); err != nil {
		handle.Close()
		return nil, err
	}
	if err := validateCompiledSchema(ctx, sqlDB); err != nil {
		handle.Close()
		return nil, err
	}
	if err := handle.initSeal(ctx); err != nil {
		handle.Close()
		return nil, err
	}
	if err := tighten(path); err != nil {
		handle.Close()
		return nil, err
	}
	return handle, nil
}

// Close stops the writer and closes the database.
func (db *DB) Close() error {
	var err error
	db.once.Do(func() {
		db.queueMu.Lock()
		db.closing = true
		close(db.high)
		db.queueMu.Unlock()
		<-db.done
		if db.write != nil {
			err = db.write.Close()
		}
		if db.sql != nil {
			if closeErr := db.sql.Close(); err == nil {
				err = closeErr
			}
		}
	})
	return err
}

// Do runs fn inside one transaction on the single writer.
// Administrator changes use this high-priority queue.
// A full queue returns ErrQueueFull without waiting.
func (db *DB) Do(ctx context.Context, fn func(*sql.Tx) error) error {
	if tx, ok := ctx.Value(configTxKey{}).(*sql.Tx); ok {
		return fn(tx)
	}
	return db.enqueue(ctx, db.high, fn)
}

// WithConn runs fn on the single writer connection, outside a transaction.
// Backup and restore use it so other writes wait.
func (db *DB) WithConn(ctx context.Context, fn func(*sql.Conn) error) error {
	item := job{ctx: ctx, connFn: fn, res: make(chan error, 1)}
	return db.queueJob(ctx, db.high, item)
}

// DoLow queues a write behind administrator changes. Metrics will use it later.
func (db *DB) DoLow(ctx context.Context, fn func(*sql.Tx) error) error {
	return db.enqueue(ctx, db.low, fn)
}

func (db *DB) enqueue(ctx context.Context, queue chan job, fn func(*sql.Tx) error) error {
	item := job{ctx: ctx, fn: fn, res: make(chan error, 1)}
	return db.queueJob(ctx, queue, item)
}

func (db *DB) queueJob(ctx context.Context, queue chan job, item job) error {
	// Close and enqueue are atomic relative to one another. No late sender
	// may panic on high or wait forever in low after the writer has exited.
	db.queueMu.RLock()
	if db.recoveryRequired.Load() {
		db.queueMu.RUnlock()
		return ErrRecoveryRequired
	}
	if db.closing {
		db.queueMu.RUnlock()
		return ErrDatabaseBusy
	}
	select {
	case queue <- item:
		db.queueMu.RUnlock()
	case <-ctx.Done():
		db.queueMu.RUnlock()
		return ctx.Err()
	default:
		db.queueMu.RUnlock()
		return ErrQueueFull
	}
	select {
	case err := <-item.res:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// QueryRow runs a read on the pool, not on the writer connection.
func (db *DB) QueryRow(ctx context.Context, query string, args ...any) *sql.Row {
	if db.recoveryRequired.Load() {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		return db.sql.QueryRowContext(canceled, query, args...)
	}
	if tx, ok := ctx.Value(configTxKey{}).(*sql.Tx); ok {
		return tx.QueryRowContext(ctx, query, args...)
	}
	return db.sql.QueryRowContext(ctx, query, args...)
}

// QueryRows participates in a supplied read snapshot or config mutation.
func (db *DB) QueryRows(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if db.recoveryRequired.Load() {
		return nil, ErrRecoveryRequired
	}
	if tx, ok := ctx.Value(configTxKey{}).(*sql.Tx); ok {
		return tx.QueryContext(ctx, query, args...)
	}
	return db.sql.QueryContext(ctx, query, args...)
}

// ReadSnapshot gives related configuration reads one SQLite snapshot.
func (db *DB) ReadSnapshot(ctx context.Context, fn func(context.Context) error) error {
	if db.recoveryRequired.Load() {
		return ErrRecoveryRequired
	}
	tx, err := db.sql.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(context.WithValue(ctx, configTxKey{}, tx)); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) loop() {
	defer close(db.done)
	for {
		select {
		case item, ok := <-db.high:
			if !ok {
				db.failQueued(db.low)
				return
			}
			item.res <- db.run(item)
		case item, ok := <-db.low:
			if !ok {
				return
			}
			if high, ready := db.takeHigh(); ready {
				high.res <- db.run(high)
			}
			item.res <- db.run(item)
		}
	}
}

func (db *DB) failQueued(queue chan job) {
	for {
		select {
		case item, ok := <-queue:
			if !ok {
				return
			}
			item.res <- ErrDatabaseBusy
		default:
			return
		}
	}
}

func (db *DB) takeHigh() (job, bool) {
	select {
	case item, ok := <-db.high:
		if !ok {
			return job{}, false
		}
		return item, true
	default:
		return job{}, false
	}
}

func (db *DB) run(item job) error {
	if db.recoveryRequired.Load() {
		return ErrRecoveryRequired
	}
	if item.connFn != nil {
		return item.connFn(db.write)
	}
	var last error
	for attempt := 0; attempt < writeAttempts; attempt++ {
		tx, err := db.write.BeginTx(item.ctx, nil)
		if err != nil {
			if retryable(err) {
				last = err
				if !sleepAttempt(item.ctx, attempt) {
					return item.ctx.Err()
				}
				continue
			}
			return err
		}
		err = item.fn(tx)
		if err != nil {
			_ = tx.Rollback()
			if retryable(err) {
				last = err
				if !sleepAttempt(item.ctx, attempt) {
					return item.ctx.Err()
				}
				continue
			}
			return err
		}
		if err := tx.Commit(); err != nil {
			if retryable(err) {
				last = err
				if !sleepAttempt(item.ctx, attempt) {
					return item.ctx.Err()
				}
				continue
			}
			return err
		}
		return nil
	}
	return fmt.Errorf("%w: %v", ErrDatabaseBusy, last)
}

func sleepAttempt(ctx context.Context, attempt int) bool {
	timer := time.NewTimer(time.Duration(attempt+1) * 5 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func retryable(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		code := se.Code()
		return code == 5 || code == 13 // SQLITE_BUSY, SQLITE_FULL
	}
	return false
}

func (db *DB) migrate(ctx context.Context) error {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	applied, err := db.applied(ctx)
	if err != nil {
		return err
	}
	if len(applied) > 0 {
		if _, done := applied[39]; !done {
			if err := db.backupBefore030(ctx); err != nil {
				return fmt.Errorf("backup before 0.3.0 migration: %w", err)
			}
		} else if _, done := applied[40]; !done {
			if err := db.backupBeforeMigration(ctx, "pre-audit-budget-"); err != nil {
				return fmt.Errorf("backup before audit migration: %w", err)
			}
		} else if _, done := applied[41]; !done {
			if err := db.backupBeforeMigration(ctx, "pre-entity-ids-"); err != nil {
				return fmt.Errorf("backup before entity ID migration: %w", err)
			}
		}
	}
	for _, name := range names {
		version, err := migrationVersion(name)
		if err != nil {
			return err
		}
		body, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return err
		}
		sum := fmt.Sprintf("%x", sha256.Sum256(body))
		if previous, ok := applied[version]; ok {
			if previous != sum {
				return fmt.Errorf("migration %d checksum changed", version)
			}
			continue
		}
		tx, err := db.write.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, applied_at, checksum) VALUES (?, ?, ?)`,
			version, time.Now().UTC().Format(time.RFC3339Nano), sum,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// backupBefore030 preserves the pre-upgrade schema and credential master together.
func (db *DB) backupBefore030(ctx context.Context) error {
	return db.backupBeforeMigration(ctx, "pre-0.3.0-")
}

func (db *DB) backupBeforeMigration(ctx context.Context, prefix string) error {
	parent := filepath.Join(filepath.Dir(db.path), "migration-backups")
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid migration backup directory")
	}
	if err := os.Chmod(parent, 0700); err != nil {
		return err
	}
	if err := BackupSpace(parent, backupSingleBytes); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(dir)
		}
	}()
	path := filepath.Join(dir, "weroxy.db")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		return err
	}
	if err := backupToContext(ctx, db.write, path); err != nil {
		return err
	}
	if err := integrity(path); err != nil {
		return err
	}
	key, err := readSeal(filepath.Join(filepath.Dir(db.path), sealFile), false)
	if err == nil {
		defer clear(key)
		if err := os.WriteFile(filepath.Join(dir, sealFile), key, 0600); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	complete = true
	return nil
}

func (db *DB) applied(ctx context.Context) (map[int]string, error) {
	var exists int
	err := db.write.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'`).Scan(&exists)
	if err != nil {
		return nil, err
	}
	out := map[int]string{}
	if exists == 0 {
		return out, nil
	}
	rows, err := db.write.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var version int
		var sum string
		if err := rows.Scan(&version, &sum); err != nil {
			return nil, err
		}
		out[version] = sum
	}
	return out, rows.Err()
}

func migrationVersion(name string) (int, error) {
	prefix := strings.SplitN(name, "_", 2)[0]
	version, err := strconv.Atoi(prefix)
	if err != nil || version <= 0 {
		return 0, fmt.Errorf("migration name %s", name)
	}
	return version, nil
}

func dsn(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	u := url.URL{Scheme: "file", Path: abs}
	q := u.Query()
	for _, pragma := range []string{
		"foreign_keys(1)",
		"secure_delete(1)",
		"busy_timeout(0)",
		"synchronous(FULL)",
		"temp_store(MEMORY)",
		"journal_mode(WAL)",
	} {
		q.Add("_pragma", pragma)
	}
	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func tighten(path string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if info.IsDir() {
			continue
		}
		if err := os.Chmod(path+suffix, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func checkVersion(version string) error {
	if compareVersion(version, MinVersion) < 0 {
		return fmt.Errorf("sqlite %s is older than %s", version, MinVersion)
	}
	return nil
}

func compareVersion(left, right string) int {
	ls := versionParts(left)
	rs := versionParts(right)
	for i := 0; i < 3; i++ {
		if ls[i] > rs[i] {
			return 1
		}
		if ls[i] < rs[i] {
			return -1
		}
	}
	return 0
}

func versionParts(version string) [3]int {
	version = strings.SplitN(version, "-", 2)[0]
	fields := strings.Split(version, ".")
	var out [3]int
	for i := 0; i < len(fields) && i < 3; i++ {
		n, _ := strconv.Atoi(fields[i])
		out[i] = n
	}
	return out
}

func driverModule() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, dep := range info.Deps {
		if dep.Path == "modernc.org/sqlite" {
			return dep.Version
		}
	}
	return ""
}
