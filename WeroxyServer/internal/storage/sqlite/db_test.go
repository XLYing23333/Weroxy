package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"weroxy/server/internal/auth"
)

func TestVersionOrder(t *testing.T) {
	if compareVersion("3.51.2", MinVersion) >= 0 {
		t.Fatal("3.51.2 should be rejected")
	}
	if compareVersion("3.51.3", MinVersion) != 0 || compareVersion("3.52.0", MinVersion) < 0 {
		t.Fatal("newer builds should pass")
	}
}

func TestMigrationPragmasAndBootstrap(t *testing.T) {
	db := openTemp(t, DefaultQueue)
	ctx := context.Background()
	var fk, sync int
	var journal string
	if err := db.QueryRow(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign_keys=%d err=%v", fk, err)
	}
	if err := db.QueryRow(ctx, `PRAGMA synchronous`).Scan(&sync); err != nil || sync != 2 {
		t.Fatalf("synchronous=%d err=%v", sync, err)
	}
	if err := db.QueryRow(ctx, `PRAGMA journal_mode`).Scan(&journal); err != nil || journal != "wal" {
		t.Fatalf("journal=%s err=%v", journal, err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 42 {
		t.Fatalf("migrations=%d", count)
	}
	var applied string
	if err := db.QueryRow(ctx, `SELECT applied_at FROM schema_migrations WHERE version = 5`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(applied, "Z") {
		t.Fatalf("migration at=%s", applied)
	}

	password := []byte("correct-horse-1")
	hasher := auth.NewArgon()
	if err := db.Bootstrap(ctx, hasher, "admin", password); err != nil {
		t.Fatal(err)
	}
	if err := db.Bootstrap(ctx, hasher, "admin", []byte("correct-horse-2")); !errors.Is(err, ErrAdminExists) {
		t.Fatalf("second bootstrap err=%v", err)
	}
	phc, err := db.PasswordPHC(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(phc, "correct-horse-1") {
		t.Fatal("plaintext password stored")
	}
	ok, err := hasher.Verify(password, phc)
	if err != nil || !ok {
		t.Fatalf("verify ok=%v err=%v", ok, err)
	}
	raw, err := os.ReadFile(db.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "correct-horse-1") {
		t.Fatal("password bytes in database file")
	}
	info, err := os.Stat(db.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("db mode %o", info.Mode().Perm())
	}
	audits, err := db.Audits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, audit := range audits {
		if strings.Contains(audit.Detail, "correct-horse") {
			t.Fatalf("audit leaked password: %+v", audit)
		}
	}
	foundFail := false
	for _, audit := range audits {
		if audit.Action == "bootstrap" && audit.Outcome == "failure" {
			foundFail = true
		}
	}
	if !foundFail {
		t.Fatalf("audits %+v", audits)
	}
}

type stubHasher struct {
	n int
}

func (s *stubHasher) Hash(password []byte) (string, error) {
	s.n++
	return "stub-hash", nil
}

func (s *stubHasher) Verify(password []byte, phc string) (bool, error) {
	return phc == "stub-hash", nil
}

func TestQueueFullDoesNotReplaceHash(t *testing.T) {
	db := openTemp(t, 1)
	ctx := context.Background()
	stub := &stubHasher{}
	if err := db.Bootstrap(ctx, stub, "admin", []byte("correct-horse-1")); err != nil {
		t.Fatal(err)
	}
	before, err := db.PasswordPHC(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = db.Do(ctx, func(tx *sql.Tx) error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	queued := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		close(queued)
		_ = db.Do(ctx, func(tx *sql.Tx) error { return nil })
	}()
	<-queued
	waitUntil(t, func() bool { return len(db.high) == 1 })
	err = db.ResetPassword(ctx, stub, "admin", []byte("correct-horse-2"))
	close(release)
	wg.Wait()
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("err=%v", err)
	}
	after, err := db.PasswordPHC(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("hash changed while the queue was full")
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM administrators`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("count=%d err=%v", n, err)
	}
}

func TestHighPriorityRunsBeforeLow(t *testing.T) {
	db := openTemp(t, 2)
	ctx := context.Background()
	started := make(chan struct{})
	release := make(chan struct{})
	order := make(chan string, 2)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = db.Do(ctx, func(tx *sql.Tx) error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = db.DoLow(ctx, func(tx *sql.Tx) error {
			order <- "low"
			return nil
		})
	}()
	waitUntil(t, func() bool { return len(db.low) == 1 })
	go func() {
		defer wg.Done()
		_ = db.Do(ctx, func(tx *sql.Tx) error {
			order <- "high"
			return nil
		})
	}()
	waitUntil(t, func() bool { return len(db.high) == 1 })
	close(release)
	wg.Wait()
	first := <-order
	second := <-order
	if first != "high" || second != "low" {
		t.Fatalf("order %s then %s", first, second)
	}
}

func TestDatabaseBusyDoesNotCreateAdmin(t *testing.T) {
	db := openTemp(t, DefaultQueue)
	ctx := context.Background()
	dsn, err := dsn(db.path)
	if err != nil {
		t.Fatal(err)
	}
	other, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })
	if _, err := other.Exec(`BEGIN EXCLUSIVE`); err != nil {
		t.Fatal(err)
	}
	err = db.Bootstrap(ctx, &stubHasher{}, "admin", []byte("correct-horse-1"))
	if _, rollErr := other.Exec(`ROLLBACK`); rollErr != nil {
		t.Fatal(rollErr)
	}
	if !errors.Is(err, ErrDatabaseBusy) {
		t.Fatalf("err=%v", err)
	}
	has, err := db.HasAdmin(ctx)
	if err != nil || has {
		t.Fatalf("has=%v err=%v", has, err)
	}
}

func openTemp(t *testing.T, queue int) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "weroxy.db"), queue)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func waitUntil(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timeout")
}

func TestResetPasswordRevokesExistingSessions(t *testing.T) {
	db := openTemp(t, DefaultQueue)
	ctx := context.Background()
	hasher := &stubHasher{}
	if err := db.Bootstrap(ctx, hasher, "admin", []byte("correct-horse-1")); err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	if err := db.CreateAdminSession(ctx, "admin", digest, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AdminBySession(ctx, digest); err != nil {
		t.Fatal(err)
	}
	if err := db.ResetPassword(ctx, hasher, "admin", []byte("correct-horse-2")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AdminBySession(ctx, digest); !errors.Is(err, ErrSession) {
		t.Fatalf("old session survived password reset: %v", err)
	}
}

func TestUpgrade030BacksUpHTTPSAndPreservesAccount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weroxy.db")
	ctx := context.Background()
	db, err := Open(path, DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Bootstrap(ctx, auth.NewArgon(), "upgrade-user", []byte("secret-test")); err != nil {
		t.Fatal(err)
	}
	phc, err := db.PasswordPHC(ctx, "upgrade-user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.write.ExecContext(ctx, `CREATE TABLE https_settings(id INTEGER PRIMARY KEY, domain TEXT); INSERT INTO https_settings VALUES(1,'old.example.com'); DELETE FROM schema_migrations WHERE version=39; INSERT INTO listener_reservations(role,host,port) VALUES ('legacy-tls','::',4993)`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path, DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	claims, e := db.ListenerReservations(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range claims {
		if c.Role == "legacy-tls" {
			t.Fatal("obsolete TLS reservation remains")
		}
	}
	current, err := db.PasswordPHC(ctx, "upgrade-user")
	if err != nil || current != phc {
		t.Fatalf("account changed: %v", err)
	}
	var n int
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name='https_settings'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("obsolete table remains: %d %v", n, err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "migration-backups", "pre-0.3.0-*", "weroxy.db"))
	if err != nil || len(files) != 1 {
		t.Fatalf("backup missing: %v %v", files, err)
	}
	info, err := os.Stat(files[0])
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("backup permissions: %v", err)
	}
	backup, err := sql.Open("sqlite", "file:"+files[0]+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	var domain string
	if err = backup.QueryRow(`SELECT domain FROM https_settings`).Scan(&domain); err != nil || domain != "old.example.com" {
		t.Fatalf("pre-upgrade content lost: %v", err)
	}
	if _, err = os.Stat(filepath.Join(filepath.Dir(files[0]), sealFile)); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentCloseRejectsLateWritersWithoutLeaks(t *testing.T) {
	for round := 0; round < 10; round++ {
		db, err := Open(filepath.Join(t.TempDir(), "close.db"), DefaultQueue)
		if err != nil {
			t.Fatal(err)
		}
		gate := make(chan struct{})
		done := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-gate
				for j := 0; j < 8; j++ {
					if i%3 == 0 {
						_ = db.DoLow(context.Background(), func(*sql.Tx) error { return nil })
					} else if i%3 == 1 {
						_ = db.Do(context.Background(), func(*sql.Tx) error { return nil })
					} else {
						_ = db.WithConn(context.Background(), func(*sql.Conn) error { return nil })
					}
				}
			}(i)
		}
		close(gate)
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("writer goroutines retained after database close")
		}
		if err := db.DoLow(context.Background(), func(*sql.Tx) error { return nil }); err != ErrDatabaseBusy {
			t.Fatalf("late low writer=%v", err)
		}
	}
}

func TestNewInstallationLocaleAndSavedPreference(t *testing.T) {
	db := openTemp(t, DefaultQueue)
	ctx := context.Background()
	settings, err := db.UI(ctx)
	if err != nil || settings.Locale != "en" {
		t.Fatalf("initial locale=%s err=%v", settings.Locale, err)
	}
	settings.Locale = "zh"
	if err := db.SetUI(ctx, settings); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(db.path, DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	saved, err := reopened.UI(ctx)
	if err != nil || saved.Locale != "zh" {
		t.Fatalf("saved locale=%s err=%v", saved.Locale, err)
	}
}
