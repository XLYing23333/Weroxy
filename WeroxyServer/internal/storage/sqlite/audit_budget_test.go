package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestLoginAuditFloodHasRowBudget(t *testing.T) {
	ctx := t.Context()
	db, err := Open(filepath.Join(t.TempDir(), "state.db"), DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var maxRows int64
	if err := db.QueryRow(ctx, `SELECT max_rows FROM audit_retention WHERE id=1`).Scan(&maxRows); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = db.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `WITH RECURSIVE flood(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM flood WHERE x < ?) INSERT INTO audit_events(action,outcome,detail,created_at) SELECT 'web.login','failure','unknown',? FROM flood`, maxRows+20, time.Now().UTC().Format(time.RFC3339Nano))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d audit inserts in %s; capacity %d", maxRows+20, time.Since(started), maxRows)
	if err = db.RecordAudit(ctx, "device_rename", "success", "kept"); err != nil {
		t.Fatal(err)
	}
	var n int64
	if err = db.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&n); err != nil || n != maxRows {
		t.Fatalf("rows=%d err=%v", n, err)
	}
	var latest string
	db.QueryRow(ctx, `SELECT detail FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&latest)
	if latest != "kept" {
		t.Fatal("latest audit lost")
	}
	var reason string
	db.QueryRow(ctx, `SELECT last_reason FROM audit_retention WHERE id=1`).Scan(&reason)
	if reason != "row_budget" {
		t.Fatal("capacity cleanup unrecorded")
	}
}

func TestAuditBudgetMigrationBacksUpExistingDatabase(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	db, err := Open(path, DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RecordAudit(ctx, "kept", "success", "history"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.write.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version=40`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path, DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	files, err := filepath.Glob(filepath.Join(dir, "migration-backups", "pre-audit-budget-*", "weroxy.db"))
	if err != nil || len(files) != 1 {
		t.Fatalf("migration backups=%d err=%v", len(files), err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE detail='history'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("audit history changed")
	}
}

func TestCancelledCheckpointDoesNotShareMutableResult(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "checkpoint.db"), DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < 500; i++ {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { db.CheckpointPassive(ctx); close(done) }()
		cancel()
		<-done
	}
}
