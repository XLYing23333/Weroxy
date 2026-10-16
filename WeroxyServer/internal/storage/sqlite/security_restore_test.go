package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weroxy/server/internal/auth"
)

type restoreFixture struct {
	db           *DB
	dir, backup  string
	old, current []byte
}

func newRestoreFixture(t *testing.T) restoreFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "state.db"), DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := t.Context()
	if err = db.Bootstrap(ctx, auth.NewArgon(), "restore-user", []byte("fixture-password")); err != nil {
		t.Fatal(err)
	}
	if err := db.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `WITH RECURSIVE batch(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM batch WHERE n<700) INSERT INTO audit_events(action,outcome,detail,created_at) SELECT 'restore_fixture','success',?,? FROM batch`, strings.Repeat("x", 1024), time.Now().UTC().Format(time.RFC3339Nano))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	old := sha256.Sum256([]byte("old-session"))
	current := sha256.Sum256([]byte("current-session"))
	if err = db.CreateAdminSession(ctx, "restore-user", old[:], time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = db.AddWeroxyDevice(ctx, "original", "uid-original", []byte("mac-original"), "key-original"); err != nil {
		t.Fatal(err)
	}
	if err = db.AddLegacyDevice(ctx, "legacy-original", []byte("mac-legacy"), "key-legacy"); err != nil {
		t.Fatal(err)
	}
	bdir := filepath.Join(dir, "backups")
	backup, err := db.BackupFile(ctx, bdir)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.RevokeAdminSession(ctx, old[:]); err != nil {
		t.Fatal(err)
	}
	if err = db.RevokeWeroxyDevice(ctx, "original"); err != nil {
		t.Fatal(err)
	}
	if err = db.SetDevicePaused(ctx, "legacy", "legacy-original", true); err != nil {
		t.Fatal(err)
	}
	if err = db.CreateAdminSession(ctx, "restore-user", current[:], time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = db.AddWeroxyDevice(ctx, "keep-current", "uid-current", []byte("mac-current"), "key-current"); err != nil {
		t.Fatal(err)
	}
	return restoreFixture{db, dir, backup, old[:], current[:]}
}
func (f restoreFixture) restored(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	for _, cookie := range [][]byte{f.old, f.current} {
		if _, err := f.db.AdminBySession(ctx, cookie); err != ErrSession {
			t.Fatal("restored session is usable")
		}
	}
	ds, _, err := f.db.ListWeroxy(ctx)
	if err != nil || len(ds) != 1 || !ds[0].Revoked || !ds[0].Paused {
		t.Fatalf("device isolation failed: %v", err)
	}
	ls, _, err := f.db.ListLegacy(ctx)
	if err != nil || len(ls) != 1 || !ls[0].Paused {
		t.Fatal("Legacy isolation failed")
	}
}
func (f restoreFixture) unchanged(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	if _, err := f.db.AdminBySession(ctx, f.old); err != ErrSession {
		t.Fatal("old session resurrected")
	}
	if _, err := f.db.AdminBySession(ctx, f.current); err != nil {
		t.Fatal("current session changed")
	}
	ds, _, err := f.db.ListWeroxy(ctx)
	if err != nil || len(ds) != 2 {
		t.Fatal("current configuration changed")
	}
}
func TestRestoreCancellationAndSQLFailureBoundaries(t *testing.T) {
	for _, phase := range []string{"copied", "validated", "quarantined", "before_apply", "during_apply", "after_apply"} {
		t.Run("cancel_"+phase, func(t *testing.T) {
			f := newRestoreFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			hooks := &restoreHooks{phase: func(current string) error {
				if current == phase {
					cancel()
				}
				return nil
			}}
			err := f.db.restoreFile(ctx, filepath.Join(f.dir, "backups"), f.backup, hooks)
			if phase == "before_apply" || phase == "during_apply" || phase == "after_apply" {
				if err != nil {
					t.Fatal(err)
				}
				f.restored(t)
			} else {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel result: %v", err)
				}
				f.unchanged(t)
			}
		})
	}
	t.Run("sql_failure_after_apply", func(t *testing.T) {
		f := newRestoreFixture(t)
		hooks := &restoreHooks{phase: func(phase string) error {
			if phase != "after_apply" {
				return nil
			}
			_, err := f.db.write.ExecContext(t.Context(), `UPDATE deliberately_missing_table SET value=1`)
			return err
		}}
		if err := f.db.restoreFile(t.Context(), filepath.Join(f.dir, "backups"), f.backup, hooks); err == nil {
			t.Fatal("SQL failure not returned")
		}
		f.unchanged(t)
	})
	t.Run("rollback_failure_closes_database", func(t *testing.T) {
		f := newRestoreFixture(t)
		hooks := &restoreHooks{phase: func(phase string) error {
			if phase == "after_apply" || phase == "before_rollback" {
				return errors.New("injected disk failure")
			}
			return nil
		}}
		if err := f.db.restoreFile(t.Context(), filepath.Join(f.dir, "backups"), f.backup, hooks); err != ErrRecoveryRequired {
			t.Fatalf("recovery result=%v", err)
		}
		select {
		case <-f.db.RecoveryFailure():
		default:
			t.Fatal("owner not notified")
		}
		if _, err := f.db.AdminBySession(t.Context(), f.old); err == nil {
			t.Fatal("failed recovery still authenticates")
		}
		if err := f.db.Do(t.Context(), func(*sql.Tx) error { return nil }); err != ErrRecoveryRequired {
			t.Fatal("failed recovery still writes")
		}
		originals, _ := filepath.Glob(filepath.Join(f.dir, ".restore-*", "original.db"))
		if len(originals) != 1 {
			t.Fatal("recovery copy was not retained")
		}
	})
}
func TestRestoreRejectsActualSchemaTampering(t *testing.T) {
	for _, mutation := range []string{
		`CREATE TABLE unexpected(value TEXT)`,
		`CREATE INDEX unexpected ON administrators(username)`,
		`CREATE TRIGGER undo_revocation AFTER UPDATE OF revoked ON admin_sessions WHEN NEW.revoked=1 BEGIN UPDATE admin_sessions SET revoked=0 WHERE id=NEW.id; END`,
		`DROP TRIGGER audit_retention_insert; CREATE TRIGGER audit_retention_insert AFTER INSERT ON audit_events BEGIN SELECT 1; END`,
		`DROP INDEX audit_events_created_at; CREATE INDEX audit_events_created_at ON audit_events(created_at DESC)`,
	} {
		t.Run(mutation[:12], func(t *testing.T) {
			f := newRestoreFixture(t)
			b, err := sql.Open("sqlite", filepath.Join(f.dir, "backups", f.backup))
			if err != nil {
				t.Fatal(err)
			}
			_, err = b.Exec(mutation)
			b.Close()
			if err != nil {
				t.Fatal(err)
			}
			if err = f.db.RestoreFile(t.Context(), filepath.Join(f.dir, "backups"), f.backup); err == nil {
				t.Fatal("tampered schema accepted")
			}
			f.unchanged(t)
		})
	}
}
func TestRestoreProcessInterruptionLeavesConsistentDatabase(t *testing.T) {
	if phase := os.Getenv("WEROXY_TEST_RESTORE_PHASE"); phase != "" {
		dir := os.Getenv("WEROXY_TEST_RESTORE_DIR")
		db, err := Open(filepath.Join(dir, "state.db"), DefaultQueue)
		if err != nil {
			t.Fatal(err)
		}
		err = db.restoreFile(t.Context(), filepath.Join(dir, "backups"), os.Getenv("WEROXY_TEST_RESTORE_NAME"), &restoreHooks{phase: func(at string) error {
			if at == phase {
				os.Exit(42)
			}
			return nil
		}})
		t.Fatalf("process interruption hook not reached: %v", err)
	}
	for _, phase := range []string{"before_apply", "during_apply", "after_apply"} {
		t.Run(phase, func(t *testing.T) {
			f := newRestoreFixture(t)
			f.db.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestRestoreProcessInterruptionLeavesConsistentDatabase$")
			cmd.Env = append(os.Environ(), "WEROXY_TEST_RESTORE_PHASE="+phase, "WEROXY_TEST_RESTORE_DIR="+f.dir, "WEROXY_TEST_RESTORE_NAME="+f.backup)
			err := cmd.Run()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 42 {
				t.Fatalf("interruption=%v", err)
			}
			f.db, err = Open(filepath.Join(f.dir, "state.db"), DefaultQueue)
			if err != nil {
				t.Fatal(err)
			}
			defer f.db.Close()
			if phase == "before_apply" || phase == "during_apply" {
				f.unchanged(t)
			} else {
				f.restored(t)
			}
		})
	}
}

func TestInterruptedRestoreScratchHasBudget(t *testing.T) {
	f := newRestoreFixture(t)
	for i := 0; i < backupKeep; i++ {
		if err := os.Mkdir(filepath.Join(f.dir, fmt.Sprint(".restore-interrupted-", i)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.db.RestoreFile(t.Context(), filepath.Join(f.dir, "backups"), f.backup); err != ErrBackupBudget {
		t.Fatalf("unbounded interrupted scratch: %v", err)
	}
	f.unchanged(t)
}

func TestOpenRefusesPreviouslyInjectedTrigger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path, DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	altered, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = altered.Exec(`CREATE TRIGGER undo_revocation AFTER UPDATE OF revoked ON admin_sessions WHEN NEW.revoked=1 BEGIN UPDATE admin_sessions SET revoked=0 WHERE id=NEW.id; END`)
	altered.Close()
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path, DefaultQueue); err == nil {
		opened.Close()
		t.Fatal("restart activated injected schema")
	}
}
