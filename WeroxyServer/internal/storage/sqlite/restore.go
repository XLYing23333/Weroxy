package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrRecoveryRequired = errors.New("database restoration requires offline recovery")

// Internal fault injection has no Web/CLI configuration path.
type restoreHooks struct{ phase func(string) error }

func (h *restoreHooks) call(phase string) error {
	if h != nil && h.phase != nil {
		return h.phase(phase)
	}
	return nil
}

func (db *DB) RestoreFile(ctx context.Context, dir, name string) error {
	return db.restoreFile(ctx, dir, name, nil)
}

// The candidate is immutable to other users, validated and quarantined before
// it can reach the live SQLite handle. The writer serializes replacement and
// rollback; once admitted, the callback finishes before scratch files disappear.
func (db *DB) restoreFile(ctx context.Context, dir, name string, hooks *restoreHooks) error {
	if db.recoveryRequired.Load() {
		return ErrRecoveryRequired
	}
	path, err := backupPath(dir, name)
	if err != nil {
		return err
	}
	if err := restoreScratchBudget(filepath.Dir(db.path)); err != nil {
		return err
	}
	available, err := diskAvailable(filepath.Dir(db.path))
	if err != nil || available < uint64(2*backupSingleBytes)+diskPauseBytes {
		return ErrBackupBudget
	}
	scratch, err := os.MkdirTemp(filepath.Dir(db.path), ".restore-")
	if err != nil {
		return err
	}
	defer func() {
		if !db.recoveryRequired.Load() {
			_ = os.RemoveAll(scratch)
		}
	}()
	candidate := filepath.Join(scratch, "candidate.db")
	if err := copyRestoreCandidate(ctx, path, candidate); err != nil {
		return err
	}
	if err := hooks.call("copied"); err != nil {
		return err
	}
	if err := integrity(candidate); err != nil {
		return err
	}
	if err := db.checkBackupSchema(ctx, candidate); err != nil {
		return err
	}
	if err := backupSealMatches(candidate, db.seal); err != nil {
		return err
	}
	if err := hooks.call("validated"); err != nil {
		return err
	}
	if err := prepareRestore(ctx, candidate); err != nil {
		return err
	}
	if err := hooks.call("quarantined"); err != nil {
		return err
	}

	// Queue cancellation is checked before touching the database. During the
	// critical phase, caller cancellation cannot skip isolation or rollback.
	return db.WithConn(context.WithoutCancel(ctx), func(conn *sql.Conn) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		critical, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if err := mergeRestoreWatermarks(critical, conn, candidate); err != nil {
			return err
		}
		original := filepath.Join(scratch, "original.db")
		if err := backupToContext(critical, conn, original); err != nil {
			return err
		}
		if err := integrity(original); err != nil {
			return err
		}
		if err := hooks.call("before_apply"); err != nil {
			return err
		}
		applyErr := restoreSteps(critical, conn, candidate, func() error { return hooks.call("during_apply") })
		if applyErr == nil {
			applyErr = hooks.call("after_apply")
		}
		if applyErr == nil {
			applyErr = integrity(db.path)
		}
		if applyErr == nil {
			return nil
		}
		rollback, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer stop()
		rollbackErr := hooks.call("before_rollback")
		if rollbackErr == nil {
			rollbackErr = restoreFrom(rollback, conn, original)
		}
		if rollbackErr == nil {
			rollbackErr = integrity(db.path)
		}
		if rollbackErr != nil {
			db.requireRecovery()
			return ErrRecoveryRequired
		}
		return applyErr
	})
}

// Interrupted processes may leave private recovery copies. Preserve them for
// offline recovery, but never let repeated interruptions grow scratch without a budget.
func restoreScratchBudget(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	count := 0
	var total int64
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".restore-") {
			continue
		}
		count++
		if count >= backupKeep || !entry.IsDir() {
			return ErrBackupBudget
		}
		err := filepath.WalkDir(filepath.Join(dir, entry.Name()), func(path string, item fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if item.IsDir() {
				return nil
			}
			info, err := item.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return ErrBackupBudget
			}
			total += info.Size()
			if total+2*backupSingleBytes > backupPeakBytes {
				return ErrBackupBudget
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func copyRestoreCandidate(ctx context.Context, source, dest string) error {
	before, err := os.Lstat(source)
	if err != nil || !before.Mode().IsRegular() {
		return errors.New("invalid restore file")
	}
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return errors.New("restore file changed")
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	reader := &restoreReader{ctx: ctx, reader: io.LimitReader(f, backupSingleBytes+1)}
	n, err := io.Copy(out, reader)
	if err != nil {
		return err
	}
	if n != opened.Size() || n > backupSingleBytes {
		return ErrBackupBudget
	}
	return out.Sync()
}

type restoreReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *restoreReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func prepareRestore(ctx context.Context, path string) error {
	name, err := dsn(path)
	if err != nil {
		return err
	}
	prepared, err := sql.Open("sqlite", name)
	if err != nil {
		return err
	}
	defer prepared.Close()
	prepared.SetMaxOpenConns(1)
	version, err := validatedBackupVersion(ctx, prepared)
	if err != nil {
		return err
	}
	scripts, err := migrationScripts()
	if err != nil {
		return err
	}
	tx, err := prepared.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, script := range scripts {
		if script.version <= version {
			continue
		}
		if _, err := tx.ExecContext(ctx, script.body); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at,checksum) VALUES(?,?,?)`, script.version, time.Now().UTC().Format(time.RFC3339Nano), script.sum); err != nil {
			return err
		}
	}
	for _, query := range []string{
		`DELETE FROM admin_sessions`, `UPDATE quick_tokens SET revoked=1`,
		`UPDATE weroxy_devices SET revoked=1,paused=1`, `UPDATE legacy_devices SET paused=1`,
		`UPDATE firewall_sync SET enabled=0,managed=1,status='pending',failure_reason='restore_cleanup_required' WHERE id=1`,
		`DELETE FROM config_operations`,
		`UPDATE connection_details SET closed_at=last_at,close_reason='restored' WHERE closed_at IS NULL`,
	} {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

// Preserve live ID ceilings across a restore and force every reconciler to
// observe the isolated credentials/configuration even for an equal revision.
func mergeRestoreWatermarks(ctx context.Context, live *sql.Conn, path string) error {
	read := func(query string) (map[string]int64, error) {
		rows, err := live.QueryContext(ctx, query)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[string]int64{}
		for rows.Next() {
			var key string
			var value int64
			if err := rows.Scan(&key, &value); err != nil {
				return nil, err
			}
			out[key] = value
		}
		return out, rows.Err()
	}
	revisions, err := read(`SELECT domain,desired_revision FROM config_revisions`)
	if err != nil {
		return err
	}
	ids, err := read(`SELECT entity,last_id FROM entity_id_sequences`)
	if err != nil {
		return err
	}
	name, err := dsn(path)
	if err != nil {
		return err
	}
	prepared, err := sql.Open("sqlite", name)
	if err != nil {
		return err
	}
	defer prepared.Close()
	tx, err := prepared.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for domain, revision := range revisions {
		var archived int64
		if err := tx.QueryRowContext(ctx, `SELECT desired_revision FROM config_revisions WHERE domain=?`, domain).Scan(&archived); err != nil {
			return err
		}
		if archived > revision {
			revision = archived
		}
		if revision == math.MaxInt64 {
			return errors.New("restore revision exhausted")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE config_revisions SET desired_revision=?,applied_revision=0,failure_reason='',updated_at=? WHERE domain=?`, revision+1, time.Now().UTC().Format(time.RFC3339Nano), domain); err != nil {
			return err
		}
	}
	for entity, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE entity_id_sequences SET last_id=max(last_id,?) WHERE entity=?`, id, entity); err != nil {
			return err
		}
	}
	return tx.Commit()
}
