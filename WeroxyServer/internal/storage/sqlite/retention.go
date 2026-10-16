package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Success metadata commits with the deletions. Failed transactions record zero
// committed removals in a separate bounded attempt, never a false success.
func (db *DB) runRetention(ctx context.Context, task string, now time.Time, fn func(*sql.Tx) (int64, error)) error {
	err := db.DoLow(ctx, func(tx *sql.Tx) error {
		count, err := fn(tx)
		if err != nil {
			return err
		}
		return db.saveRetention(ctx, tx, task, now, count, "")
	})
	if err == nil {
		return nil
	}
	reason := "cleanup_failed"
	if errors.Is(err, ErrQueueFull) {
		reason = "queue_full"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		reason = "cleanup_timeout"
	}
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	_ = db.DoLow(recordCtx, func(tx *sql.Tx) error { return db.saveRetention(recordCtx, tx, task, now, 0, reason) })
	return err
}
func (db *DB) saveRetention(ctx context.Context, tx *sql.Tx, task string, now time.Time, count int64, reason string) error {
	_, err := tx.ExecContext(ctx, `UPDATE retention_status SET last_run=?, next_run=?, deleted_rows=?, failure_reason=? WHERE task=?`, now.UTC().Format(time.RFC3339Nano), now.Add(db.retentionInterval()).UTC().Format(time.RFC3339Nano), count, reason, task)
	return err
}
func (db *DB) retentionInterval() time.Duration {
	if !db.TelemetryAllowed() {
		return time.Minute
	}
	return time.Hour
}
