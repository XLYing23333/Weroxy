package sqlite

import (
	"context"
	"database/sql"
	"time"
)

// Explicit audit-only cleanup, bounded by batch size; never called by log rotation.
func (db *DB) PruneAudits(ctx context.Context, now time.Time) error {
	err := db.DoLow(ctx, func(tx *sql.Tx) error {
		cutoff := now.Add(-180 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
		_, err := tx.ExecContext(ctx, `UPDATE audit_retention SET last_reason='age_policy' WHERE id=1 AND EXISTS(SELECT 1 FROM audit_events WHERE created_at < ?)`, cutoff)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events WHERE created_at < ? ORDER BY created_at,id LIMIT 2048)`, cutoff)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE audit_retention SET last_run=?,failure_reason='' WHERE id=1`, now.UTC().Format(time.RFC3339Nano))
		return err
	})
	if err != nil {
		recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = db.DoLow(recordCtx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(recordCtx, `UPDATE audit_retention SET last_run=?,failure_reason='audit_cleanup_failed' WHERE id=1`, now.UTC().Format(time.RFC3339Nano))
			return err
		})
	}
	return err
}
