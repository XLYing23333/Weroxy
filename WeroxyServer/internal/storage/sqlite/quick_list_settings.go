package sqlite

import (
	"context"
	"database/sql"
)

func (db *DB) QuickListEnabled(ctx context.Context) (bool, error) {
	var enabled int
	err := db.QueryRow(ctx, `SELECT enabled FROM quick_list_settings WHERE id=1`).Scan(&enabled)
	return enabled != 0, err
}

func (db *DB) SetQuickListEnabled(ctx context.Context, enabled bool) error {
	value := 0
	if enabled {
		value = 1
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE quick_list_settings SET enabled=? WHERE id=1`, value)
		return err
	})
}
