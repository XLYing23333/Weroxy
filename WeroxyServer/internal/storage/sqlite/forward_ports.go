package sqlite

import (
	"context"
	"database/sql"

	"weroxy/server/internal/ports"
)

// ForwardPortAllowed is the same range check used by mutations, for previews.
func (db *DB) ForwardPortAllowed(ctx context.Context, listen string) (bool, error) {
	var allowed bool
	err := db.Do(ctx, func(tx *sql.Tx) error {
		var enabled int
		if err := tx.QueryRowContext(ctx, `SELECT enabled FROM port_settings WHERE id = 1`).Scan(&enabled); err != nil {
			return err
		}
		if enabled == 0 {
			allowed = true
			return nil
		}
		var err error
		allowed, err = forwardPortAllowed(ctx, tx, listen)
		return err
	})
	return allowed, err
}

func forwardPortAllowed(ctx context.Context, tx *sql.Tx, listen string) (bool, error) {
	_, port, ok := ports.ParseHostPort(listen)
	if !ok {
		return false, ErrPortRange
	}
	var first, last int
	if err := tx.QueryRowContext(ctx, `SELECT forward_first, forward_last FROM port_settings WHERE id = 1`).Scan(&first, &last); err != nil {
		return false, err
	}
	if port >= first && port <= last {
		return true, nil
	}
	var count int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM forward_port_exceptions WHERE listen = ?`, listen).Scan(&count)
	return count != 0, err
}
