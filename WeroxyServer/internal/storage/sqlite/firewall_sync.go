package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"
)

type FirewallSync struct {
	Enabled       bool   `json:"enabled"`
	Managed       bool   `json:"managed"`
	Generation    int64  `json:"generation"`
	Status        string `json:"status"`
	FailureReason string `json:"failure_reason"`
	UpdatedAt     string `json:"updated_at"`
}

func (db *DB) FirewallSync(ctx context.Context) (FirewallSync, error) {
	var s FirewallSync
	err := db.QueryRow(ctx, `SELECT enabled,managed,generation,status,failure_reason,updated_at FROM firewall_sync WHERE id=1`).Scan(&s.Enabled, &s.Managed, &s.Generation, &s.Status, &s.FailureReason, &s.UpdatedAt)
	return s, err
}
func (db *DB) SetFirewallSync(ctx context.Context, enabled bool) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE firewall_sync SET enabled=?,status='pending',failure_reason='' WHERE id=1`, enabled)
		if err != nil {
			return err
		}
		return insertAudit(ctx, tx, "firewall_sync_mode", "success", "", time.Now().UTC().Format(time.RFC3339Nano))
	})
}
func (db *DB) ReserveFirewallGeneration(ctx context.Context, agent uint64) (int64, error) {
	var next int64
	if agent >= math.MaxInt64 {
		return 0, errors.New("firewall generation exhausted")
	}
	err := db.Do(ctx, func(tx *sql.Tx) error {
		var current int64
		if err := tx.QueryRowContext(ctx, `SELECT generation FROM firewall_sync WHERE id=1`).Scan(&current); err != nil {
			return err
		}
		if current >= math.MaxInt64 {
			return errors.New("firewall generation exhausted")
		}
		next = current + 1
		if next <= int64(agent) {
			next = int64(agent) + 1
		}
		_, err := tx.ExecContext(ctx, `UPDATE firewall_sync SET generation=?,managed=1,status='pending' WHERE id=1`, next)
		return err
	})
	return next, err
}
func (db *DB) RecordFirewallSync(ctx context.Context, status, reason string, managed bool) error {
	return db.DoLow(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE firewall_sync SET status=?,failure_reason=?,managed=?,updated_at=? WHERE id=1 AND (status<>? OR failure_reason<>? OR managed<>?)`, status, reason, managed, time.Now().UTC().Format(time.RFC3339Nano), status, reason, managed)
		return err
	})
}
