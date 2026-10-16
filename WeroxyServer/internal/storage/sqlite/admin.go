package sqlite

import (
	"context"
	"database/sql"
	"time"

	"weroxy/server/internal/auth"
)

// Audit is one stored administrator action.
type Audit struct {
	Action  string
	Outcome string
	Detail  string
}

// HasAdmin reports whether any administrator row exists.
func (db *DB) HasAdmin(ctx context.Context) (bool, error) {
	var n int
	err := db.QueryRow(ctx, `SELECT COUNT(*) FROM administrators`).Scan(&n)
	return n > 0, err
}

// Bootstrap creates the first administrator. A second call does not change the hash.
func (db *DB) Bootstrap(ctx context.Context, hasher auth.PasswordHasher, username string, password []byte) error {
	if !auth.ValidUsername(username) {
		return auth.ErrUsername
	}
	if err := auth.ValidatePassword(password); err != nil {
		_ = db.record(ctx, "bootstrap", "failure", "password rejected")
		return err
	}
	exists, err := db.HasAdmin(ctx)
	if err != nil {
		return err
	}
	if exists {
		if err := db.record(ctx, "bootstrap", "failure", "administrator already exists"); err != nil {
			return err
		}
		return ErrAdminExists
	}
	phc, err := hasher.Hash(password)
	if err != nil {
		_ = db.record(ctx, "bootstrap", "failure", "password hash rejected")
		return err
	}
	var raced bool
	err = db.Do(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM administrators`).Scan(&n); err != nil {
			return err
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if n > 0 {
			raced = true
			return insertAudit(ctx, tx, "bootstrap", "failure", "administrator already exists", now)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO administrators(username, password_phc, disabled, password_updated_at, created_at) VALUES (?, ?, 0, ?, ?)`,
			username, phc, now, now,
		); err != nil {
			return err
		}
		return insertAudit(ctx, tx, "bootstrap", "success", "username="+username, now)
	})
	if err != nil {
		return err
	}
	if raced {
		return ErrAdminExists
	}
	return nil
}

// ResetPassword replaces the hash for an existing administrator.
func (db *DB) ResetPassword(ctx context.Context, hasher auth.PasswordHasher, username string, password []byte) error {
	if !auth.ValidUsername(username) {
		return auth.ErrUsername
	}
	if err := auth.ValidatePassword(password); err != nil {
		_ = db.record(ctx, "reset_password", "failure", "password rejected")
		return err
	}
	phc, err := hasher.Hash(password)
	if err != nil {
		_ = db.record(ctx, "reset_password", "failure", "password hash rejected")
		return err
	}
	var missing bool
	err = db.Do(ctx, func(tx *sql.Tx) error {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		res, err := tx.ExecContext(ctx,
			`UPDATE administrators SET password_phc = ?, password_updated_at = ? WHERE username = ?`,
			phc, now, username,
		)
		if err != nil {
			return err
		}
		rows, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			missing = true
			return insertAudit(ctx, tx, "reset_password", "failure", "administrator not found", now)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE admin_sessions SET revoked = 1 WHERE username = ?`, username); err != nil {
			return err
		}
		return insertAudit(ctx, tx, "reset_password", "success", "username="+username, now)
	})
	if err != nil {
		return err
	}
	if missing {
		return ErrNoAdmin
	}
	return nil
}

// PasswordPHC returns the stored hash for tests and verification.
func (db *DB) PasswordPHC(ctx context.Context, username string) (string, error) {
	var phc string
	err := db.QueryRow(ctx, `SELECT password_phc FROM administrators WHERE username = ?`, username).Scan(&phc)
	return phc, err
}

// Audits returns stored audit rows in insertion order.
func (db *DB) Audits(ctx context.Context) ([]Audit, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT action, outcome, detail FROM audit_events ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Audit
	for rows.Next() {
		var item Audit
		if err := rows.Scan(&item.Action, &item.Outcome, &item.Detail); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// RecordAudit stores one audit row. Detail must not contain a password or key.
func (db *DB) RecordAudit(ctx context.Context, action, outcome, detail string) error {
	return db.record(ctx, action, outcome, detail)
}

func (db *DB) record(ctx context.Context, action, outcome, detail string) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		return insertAudit(ctx, tx, action, outcome, detail, time.Now().UTC().Format(time.RFC3339Nano))
	})
}

func insertAudit(ctx context.Context, tx *sql.Tx, action, outcome, detail, now string) error {
	action = auditText(action, 96)
	outcome = auditText(outcome, 32)
	detail = auditText(detail, 1024)
	_, err := tx.ExecContext(ctx,
		`INSERT INTO audit_events(action, outcome, detail, created_at) VALUES (?, ?, ?, ?)`,
		action, outcome, detail, now,
	)
	return err
}
