package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

var ErrRevisionConflict = errors.New("config revision conflict")
var ErrConfigDomain = errors.New("invalid config domain")
var ErrOperationID = errors.New("invalid operation id")

type Revision struct {
	Domain          string `json:"domain"`
	DesiredRevision int64  `json:"desired_revision"`
	AppliedRevision int64  `json:"applied_revision"`
	FailureReason   string `json:"failure_reason"`
	UpdatedAt       string `json:"updated_at"`
}

type MutationResult struct {
	Revision
	Duplicate         bool  `json:"duplicate"`
	OperationRevision int64 `json:"operation_revision"`
}

type configTxKey struct{}

func validConfigDomain(domain string) bool {
	switch domain {
	case "listener", "policy", "credential", "ui", "storage", "logging":
		return true
	default:
		return false
	}
}

// ConfigRevision returns the persisted desired and runtime-applied positions.
func (db *DB) ConfigRevision(ctx context.Context, domain string) (Revision, error) {
	if !validConfigDomain(domain) {
		return Revision{}, ErrConfigDomain
	}
	var out Revision
	err := db.QueryRow(ctx, `SELECT domain, desired_revision, applied_revision, failure_reason, updated_at FROM config_revisions WHERE domain = ?`, domain).
		Scan(&out.Domain, &out.DesiredRevision, &out.AppliedRevision, &out.FailureReason, &out.UpdatedAt)
	return out, err
}

// ConfigRevisions returns the five independent domains in stable order.
func (db *DB) ConfigRevisions(ctx context.Context) ([]Revision, error) {
	rows, err := db.QueryRows(ctx, `SELECT domain, desired_revision, applied_revision, failure_reason, updated_at FROM config_revisions ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Revision, 0, 5)
	for rows.Next() {
		var item Revision
		if err := rows.Scan(&item.Domain, &item.DesiredRevision, &item.AppliedRevision, &item.FailureReason, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// MutateConfig performs one existing storage mutation and its revision update
// inside the same writer transaction. fn must use DB methods with the supplied
// context; those methods reuse this transaction through DB.Do.
func (db *DB) MutateConfig(ctx context.Context, domain string, expected int64, operationID, requestHash string, fn func(context.Context) error) (MutationResult, error) {
	if !validConfigDomain(domain) {
		return MutationResult{}, ErrConfigDomain
	}
	if expected < 0 || fn == nil {
		return MutationResult{}, ErrRevisionConflict
	}
	if len(operationID) > 128 || strings.ContainsAny(operationID, "\x00\r\n") || (operationID != "" && len(requestHash) != 64) {
		return MutationResult{}, ErrOperationID
	}
	var out MutationResult
	err := db.Do(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT domain, desired_revision, applied_revision, failure_reason, updated_at FROM config_revisions WHERE domain = ?`, domain).
			Scan(&out.Domain, &out.DesiredRevision, &out.AppliedRevision, &out.FailureReason, &out.UpdatedAt); err != nil {
			return err
		}
		if operationID != "" {
			var previous int64
			var previousHash string
			err := tx.QueryRowContext(ctx, `SELECT revision, request_hash FROM config_operations WHERE domain = ? AND operation_id = ?`, domain, operationID).Scan(&previous, &previousHash)
			if err == nil {
				if previousHash != requestHash {
					return ErrOperationID
				}
				out.Duplicate, out.OperationRevision = true, previous
				return nil
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if out.DesiredRevision != expected {
			return ErrRevisionConflict
		}
		if err := fn(context.WithValue(ctx, configTxKey{}, tx)); err != nil {
			return err
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		out.DesiredRevision++
		out.OperationRevision = out.DesiredRevision
		out.FailureReason = ""
		out.UpdatedAt = now
		if domain == "ui" {
			out.AppliedRevision = out.DesiredRevision
		}
		if _, err := tx.ExecContext(ctx, `UPDATE config_revisions SET desired_revision = ?, applied_revision = ?, failure_reason = '', updated_at = ? WHERE domain = ?`, out.DesiredRevision, out.AppliedRevision, now, domain); err != nil {
			return err
		}
		if operationID != "" {
			if _, err := tx.ExecContext(ctx, `INSERT INTO config_operations(domain, operation_id, revision, request_hash, created_at) VALUES (?, ?, ?, ?, ?)`, domain, operationID, out.DesiredRevision, requestHash, now); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM config_operations WHERE created_at < ?`, time.Now().UTC().Add(-7*24*time.Hour).Format(time.RFC3339Nano)); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM config_operations WHERE rowid IN (
				SELECT rowid FROM config_operations ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET 4096)`); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// BumpRelatedRevision records a domain changed by the same configuration
// transaction. Only a MutateConfig callback may call this method.
func (db *DB) BumpRelatedRevision(ctx context.Context, domain string) error {
	if !validConfigDomain(domain) || domain == "ui" {
		return ErrConfigDomain
	}
	tx, ok := ctx.Value(configTxKey{}).(*sql.Tx)
	if !ok {
		return ErrConfigDomain
	}
	result, err := tx.ExecContext(ctx, `UPDATE config_revisions SET desired_revision = desired_revision + 1, failure_reason = '', updated_at = ? WHERE domain = ?`, time.Now().UTC().Format(time.RFC3339Nano), domain)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConfigDomain
	}
	return nil
}

// MarkConfigApplied confirms that a specific desired snapshot is active.
func (db *DB) MarkConfigApplied(ctx context.Context, domain string, revision int64) error {
	if !validConfigDomain(domain) || revision < 0 {
		return ErrConfigDomain
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE config_revisions SET applied_revision = ?, failure_reason = '', updated_at = ? WHERE domain = ? AND desired_revision >= ? AND applied_revision < ?`,
			revision, time.Now().UTC().Format(time.RFC3339Nano), domain, revision, revision)
		return err
	})
}

// MarkConfigFailed records an apply error without advancing the active revision.
func (db *DB) MarkConfigFailed(ctx context.Context, domain string, revision int64, reason string) error {
	if !validConfigDomain(domain) || revision < 0 {
		return ErrConfigDomain
	}
	if len(reason) > 160 {
		reason = reason[:160]
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE config_revisions SET failure_reason = ?, updated_at = ? WHERE domain = ? AND desired_revision = ?`,
			reason, time.Now().UTC().Format(time.RFC3339Nano), domain, revision)
		return err
	})
}
