package sqlite

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"
)

// ErrSession means the management cookie is missing, expired, or revoked.
var ErrSession = errors.New("admin session")

// ErrSessionCapacity rejects a login when the persisted management session budget is full.
var ErrSessionCapacity = errors.New("admin session capacity")

// UISettings is the saved language, theme, and product defaults.
type UISettings struct {
	Locale           string
	Theme            string
	ForwardMode      string
	ForwardMin       int
	ForwardPreferred int
	ForwardMax       int
	BanAction        string
	BanCIDR          string
	GuardEnabled     bool
	GuardFindSec     int
	GuardMaxRetry    int
	GuardBanSec      int
}

// CreateAdminSession stores the digest of a session token.
func (db *DB) CreateAdminSession(ctx context.Context, username string, digest []byte, expires time.Time) error {
	// Commit bounded cleanup independently so rejected logins still free stale rows.
	if err := db.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id IN (
            SELECT id FROM admin_sessions WHERE revoked != 0 OR expires_at <= ? ORDER BY id LIMIT 2048
        )`, time.Now().UTC().Format(time.RFC3339Nano))
		return err
	}); err != nil {
		return err
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		var total, live int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_sessions`).Scan(&total); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_sessions WHERE username = ? AND revoked = 0 AND expires_at > ?`, username, now).Scan(&live); err != nil {
			return err
		}
		if total >= 4096 || live >= 32 {
			return ErrSessionCapacity
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO admin_sessions(username, token_mac, expires_at, created_at, reauthenticated_at)
			VALUES (?, ?, ?, ?, ?)`,
			username, digest, expires.UTC().Format(time.RFC3339Nano), now, now)
		if err != nil {
			return err
		}
		return insertAudit(ctx, tx, "web.login", "success", username, now)
	})
}

// AdminBySession returns the username when the digest is still valid.
func (db *DB) AdminBySession(ctx context.Context, digest []byte) (string, error) {
	var username, expires string
	var revoked int
	err := db.QueryRow(ctx, `SELECT username, expires_at, revoked FROM admin_sessions WHERE token_mac = ?`, digest).Scan(&username, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) || revoked != 0 {
		return "", ErrSession
	}
	if err != nil {
		return "", err
	}
	at, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || !time.Now().Before(at) {
		return "", ErrSession
	}
	return username, nil
}

// RevokeAdminSession marks one digest unusable.
func (db *DB) RevokeAdminSession(ctx context.Context, digest []byte) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE admin_sessions SET revoked = 1 WHERE token_mac = ?`, digest)
		return err
	})
}

// UI reads the saved language and theme.
func (db *DB) UI(ctx context.Context) (UISettings, error) {
	var item UISettings
	var guard int
	err := db.QueryRow(ctx, `SELECT locale, theme, forward_mode, forward_min, forward_preferred, forward_max, ban_action, ban_cidr, guard_enabled, guard_find_sec, guard_max_retry, guard_ban_sec FROM ui_settings WHERE id = 1`).
		Scan(&item.Locale, &item.Theme, &item.ForwardMode, &item.ForwardMin, &item.ForwardPreferred, &item.ForwardMax, &item.BanAction, &item.BanCIDR, &guard, &item.GuardFindSec, &item.GuardMaxRetry, &item.GuardBanSec)
	item.GuardEnabled = guard != 0
	return item, err
}

// SetUI stores the language and theme.
func (db *DB) SetUI(ctx context.Context, item UISettings) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		guard := 0
		if item.GuardEnabled {
			guard = 1
		}
		_, err := tx.ExecContext(ctx, `UPDATE ui_settings SET locale = ?, theme = ?, forward_mode = ?, forward_min = ?, forward_preferred = ?, forward_max = ?, ban_action = ?, ban_cidr = ?, guard_enabled = ?, guard_find_sec = ?, guard_max_retry = ?, guard_ban_sec = ? WHERE id = 1`,
			item.Locale, item.Theme, item.ForwardMode, item.ForwardMin, item.ForwardPreferred, item.ForwardMax, item.BanAction, item.BanCIDR, guard, item.GuardFindSec, item.GuardMaxRetry, item.GuardBanSec)
		return err
	})
}

// AdminSessionInfo exposes session metadata without exposing the token digest.
type AdminSessionInfo struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	Current   bool   `json:"current"`
}

// ListAdminSessions returns one bounded page of live sessions for the account.
func (db *DB) ListAdminSessions(ctx context.Context, username string, current []byte, after int64, limit int) ([]AdminSessionInfo, int64, error) {
	if after < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrSession
	}
	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := db.sql.QueryContext(queryCtx, `
		SELECT id, token_mac, created_at, expires_at
		FROM admin_sessions
		WHERE username = ? AND revoked = 0 AND expires_at > ? AND id > ?
		ORDER BY id LIMIT ?`, username, time.Now().UTC().Format(time.RFC3339Nano), after, limit+1)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]AdminSessionInfo, 0, limit)
	for rows.Next() {
		var item AdminSessionInfo
		var digest []byte
		if err := rows.Scan(&item.ID, &digest, &item.CreatedAt, &item.ExpiresAt); err != nil {
			return nil, 0, err
		}
		if len(items) == limit {
			return items, items[len(items)-1].ID, nil
		}
		item.Current = subtle.ConstantTimeCompare(current, digest) == 1
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, 0, nil
}

// RevokeAdminSessionByID revokes only a session belonging to username.
func (db *DB) RevokeAdminSessionByID(ctx context.Context, username string, id int64, current []byte) (bool, error) {
	if id < 1 {
		return false, ErrSession
	}
	var revokedCurrent bool
	err := db.Do(ctx, func(tx *sql.Tx) error {
		var digest []byte
		err := tx.QueryRowContext(ctx, `UPDATE admin_sessions SET revoked = 1 WHERE id = ? AND username = ? AND revoked = 0 RETURNING token_mac`, id, username).Scan(&digest)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSession
		}
		if err != nil {
			return err
		}
		revokedCurrent = subtle.ConstantTimeCompare(current, digest) == 1
		return insertAudit(ctx, tx, "web.session_revoke", "success", username, time.Now().UTC().Format(time.RFC3339Nano))
	})
	if err != nil {
		return false, err
	}
	return revokedCurrent, nil
}
