package sqlite

import (
	"context"
	"database/sql"
	"weroxy/server/internal/ports"
)

type listenerQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func listenerClaims(ctx context.Context, query listenerQuery) ([]ports.Endpoint, error) {
	rows, err := query.QueryContext(ctx, `SELECT host, port, role FROM listener_reservations ORDER BY role`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.Endpoint, 0, 4)
	for rows.Next() {
		var item ports.Endpoint
		if err := rows.Scan(&item.Host, &item.Port, &item.Role); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ListenerReservations are configuration claims, not socket health or host publication.
func (db *DB) ListenerReservations(ctx context.Context) ([]ports.Endpoint, error) {
	return listenerClaims(ctx, db.sql)
}
func saveListenerClaims(ctx context.Context, tx *sql.Tx, items []ports.Endpoint) error {
	if len(items) > 4 {
		return ErrPortRange
	}
	claims, err := claimsTx(ctx, tx)
	if err != nil {
		return err
	}
	var occupied, valid []ports.Endpoint
	for _, claim := range claims {
		if claim.Role == "forward" || claim.Role == "data" {
			occupied = append(occupied, claim)
		}
	}
	seen := map[string]bool{}
	for _, entry := range items {
		switch entry.Role {
		case "legacy", "weroxy-control", "weroxy-data", "web":
		default:
			return ErrPortRange
		}
		if entry.Port == 0 {
			continue
		} // ephemeral binds registered after Listen
		if entry.Port < 1 || entry.Port > 65535 || entry.Host == "" || seen[entry.Role] {
			return ErrPortRange
		}
		seen[entry.Role] = true
		if _, hit := ports.FirstConflict(occupied, entry); hit {
			return ErrPortConflict
		}
		if _, hit := ports.FirstConflict(valid, entry); hit {
			return ErrPortConflict
		}
		valid = append(valid, entry)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM listener_reservations`); err != nil {
		return err
	}
	for _, entry := range valid {
		if _, err := tx.ExecContext(ctx, `INSERT INTO listener_reservations(role, host, port) VALUES (?, ?, ?)`, entry.Role, entry.Host, entry.Port); err != nil {
			return err
		}
	}
	return nil
}
func (db *DB) SetListenerReservations(ctx context.Context, items []ports.Endpoint) error {
	return db.Do(ctx, func(tx *sql.Tx) error { return saveListenerClaims(ctx, tx, items) })
}

// RegisterListener replaces a planned entrance with its actual bind.
func (db *DB) RegisterListener(ctx context.Context, role, listen string) error {
	host, port, ok := ports.ParseHostPort(listen)
	if !ok {
		return ErrPortRange
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		current, err := listenerClaims(ctx, tx)
		if err != nil {
			return err
		}
		next := make([]ports.Endpoint, 0, 4)
		for _, entry := range current {
			if entry.Role != role {
				next = append(next, entry)
			}
		}
		next = append(next, ports.Endpoint{Host: host, Port: port, Role: role})
		return saveListenerClaims(ctx, tx, next)
	})
}
