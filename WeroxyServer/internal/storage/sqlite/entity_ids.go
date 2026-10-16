package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// insertEntity accepts only internal INSERT templates, never SQL from a request.
// Sequence advancement and insertion share the caller's configuration transaction.
func insertEntity(ctx context.Context, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	query = strings.TrimSpace(query)
	const prefix = "INSERT INTO "
	column := strings.IndexByte(query, '(')
	if !strings.HasPrefix(query, prefix) || column <= len(prefix) {
		return nil, errors.New("invalid entity insert")
	}
	table := strings.TrimSpace(query[len(prefix):column])
	switch table {
	case "legacy_devices", "legacy_forwards", "weroxy_devices", "weroxy_forwards":
	default:
		return nil, errors.New("invalid entity table")
	}
	var id int64
	if err := tx.QueryRowContext(ctx, `UPDATE entity_id_sequences SET last_id=last_id+1 WHERE entity=? AND last_id<9223372036854775807 RETURNING last_id`, table).Scan(&id); err != nil {
		return nil, err
	}
	query = query[:column+1] + "id," + query[column+1:]
	if !strings.Contains(query, "VALUES (") {
		return nil, errors.New("invalid entity values")
	}
	query = strings.Replace(query, "VALUES (", "VALUES (?, ", 1)
	return tx.ExecContext(ctx, query, append([]any{id}, args...)...)
}
