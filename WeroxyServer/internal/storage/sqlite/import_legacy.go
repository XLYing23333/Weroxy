package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"weroxy/server/internal/ports"
)

// LegacyImport is one source client and its original public port mappings.
// The supplied MAC is computed outside storage with the server HMAC secret.
type LegacyImport struct {
	Name        string
	Key         []byte
	MAC         []byte
	SourceIndex int
	Forwards    []LegacyImportForward
}

type LegacyImportForward struct {
	Listen, Target   string
	SourceIndex      int
	AllowOutsidePool bool
}
type ImportIssue struct {
	Device, Listen, Code      string
	ClientIndex, MappingIndex int
	Required, Capacity        int
}

var errPreviewRollback = errors.New("import preview rollback")
var ErrImportConflicts = errors.New("legacy import has conflicts")

// ImportLegacy validates every row in one transaction. A preview always rolls
// back; apply commits only when every row has passed the same checks.
func (db *DB) ImportLegacy(ctx context.Context, items []LegacyImport, apply bool) ([]ImportIssue, error) {
	var issues []ImportIssue
	err := db.Do(ctx, func(tx *sql.Tx) error {
		issues = nil
		now := time.Now().UTC().Format(time.RFC3339Nano)
		for _, device := range items {
			var nameCount, keyCount int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM legacy_devices WHERE name = ?`, device.Name).Scan(&nameCount); err != nil {
				return err
			}
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM legacy_devices WHERE key_mac = ?`, device.MAC).Scan(&keyCount); err != nil {
				return err
			}
			if nameCount != 0 {
				issues = append(issues, ImportIssue{Device: device.Name, ClientIndex: device.SourceIndex, Code: "duplicate_name"})
			}
			if keyCount != 0 {
				issues = append(issues, ImportIssue{Device: device.Name, ClientIndex: device.SourceIndex, Code: "duplicate_key"})
			}
			if nameCount != 0 || keyCount != 0 {
				continue
			}
			ciphertext, err := db.sealKeyBytes(device.Name, device.Key)
			if err != nil {
				return err
			}
			result, err := insertEntity(ctx, tx, `INSERT INTO legacy_devices(name, key_mac, client_key, created_at) VALUES (?, ?, ?, ?)`, device.Name, device.MAC, ciphertext, now)
			if err != nil {
				return err
			}
			id, err := result.LastInsertId()
			if err != nil {
				return err
			}
			for _, forward := range device.Forwards {
				allowed, err := forwardPortAllowed(ctx, tx, forward.Listen)
				if err != nil {
					return err
				}
				if !allowed && !forward.AllowOutsidePool {
					issues = append(issues, ImportIssue{Device: device.Name, Listen: forward.Listen, ClientIndex: device.SourceIndex, MappingIndex: forward.SourceIndex, Code: "outside_forward_pool"})
					continue
				}
				if err := conflictListen(ctx, tx, forward.Listen); err != nil {
					if errors.Is(err, ErrPortConflict) || errors.Is(err, ErrPortRange) {
						issues = append(issues, ImportIssue{Device: device.Name, Listen: forward.Listen, ClientIndex: device.SourceIndex, MappingIndex: forward.SourceIndex, Code: "port_conflict"})
						continue
					}
					return err
				}
				if !allowed {
					if _, err := tx.ExecContext(ctx, `INSERT INTO forward_port_exceptions(listen, origin, created_at) VALUES (?, 'lanproxy_import', ?) ON CONFLICT(listen) DO NOTHING`, forward.Listen, now); err != nil {
						return err
					}
				}
				if _, err := insertEntity(ctx, tx, `INSERT INTO legacy_forwards(device_id, listen, target, created_at) VALUES (?, ?, ?, ?)`, id, forward.Listen, forward.Target, now); err != nil {
					return fmt.Errorf("legacy forward insert: %w", err)
				}
			}
		}
		var forwardCapacity int
		if err := tx.QueryRowContext(ctx, `SELECT forward_last-forward_first+1 FROM port_settings WHERE id = 1`).Scan(&forwardCapacity); err != nil {
			return err
		}
		requiredPorts, err := distinctForwardPorts(ctx, tx)
		if err != nil {
			return err
		}
		if forwardCapacity < 1 || requiredPorts > forwardCapacity {
			issues = append(issues, ImportIssue{Code: "forward_capacity_exceeded", Required: requiredPorts, Capacity: forwardCapacity})
		}
		if !apply {
			return errPreviewRollback
		}
		if len(issues) != 0 {
			return ErrImportConflicts
		}
		if len(items) > 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE config_revisions SET desired_revision = desired_revision + 1, failure_reason = '', updated_at = ? WHERE domain IN ('listener', 'credential')`, now); err != nil {
				return err
			}
			if err := insertAudit(ctx, tx, "lanproxy_import", "success", fmt.Sprintf("devices=%d ports=%d", len(items), requiredPorts), now); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, errPreviewRollback) {
		return issues, nil
	}
	return issues, err
}

// distinctForwardPorts counts public port numbers, not Forward rows: two
// non-overlapping bind IPs can legitimately use the same numeric port.
func distinctForwardPorts(ctx context.Context, tx *sql.Tx) (int, error) {
	seen := map[int]struct{}{}
	for _, query := range []string{
		`SELECT listen FROM legacy_forwards`,
		`SELECT listen FROM weroxy_forwards WHERE enabled = 1`,
	} {
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return 0, err
		}
		for rows.Next() {
			var listen string
			if err := rows.Scan(&listen); err != nil {
				rows.Close()
				return 0, err
			}
			_, port, ok := ports.ParseHostPort(listen)
			if !ok {
				rows.Close()
				return 0, ErrPortRange
			}
			seen[port] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return 0, err
		}
		rows.Close()
	}
	return len(seen), nil
}
