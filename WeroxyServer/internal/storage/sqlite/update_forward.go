package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"weroxy/server/internal/ports"
)

// UpdateLegacyForward changes a stored mapping atomically. A failed conflict
// check leaves the original row in place.
func (db *DB) UpdateLegacyForward(ctx context.Context, device, previous, listen, target string) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		var id int64
		err := tx.QueryRowContext(ctx, `SELECT f.id FROM legacy_forwards f JOIN legacy_devices d ON d.id = f.device_id WHERE d.name = ? AND f.listen = ?`, device, previous).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrLegacyNotFound
		}
		if err != nil {
			return err
		}
		if err := conflictListenExcept(ctx, tx, listen, previous); err != nil {
			return err
		}
		if listen != previous {
			if err := forwardInPool(ctx, tx, listen, false); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE legacy_forwards SET listen = ?, target = ? WHERE id = ?`, listen, target, id)
		return err
	})
}

// UpdateWeroxyForward updates one row and recomputes assignments in the same
// transaction, so a quota rejection rolls the entire edit back.
func (db *DB) UpdateWeroxyForward(ctx context.Context, device, previous, listen, target, mode string, minPorts, preferred, maxPorts int, manual ...[]int) error {
	if mode == "" {
		mode = ports.Shared
	}
	if minPorts == 0 && preferred == 0 && maxPorts == 0 {
		minPorts, preferred, maxPorts = 1, 1, 4
	}
	if mode != ports.Shared && mode != ports.Exclusive || !ports.ValidRange(minPorts, preferred, maxPorts) {
		return ErrPortRange
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		var id int64
		err := tx.QueryRowContext(ctx, `SELECT f.id FROM weroxy_forwards f JOIN weroxy_devices d ON d.id = f.device_id WHERE d.name = ? AND f.listen = ? AND d.revoked = 0`, device, previous).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrWeroxyNotFound
		}
		if err != nil {
			return err
		}
		if err := conflictListenExcept(ctx, tx, listen, previous); err != nil {
			return err
		}
		if listen != previous {
			if err := forwardInPool(ctx, tx, listen, false); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE weroxy_forwards SET listen = ?, target = ?, sharing_mode = ?, min_ports = ?, preferred_ports = ?, max_ports = ? WHERE id = ?`, listen, target, mode, minPorts, preferred, maxPorts, id)
		if err != nil {
			return err
		}
		if len(manual) > 0 {
			if err := setManualDataPortsTx(ctx, tx, device, listen, manual[0]); err != nil {
				return err
			}
		}
		return allocateTx(ctx, tx, id)
	})
}

// ForwardExists verifies a preview's previous address belongs to the device.
func (db *DB) ForwardExists(ctx context.Context, protocol, device, listen string) (bool, error) {
	var query string
	switch protocol {
	case "legacy":
		query = `SELECT COUNT(*) FROM legacy_forwards f JOIN legacy_devices d ON d.id = f.device_id WHERE d.name = ? AND f.listen = ?`
	case "weroxy":
		query = `SELECT COUNT(*) FROM weroxy_forwards f JOIN weroxy_devices d ON d.id = f.device_id WHERE d.name = ? AND f.listen = ?`
	default:
		return false, ErrPortRange
	}
	var count int
	if err := db.QueryRow(ctx, query, device, listen).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

func conflictListenExcept(ctx context.Context, tx *sql.Tx, listen, previous string) error {
	host, port, ok := ports.ParseHostPort(listen)
	if !ok {
		return ErrPortRange
	}
	oldHost, oldPort, ok := ports.ParseHostPort(previous)
	if !ok {
		return ErrPortRange
	}
	claims, err := claimsTx(ctx, tx)
	if err != nil {
		return err
	}
	filtered := make([]ports.Endpoint, 0, len(claims))
	skipped := false
	for _, claim := range claims {
		if !skipped && claim.Role == "forward" && claim.Host == oldHost && claim.Port == oldPort {
			skipped = true
			continue
		}
		filtered = append(filtered, claim)
	}
	if !skipped {
		return ErrPortConflict
	}
	if _, hit := ports.FirstConflict(filtered, ports.Endpoint{Host: host, Port: port, Role: "forward"}); hit {
		return ErrPortConflict
	}
	return nil
}
