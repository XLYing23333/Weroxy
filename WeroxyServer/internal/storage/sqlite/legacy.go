package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	// ErrLegacyExists means the device name or client key is already stored.
	ErrLegacyExists = errors.New("legacy device exists")
	// ErrLegacyNotFound means the named device is not stored.
	ErrLegacyNotFound = errors.New("legacy device not found")
	// ErrLegacyListen means another forward already uses that listen address.
	ErrLegacyListen = errors.New("legacy listen exists")
)

// LegacyDevice is one old client. KeyMAC authenticates the client.
// ClientKey is the stored key so an administrator can copy it again.
type LegacyDevice struct {
	ID        int64
	Name      string
	KeyMAC    []byte
	ClientKey string
	Paused    bool
}

// LegacyForward is one fixed visitor listener and its LAN target.
type LegacyForward struct {
	ID       int64
	DeviceID int64
	Listen   string
	Target   string
}

// AddLegacyDevice stores the Client Key HMAC and the key itself.
func (db *DB) AddLegacyDevice(ctx context.Context, name string, keyMAC []byte, clientKey string) error {
	ciphertext, err := db.sealKey(name, clientKey)
	if err != nil {
		return err
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		var nameCount, macCount int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM legacy_devices WHERE name = ?`, name).Scan(&nameCount); err != nil {
			return err
		}
		if nameCount > 0 {
			return ErrLegacyExists
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM legacy_devices WHERE key_mac = ?`, keyMAC).Scan(&macCount); err != nil {
			return err
		}
		if macCount > 0 {
			return ErrLegacyExists
		}
		_, err := insertEntity(ctx, tx,
			`INSERT INTO legacy_devices(name, key_mac, client_key, created_at) VALUES (?, ?, ?, ?)`,
			name, keyMAC, ciphertext, time.Now().UTC().Format(time.RFC3339Nano),
		)
		return err
	})
}

// AddLegacyForward attaches one listen and target address to a device.
func (db *DB) AddLegacyForward(ctx context.Context, device, listen, target string) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		var deviceID int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM legacy_devices WHERE name = ?`, device).Scan(&deviceID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrLegacyNotFound
		}
		if err != nil {
			return err
		}
		var listenCount int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM legacy_forwards WHERE listen = ?`, listen).Scan(&listenCount); err != nil {
			return err
		}
		if listenCount > 0 {
			return ErrLegacyListen
		}
		if err := conflictListen(ctx, tx, listen); err != nil {
			return err
		}
		if err := forwardInPool(ctx, tx, listen, false); err != nil {
			return err
		}
		_, err = insertEntity(ctx, tx,
			`INSERT INTO legacy_forwards(device_id, listen, target, created_at) VALUES (?, ?, ?, ?)`,
			deviceID, listen, target, time.Now().UTC().Format(time.RFC3339Nano),
		)
		return err
	})
}

// ListLegacy reads the cached configuration. Callers keep the result in memory.
func (db *DB) ListLegacy(ctx context.Context) ([]LegacyDevice, []LegacyForward, error) {
	deviceRows, err := db.QueryRows(ctx, `SELECT id, name, key_mac, client_key, paused FROM legacy_devices ORDER BY id`)
	if err != nil {
		return nil, nil, err
	}
	defer deviceRows.Close()
	var devices []LegacyDevice
	for deviceRows.Next() {
		var item LegacyDevice
		var paused int
		var ciphertext string
		if err := deviceRows.Scan(&item.ID, &item.Name, &item.KeyMAC, &ciphertext, &paused); err != nil {
			return nil, nil, err
		}
		item.ClientKey, err = db.openKey(item.Name, ciphertext)
		if err != nil {
			return nil, nil, err
		}
		item.Paused = paused != 0
		devices = append(devices, item)
	}
	if err := deviceRows.Err(); err != nil {
		return nil, nil, err
	}
	forwardRows, err := db.QueryRows(ctx, `SELECT id, device_id, listen, target FROM legacy_forwards ORDER BY id`)
	if err != nil {
		return nil, nil, err
	}
	defer forwardRows.Close()
	var forwards []LegacyForward
	for forwardRows.Next() {
		var item LegacyForward
		if err := forwardRows.Scan(&item.ID, &item.DeviceID, &item.Listen, &item.Target); err != nil {
			return nil, nil, err
		}
		forwards = append(forwards, item)
	}
	return devices, forwards, forwardRows.Err()
}

// SetLegacyKey replaces the stored HMAC and the copy shown in the admin UI.
func (db *DB) SetLegacyKey(ctx context.Context, name string, keyMAC []byte, clientKey string) error {
	ciphertext, err := db.sealKey(name, clientKey)
	if err != nil {
		return err
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM legacy_devices WHERE key_mac = ? AND name <> ?`, keyMAC, name).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			return ErrLegacyExists
		}
		result, err := tx.ExecContext(ctx, `UPDATE legacy_devices SET key_mac = ?, client_key = ? WHERE name = ?`, keyMAC, ciphertext, name)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrLegacyNotFound
		}
		return nil
	})
}

// DeleteLegacyDevice removes the device, its forwards, and its access rows in one transaction.
func (db *DB) DeleteLegacyDevice(ctx context.Context, name string) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		var id int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM legacy_devices WHERE name = ?`, name).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrLegacyNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM legacy_forwards WHERE device_id = ?`, id); err != nil {
			return err
		}
		if err := deleteDeviceAccess(ctx, tx, name); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM protocol_credential_archive WHERE device_name = ?`, name); err != nil {
			return err
		}
		if err := revokeDeviceQuickTokens(ctx, tx, name); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM legacy_devices WHERE id = ?`, id)
		return err
	})
}

// DeleteLegacyForward removes one listen address from a legacy device.
func (db *DB) DeleteLegacyForward(ctx context.Context, device, listen string) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `
			DELETE FROM legacy_forwards
			WHERE listen = ? AND device_id = (SELECT id FROM legacy_devices WHERE name = ?)`, listen, device)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrLegacyNotFound
		}
		return nil
	})
}
