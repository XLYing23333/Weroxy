package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"weroxy/server/internal/ports"
)

var (
	// ErrWeroxyExists means the device name or token is already stored.
	ErrWeroxyExists = errors.New("weroxy device exists")
	// ErrWeroxyNotFound means the named device is not stored.
	ErrWeroxyNotFound = errors.New("weroxy device not found")
	// ErrWeroxyListen means another forward already uses that listen address.
	ErrWeroxyListen = errors.New("weroxy listen exists")
	// ErrWeroxyRevoked means the device can no longer accept a forward.
	ErrWeroxyRevoked = errors.New("weroxy device revoked")
	// ErrWeroxyLimit means this device already has its one forward.
	ErrWeroxyLimit = errors.New("weroxy forward limit")
)

// WeroxyDevice is one new client. TokenMAC authenticates the client.
// ClientKey is the stored token so an administrator can copy it again.
type WeroxyDevice struct {
	ID        int64
	Name      string
	UID       string
	TokenMAC  []byte
	ClientKey string
	Revoked   bool
	Paused    bool
}

// WeroxyForward is one visitor listener and its target.
type WeroxyForward struct {
	ID          int64
	DeviceID    int64
	Listen      string
	Target      string
	Mode        string
	Min         int
	Preferred   int
	Max         int
	Enabled     bool
	DeviceMax   int
	Device      string
	UseReserved bool
	ManualPorts []int
}

// AddWeroxyDevice stores a device id, the token HMAC, and the token itself.
func (db *DB) AddWeroxyDevice(ctx context.Context, name, uid string, tokenMAC []byte, clientKey string) error {
	ciphertext, err := db.sealKey(name, clientKey)
	if err != nil {
		return err
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM weroxy_devices WHERE name = ? OR device_uid = ? OR token_mac = ?`, name, uid, tokenMAC).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			return ErrWeroxyExists
		}
		_, err := insertEntity(ctx, tx,
			`INSERT INTO weroxy_devices(name, device_uid, token_mac, client_key, revoked, created_at) VALUES (?, ?, ?, ?, 0, ?)`,
			name, uid, tokenMAC, ciphertext, time.Now().UTC().Format(time.RFC3339Nano),
		)
		return err
	})
}

// AddWeroxyForward attaches one listen address and target to a device.
// mode defaults to shared, and the port triple defaults to 1/1/4.
func (db *DB) AddWeroxyForward(ctx context.Context, device, listen, target, mode string, minPorts, preferred, maxPorts int, useReserved, allowOutside bool, manual ...[]int) error {
	if mode == "" {
		mode = ports.Shared
	}
	if minPorts == 0 && preferred == 0 && maxPorts == 0 {
		minPorts, preferred, maxPorts = 1, 1, 4
	}
	if mode != ports.Shared && mode != ports.Exclusive {
		return ErrPortRange
	}
	if !ports.ValidRange(minPorts, preferred, maxPorts) {
		return ErrPortRange
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		var deviceID int64
		var revoked int
		err := tx.QueryRowContext(ctx, `SELECT id, revoked FROM weroxy_devices WHERE name = ?`, device).Scan(&deviceID, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrWeroxyNotFound
		}
		if err != nil {
			return err
		}
		if revoked != 0 {
			return ErrWeroxyRevoked
		}
		if err := conflictListen(ctx, tx, listen); err != nil {
			return err
		}
		if err := forwardInPool(ctx, tx, listen, allowOutside); err != nil {
			return err
		}
		var listenCount int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM weroxy_forwards WHERE listen = ?`, listen).Scan(&listenCount); err != nil {
			return err
		}
		if listenCount > 0 {
			return ErrWeroxyListen
		}
		reserved := 0
		if useReserved {
			reserved = 1
		}
		result, err := insertEntity(ctx, tx,
			`INSERT INTO weroxy_forwards(device_id, listen, target, sharing_mode, min_ports, preferred_ports, max_ports, enabled, use_reserved, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
			deviceID, listen, target, mode, minPorts, preferred, maxPorts, reserved, time.Now().UTC().Format(time.RFC3339Nano),
		)
		if err != nil {
			return err
		}
		id, err := result.LastInsertId()
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

// SetWeroxyToken replaces the stored token HMAC and the copy shown in the admin UI.
func (db *DB) SetWeroxyToken(ctx context.Context, name string, tokenMAC []byte, clientKey string) error {
	ciphertext, err := db.sealKey(name, clientKey)
	if err != nil {
		return err
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM weroxy_devices WHERE token_mac = ? AND name <> ?`, tokenMAC, name).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			return ErrWeroxyExists
		}
		result, err := tx.ExecContext(ctx, `UPDATE weroxy_devices SET token_mac = ?, client_key = ? WHERE name = ?`, tokenMAC, ciphertext, name)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrWeroxyNotFound
		}
		return nil
	})
}

// DeleteWeroxyForward removes one listen address and its data-port assignments.
func (db *DB) DeleteWeroxyForward(ctx context.Context, device, listen string) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		var id int64
		err := tx.QueryRowContext(ctx, `
			SELECT f.id FROM weroxy_forwards f
			JOIN weroxy_devices d ON d.id = f.device_id
			WHERE d.name = ? AND f.listen = ?`, device, listen).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrWeroxyNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM data_assignments WHERE forward_id = ?`, id); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM weroxy_forwards WHERE id = ?`, id)
		return err
	})
}

// SetWeroxyForwardEnabled stores whether new sessions may use this forward.
// A running process keeps the copy it loaded at start.
func (db *DB) SetWeroxyForwardEnabled(ctx context.Context, device, listen string, enabled bool) error {
	flag := 0
	if enabled {
		flag = 1
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `
			UPDATE weroxy_forwards SET enabled = ?
			WHERE listen = ? AND device_id = (SELECT id FROM weroxy_devices WHERE name = ?)`,
			flag, listen, device)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrWeroxyNotFound
		}
		return nil
	})
}

// DeleteWeroxyDevice removes the device, its forwards, and its access rows in one transaction.
func (db *DB) DeleteWeroxyDevice(ctx context.Context, name string) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		var id int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM weroxy_devices WHERE name = ?`, name).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrWeroxyNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM data_assignments
			WHERE forward_id IN (SELECT id FROM weroxy_forwards WHERE device_id = ?)`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM weroxy_forwards WHERE device_id = ?`, id); err != nil {
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
		_, err = tx.ExecContext(ctx, `DELETE FROM weroxy_devices WHERE id = ?`, id)
		return err
	})
}

// SetDevicePaused stores whether a device accepts new visitors.
func (db *DB) SetDevicePaused(ctx context.Context, protocol, name string, paused bool) error {
	table := ""
	switch protocol {
	case "weroxy":
		table = "weroxy_devices"
	case "legacy":
		table = "legacy_devices"
	default:
		return ErrWeroxyNotFound
	}
	flag := 0
	if paused {
		flag = 1
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE `+table+` SET paused = ? WHERE name = ?`, flag, name)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrWeroxyNotFound
		}
		return nil
	})
}

// RevokeWeroxyDevice marks a device so the running server can drop its sessions.
func (db *DB) RevokeWeroxyDevice(ctx context.Context, name string) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE weroxy_devices SET revoked = 1 WHERE name = ?`, name)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrWeroxyNotFound
		}
		return nil
	})
}

// ListWeroxy reads the device cache. Callers keep it in memory.
func (db *DB) ListWeroxy(ctx context.Context) ([]WeroxyDevice, []WeroxyForward, error) {
	rows, err := db.QueryRows(ctx, `SELECT id, name, device_uid, token_mac, client_key, revoked, paused FROM weroxy_devices ORDER BY id`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var devices []WeroxyDevice
	for rows.Next() {
		var item WeroxyDevice
		var revoked, paused int
		var ciphertext string
		if err := rows.Scan(&item.ID, &item.Name, &item.UID, &item.TokenMAC, &ciphertext, &revoked, &paused); err != nil {
			return nil, nil, err
		}
		item.ClientKey, err = db.openKey(item.Name, ciphertext)
		if err != nil {
			return nil, nil, err
		}
		item.Revoked = revoked != 0
		item.Paused = paused != 0
		devices = append(devices, item)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	forwardRows, err := db.QueryRows(ctx, `
		SELECT f.id, f.device_id, f.listen, f.target, f.sharing_mode, f.min_ports, f.preferred_ports, f.max_ports, f.enabled, f.use_reserved, d.max_data_ports, d.name, f.manual_data_ports
		FROM weroxy_forwards f JOIN weroxy_devices d ON d.id = f.device_id
		ORDER BY f.id`)
	if err != nil {
		return nil, nil, err
	}
	defer forwardRows.Close()
	var forwards []WeroxyForward
	for forwardRows.Next() {
		var item WeroxyForward
		var manual string
		var enabled, reserved int
		var deviceMax sql.NullInt64
		if err := forwardRows.Scan(&item.ID, &item.DeviceID, &item.Listen, &item.Target, &item.Mode, &item.Min, &item.Preferred, &item.Max, &enabled, &reserved, &deviceMax, &item.Device, &manual); err != nil {
			return nil, nil, err
		}
		if err := json.Unmarshal([]byte(manual), &item.ManualPorts); err != nil {
			return nil, nil, err
		}
		item.Enabled = enabled != 0
		item.UseReserved = reserved != 0
		if deviceMax.Valid {
			item.DeviceMax = int(deviceMax.Int64)
		}
		forwards = append(forwards, item)
	}
	return devices, forwards, forwardRows.Err()
}

// RevokedWeroxyUIDs returns device ids that must lose their live sessions.
func (db *DB) RevokedWeroxyUIDs(ctx context.Context) ([]string, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT device_uid FROM weroxy_devices WHERE revoked = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
