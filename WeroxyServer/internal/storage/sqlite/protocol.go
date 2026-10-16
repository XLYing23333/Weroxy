package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"weroxy/server/internal/legacy"
)

// SwitchProtocol moves a device and its forwards to the other protocol table.
// A new-protocol switch generates a fresh token and archives the sealed Legacy
// key for rollback. Each protocol's HMAC uses its actual wire credential bytes.
func (db *DB) SwitchProtocol(ctx context.Context, protocol, name string, macSecret []byte) (string, error) {
	if len(macSecret) < 32 {
		return "", errors.New("device MAC secret unavailable")
	}
	next := ""
	err := db.Do(ctx, func(tx *sql.Tx) error {
		var err error
		switch protocol {
		case "weroxy":
			next, err = db.toLegacy(ctx, tx, name, macSecret)
		case "legacy":
			next, err = db.toWeroxy(ctx, tx, name, macSecret)
		default:
			err = ErrWeroxyNotFound
		}
		return err
	})
	return next, err
}

func (db *DB) toLegacy(ctx context.Context, tx *sql.Tx, name string, macSecret []byte) (string, error) {
	var id, paused int64
	var mac []byte
	var clientKey string
	err := tx.QueryRowContext(ctx, `SELECT id, token_mac, client_key, paused FROM weroxy_devices WHERE name = ?`, name).Scan(&id, &mac, &clientKey, &paused)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrWeroxyNotFound
	}
	if err != nil {
		return "", err
	}
	var archived string
	archiveErr := tx.QueryRowContext(ctx, `SELECT legacy_client_key FROM protocol_credential_archive WHERE device_name = ?`, name).Scan(&archived)
	if archiveErr != nil && !errors.Is(archiveErr, sql.ErrNoRows) {
		return "", archiveErr
	}
	if archiveErr == nil {
		clientKey = archived
	}
	plain, err := db.openKey(name, clientKey)
	if err != nil || plain == "" {
		return "", errors.New("device credential unavailable")
	}
	mac = legacy.MAC(macSecret, []byte(plain))
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM legacy_devices WHERE name = ? OR key_mac = ?`, name, mac).Scan(&count); err != nil {
		return "", err
	}
	if count > 0 {
		return "", ErrLegacyExists
	}
	rows, err := tx.QueryContext(ctx, `SELECT listen, target FROM weroxy_forwards WHERE device_id = ? ORDER BY id`, id)
	if err != nil {
		return "", err
	}
	type hop struct{ listen, target string }
	var hops []hop
	for rows.Next() {
		var item hop
		if err := rows.Scan(&item.listen, &item.target); err != nil {
			rows.Close()
			return "", err
		}
		hops = append(hops, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	rows.Close()
	if _, err := tx.ExecContext(ctx, `DELETE FROM data_assignments WHERE forward_id IN (SELECT id FROM weroxy_forwards WHERE device_id = ?)`, id); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM weroxy_forwards WHERE device_id = ?`, id); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM weroxy_devices WHERE id = ?`, id); err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := insertEntity(ctx, tx, `INSERT INTO legacy_devices(name, key_mac, client_key, paused, created_at) VALUES (?, ?, ?, ?, ?)`, name, mac, clientKey, paused, now)
	if err != nil {
		return "", err
	}
	deviceID, err := result.LastInsertId()
	if err != nil {
		return "", err
	}
	for _, item := range hops {
		if _, err := insertEntity(ctx, tx, `INSERT INTO legacy_forwards(device_id, listen, target, created_at) VALUES (?, ?, ?, ?)`, deviceID, item.listen, item.target, now); err != nil {
			return "", err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM protocol_credential_archive WHERE device_name = ?`, name); err != nil {
		return "", err
	}
	return "legacy", nil
}

func (db *DB) toWeroxy(ctx context.Context, tx *sql.Tx, name string, macSecret []byte) (string, error) {
	var id, paused int64
	var mac []byte
	var clientKey string
	err := tx.QueryRowContext(ctx, `SELECT id, key_mac, client_key, paused FROM legacy_devices WHERE name = ?`, name).Scan(&id, &mac, &clientKey, &paused)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrLegacyNotFound
	}
	if err != nil {
		return "", err
	}
	uidRaw := make([]byte, 16)
	if _, err := rand.Read(uidRaw); err != nil {
		return "", err
	}
	uid := hex.EncodeToString(uidRaw)
	tokenRaw := make([]byte, 32)
	if _, err := rand.Read(tokenRaw); err != nil {
		return "", err
	}
	defer func() {
		for i := range tokenRaw {
			tokenRaw[i] = 0
		}
	}()
	newKey, err := db.sealKey(name, hex.EncodeToString(tokenRaw))
	if err != nil {
		return "", err
	}
	newMAC := legacy.MAC(macSecret, tokenRaw)
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM weroxy_devices WHERE name = ? OR device_uid = ? OR token_mac = ?`, name, uid, newMAC).Scan(&count); err != nil {
		return "", err
	}
	if count > 0 {
		return "", ErrWeroxyExists
	}
	rows, err := tx.QueryContext(ctx, `SELECT listen, target FROM legacy_forwards WHERE device_id = ? ORDER BY id`, id)
	if err != nil {
		return "", err
	}
	type hop struct{ listen, target string }
	var hops []hop
	for rows.Next() {
		var item hop
		if err := rows.Scan(&item.listen, &item.target); err != nil {
			rows.Close()
			return "", err
		}
		hops = append(hops, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	rows.Close()
	if _, err := tx.ExecContext(ctx, `INSERT INTO protocol_credential_archive(device_name, legacy_client_key, created_at) VALUES (?, ?, ?) ON CONFLICT(device_name) DO UPDATE SET legacy_client_key = excluded.legacy_client_key, created_at = excluded.created_at`, name, clientKey, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM legacy_forwards WHERE device_id = ?`, id); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM legacy_devices WHERE id = ?`, id); err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := insertEntity(ctx, tx, `INSERT INTO weroxy_devices(name, device_uid, token_mac, client_key, revoked, paused, created_at) VALUES (?, ?, ?, ?, 0, ?, ?)`, name, uid, newMAC, newKey, paused, now)
	if err != nil {
		return "", err
	}
	deviceID, err := result.LastInsertId()
	if err != nil {
		return "", err
	}
	for _, item := range hops {
		res, err := insertEntity(ctx, tx, `
			INSERT INTO weroxy_forwards(device_id, listen, target, sharing_mode, min_ports, preferred_ports, max_ports, enabled, use_reserved, created_at)
			VALUES (?, ?, ?, 'shared', 1, 1, 4, 1, 0, ?)`, deviceID, item.listen, item.target, now)
		if err != nil {
			return "", err
		}
		forwardID, err := res.LastInsertId()
		if err != nil {
			return "", err
		}
		if err := allocateTx(ctx, tx, forwardID); err != nil {
			return "", err
		}
	}
	return "weroxy", nil
}
