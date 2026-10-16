package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type DeviceStatus struct {
	DeviceID    int64
	Protocol    string
	Device      string
	At          time.Time
	DurationSec int
	State       string
	Sessions    int
	Up          uint64
	Down        uint64
}

func (db *DB) SaveDeviceStatus(ctx context.Context, items []DeviceStatus) error {
	if len(items) == 0 {
		return nil
	}
	if len(items) > 512 {
		return ErrConnectionPage
	}
	return db.DoLow(ctx, func(tx *sql.Tx) error {
		for _, item := range items {
			if item.Protocol == "" || item.Device == "" || item.At.IsZero() || item.Sessions < 0 || (item.DurationSec != 60 && item.DurationSec != 300) {
				return ErrConnectionPage
			}
			if item.DeviceID > 0 {
				var name string
				if item.Protocol != "legacy" && item.Protocol != "weroxy" {
					return ErrConnectionPage
				}
				err := tx.QueryRowContext(ctx, "SELECT name FROM "+item.Protocol+"_devices WHERE id=?", item.DeviceID).Scan(&name)
				if errors.Is(err, sql.ErrNoRows) {
					continue
				}
				if err != nil {
					return err
				}
				item.Device = name
			}
			_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO device_status_samples(protocol,device,at,duration_sec,state,sessions,up_bytes,down_bytes) VALUES(?,?,?,?,?,?,?,?)`, item.Protocol, item.Device, item.At.UTC().Format(time.RFC3339Nano), item.DurationSec, item.State, item.Sessions, item.Up, item.Down)
			if err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM device_status_samples WHERE at < ?`, time.Now().UTC().Add(-3*time.Hour).Format(time.RFC3339Nano))
		return err
	})
}

func (db *DB) LoadDeviceStatus(ctx context.Context) ([]DeviceStatus, error) {
	rows, err := db.QueryRows(ctx, `SELECT protocol,device,at,duration_sec,state,sessions,up_bytes,down_bytes FROM (SELECT *,row_number() OVER (PARTITION BY protocol,device ORDER BY at DESC) AS rn FROM device_status_samples WHERE at>=?) WHERE rn<=180 ORDER BY at DESC`, time.Now().UTC().Add(-3*time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]DeviceStatus, 0)
	for rows.Next() {
		var item DeviceStatus
		var at string
		if err := rows.Scan(&item.Protocol, &item.Device, &at, &item.DurationSec, &item.State, &item.Sessions, &item.Up, &item.Down); err != nil {
			return nil, err
		}
		item.At, err = time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
