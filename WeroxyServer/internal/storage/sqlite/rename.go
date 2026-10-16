package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// RenameDevice preserves stable IDs and reseals name-bound credentials atomically.
func (db *DB) RenameDevice(ctx context.Context, protocol, oldName, newName string) error {
	valid := func(s string) bool {
		if len(s) < 1 || len(s) > 64 {
			return false
		}
		for _, r := range s {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
				return false
			}
		}
		return true
	}
	if !valid(oldName) || !valid(newName) || (protocol != "legacy" && protocol != "weroxy") {
		return ErrPortRange
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		table := protocol + "_devices"
		var id int64
		var sealed string
		if err := tx.QueryRowContext(ctx, "SELECT id,client_key FROM "+table+" WHERE name=?", oldName).Scan(&id, &sealed); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrWeroxyNotFound
			}
			return err
		}
		if oldName == newName {
			return nil
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM legacy_devices WHERE name=?)+(SELECT COUNT(*) FROM weroxy_devices WHERE name=?)", newName, newName).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			return ErrWeroxyExists
		}
		key, err := db.openKey(oldName, sealed)
		if err != nil {
			return err
		}
		sealed, err = db.sealKey(newName, key)
		if err != nil {
			return err
		}
		var archive string
		err = tx.QueryRowContext(ctx, "SELECT legacy_client_key FROM protocol_credential_archive WHERE device_name=?", oldName).Scan(&archive)
		if err == nil {
			key, e := db.openKey(oldName, archive)
			if e != nil {
				return e
			}
			archive, e = db.sealKey(newName, key)
			if e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "UPDATE protocol_credential_archive SET device_name=?,legacy_client_key=? WHERE device_name=?", newName, archive, oldName); e != nil {
				return e
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+table+" SET name=?,client_key=? WHERE id=?", newName, sealed, id); err != nil {
			return err
		}
		for _, t := range []string{"access_policies", "access_rules"} {
			rows, e := tx.QueryContext(ctx, "SELECT id,scope,scope_key FROM "+t+" WHERE scope<>'global'")
			if e != nil {
				return e
			}
			changes := map[int64]string{}
			for rows.Next() {
				var n int64
				var scope, k string
				if e = rows.Scan(&n, &scope, &k); e != nil {
					rows.Close()
					return e
				}
				if k == oldName || (scope == "forward" && strings.HasPrefix(k, oldName+"|")) {
					changes[n] = newName + strings.TrimPrefix(k, oldName)
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			for n, k := range changes {
				if _, e = tx.ExecContext(ctx, "UPDATE "+t+" SET scope_key=? WHERE id=?", k, n); e != nil {
					return e
				}
			}
		}
		if _, err = tx.ExecContext(ctx, "UPDATE connection_details SET device_name=? WHERE protocol=? AND device_id=?", newName, protocol, id); err != nil {
			return err
		}
		// A deleted device may have left short-lived samples under the new name.
		if _, err = tx.ExecContext(ctx, "DELETE FROM device_status_samples WHERE protocol=? AND device=?", protocol, newName); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE device_status_samples SET device=? WHERE protocol=? AND device=?", newName, protocol, oldName); err != nil {
			return err
		}
		return nil
	})
}
