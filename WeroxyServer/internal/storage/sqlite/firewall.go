package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// FirewallBan and FirewallForward contain only the fields needed to compile
// host rules; no device key or LAN target is loaded into this path.
type FirewallBan struct {
	ID        int64
	Scope     string
	Key       string
	CIDR      string
	ExpiresAt *time.Time
}

type FirewallForward struct {
	Device string
	Listen string
}

// FirewallSnapshot returns one consistent policy generation, active Bans and
// enabled visitor listeners. The agent maps target ports to host publication.
func (db *DB) FirewallSnapshot(ctx context.Context) (int64, []FirewallBan, []FirewallForward, error) {
	var revision int64
	var bans []FirewallBan
	var forwards []FirewallForward
	err := db.ReadSnapshot(ctx, func(readCtx context.Context) error {
		state, err := db.ConfigRevision(readCtx, "policy")
		if err != nil {
			return err
		}
		revision = state.DesiredRevision
		now := time.Now().UTC().Format(time.RFC3339Nano)
		rows, err := db.QueryRows(readCtx, `SELECT id, scope, scope_key, cidr, expires_at FROM access_rules
			WHERE action = 'ban' AND (expires_at IS NULL OR expires_at > ?) ORDER BY id LIMIT 4097`, now)
		if err != nil {
			return err
		}
		for rows.Next() {
			var item FirewallBan
			var expiry sql.NullString
			if err := rows.Scan(&item.ID, &item.Scope, &item.Key, &item.CIDR, &expiry); err != nil {
				rows.Close()
				return err
			}
			if expiry.Valid {
				parsed, err := time.Parse(time.RFC3339Nano, expiry.String)
				if err != nil {
					rows.Close()
					return err
				}
				item.ExpiresAt = &parsed
			}
			bans = append(bans, item)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(bans) > 4096 {
			return errors.New("too many active bans for firewall compiler")
		}
		queries := []string{
			`SELECT d.name, f.listen FROM legacy_forwards f JOIN legacy_devices d ON d.id = f.device_id WHERE d.paused = 0 ORDER BY f.id LIMIT 4097`,
			`SELECT d.name, f.listen FROM weroxy_forwards f JOIN weroxy_devices d ON d.id = f.device_id WHERE f.enabled = 1 AND d.paused = 0 AND d.revoked = 0 ORDER BY f.id LIMIT 4097`,
		}
		for _, query := range queries {
			rows, err := db.QueryRows(readCtx, query)
			if err != nil {
				return err
			}
			for rows.Next() {
				var item FirewallForward
				if err := rows.Scan(&item.Device, &item.Listen); err != nil {
					rows.Close()
					return err
				}
				forwards = append(forwards, item)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			if len(forwards) > 4096 {
				return errors.New("too many forwards for firewall compiler")
			}
		}
		return nil
	})
	return revision, bans, forwards, err
}

// RecordFirewallStatus stores the latest attempted generation separately from
// application-policy success. An agent acknowledgement remains pending until
// kernel path and actual connectivity are independently verified.
func (db *DB) RecordFirewallStatus(ctx context.Context, ids []int64, status string, generation int64, retry bool) error {
	if status != "unsupported" && status != "not_requested" && status != "pending" && status != "failed" && status != "applied" {
		return errors.New("invalid kernel status")
	}
	if generation < 0 || len(ids) > 4096 {
		return errors.New("invalid kernel generation")
	}
	return db.DoLow(ctx, func(tx *sql.Tx) error {
		for _, id := range ids {
			if retry {
				if _, err := tx.ExecContext(ctx, `UPDATE access_rules SET kernel_status = ?, kernel_retry_count = kernel_retry_count + 1, policy_generation = ? WHERE id = ? AND action = 'ban'`, status, generation, id); err != nil {
					return err
				}
			} else {
				if _, err := tx.ExecContext(ctx, `UPDATE access_rules SET kernel_status = ?, policy_generation = ? WHERE id = ? AND action = 'ban' AND (kernel_status <> ? OR policy_generation <> ?)`, status, generation, id, status, generation); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
