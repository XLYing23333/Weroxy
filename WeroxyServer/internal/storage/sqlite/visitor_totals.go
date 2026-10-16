package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"net"
	"sort"

	"weroxy/server/internal/metrics"
)

// SaveVisitorTotals applies absolute checkpoints and aggregate deltas atomically.
func (db *DB) SaveVisitorTotals(ctx context.Context, items []metrics.VisitorTotal) error {
	if len(items) > 512 {
		return ErrConnectionPage
	}
	if !db.TelemetryAllowed() {
		return ErrTelemetryDisk
	}
	return db.DoLow(ctx, func(tx *sql.Tx) error {
		for _, v := range items {
			if v.RunID == "" || net.ParseIP(v.IP) == nil || (v.Protocol != "weroxy" && v.Protocol != "legacy") || v.Connections > math.MaxInt64 || v.Bytes > math.MaxInt64 || v.Version > math.MaxInt64 {
				return ErrConnectionPage
			}
			var count, bytes, version uint64
			e := tx.QueryRowContext(ctx, `SELECT connections,bytes,version FROM visitor_checkpoints WHERE run_id=? AND protocol=? AND device_id=? AND source_ip=?`, v.RunID, v.Protocol, v.DeviceID, v.IP).Scan(&count, &bytes, &version)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if v.Version <= version {
				continue
			}
			if v.Connections < count || v.Bytes < bytes {
				return ErrConnectionPage
			}
			_, e = tx.ExecContext(ctx, `INSERT INTO visitor_totals(protocol,device_id,source_ip,connections,bytes,client_os,last_unix,cumulative_since,hidden) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(protocol,device_id,source_ip) DO UPDATE SET connections=connections+excluded.connections,bytes=bytes+excluded.bytes,client_os=CASE WHEN excluded.client_os<>'' THEN excluded.client_os ELSE client_os END,last_unix=max(last_unix,excluded.last_unix),hidden=excluded.hidden`, v.Protocol, v.DeviceID, v.IP, v.Connections-count, v.Bytes-bytes, v.OS, v.Last, v.Since, v.Hidden)
			if e != nil {
				return e
			}
			_, e = tx.ExecContext(ctx, `INSERT INTO visitor_checkpoints VALUES(?,?,?,?,?,?,?) ON CONFLICT(run_id,protocol,device_id,source_ip) DO UPDATE SET connections=excluded.connections,bytes=excluded.bytes,version=excluded.version`, v.RunID, v.Protocol, v.DeviceID, v.IP, v.Connections, v.Bytes, v.Version)
			if e != nil {
				return e
			}
		}
		return nil
	})
}

// VisitorPage merges a pre-query memory snapshot with persisted checkpoints.
// Cursor order is the canonical IP text, not an unstable last-activity timestamp.
func (db *DB) VisitorPage(ctx context.Context, protocol string, id int64, cursor string, limit int, run string, local []metrics.VisitorTotal, active []metrics.Visitor) ([]metrics.Visitor, string, error) {
	if limit < 1 || limit > 100 || len(cursor) > 45 {
		return nil, "", ErrConnectionPage
	}
	rows, e := db.QueryRows(ctx, `SELECT v.source_ip,v.client_os,v.connections,v.bytes,v.last_unix,v.cumulative_since,v.hidden,coalesce(c.connections,0),coalesce(c.bytes,0),coalesce(c.version,0) FROM visitor_totals v LEFT JOIN visitor_checkpoints c ON c.protocol=v.protocol AND c.device_id=v.device_id AND c.source_ip=v.source_ip AND c.run_id=? WHERE v.protocol=? AND v.device_id=? AND v.source_ip>? ORDER BY v.source_ip LIMIT ?`, run, protocol, id, cursor, limit+1)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	type saved struct {
		item                  metrics.Visitor
		hidden                bool
		count, bytes, version uint64
	}
	table := map[string]*saved{}
	keys := []string{}
	for rows.Next() {
		s := &saved{}
		if e = rows.Scan(&s.item.IP, &s.item.OS, &s.item.Connections, &s.item.Bytes, &s.item.Last, &s.item.CumulativeSince, &s.hidden, &s.count, &s.bytes, &s.version); e != nil {
			return nil, "", e
		}
		table[s.item.IP] = s
		keys = append(keys, s.item.IP)
	}
	if e = rows.Err(); e != nil {
		return nil, "", e
	}
	boundary := ""
	if len(keys) > limit {
		boundary = keys[limit-1]
	}
	for _, v := range local {
		if v.IP <= cursor || (boundary != "" && v.IP > boundary) {
			continue
		}
		s := table[v.IP]
		if s == nil {
			s = &saved{item: metrics.Visitor{IP: v.IP, CumulativeSince: v.Since}}
			table[v.IP] = s
			keys = append(keys, v.IP)
		}
		if v.Version >= s.version {
			s.hidden = v.Hidden
			s.item.OS = v.OS
			if v.Connections > s.count {
				s.item.Connections += int(v.Connections - s.count)
			}
			if v.Bytes > s.bytes {
				s.item.Bytes += v.Bytes - s.bytes
			}
			if v.Last > s.item.Last {
				s.item.Last = v.Last
			}
		}
	}
	for _, v := range active {
		if s := table[v.IP]; s != nil {
			s.item.ActiveConnections = v.ActiveConnections
			s.item.Active = v.ActiveConnections > 0
		}
	}
	sort.Strings(keys)
	out := []metrics.Visitor{}
	next := ""
	for i, ip := range keys {
		if i == limit {
			next = keys[i-1]
			break
		}
		s := table[ip]
		if !s.hidden {
			out = append(out, s.item)
		}
	}
	return out, next, nil
}

func (db *DB) HideVisitors(ctx context.Context, protocol string, id int64, ips []string) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		for _, ip := range ips {
			if _, e := tx.ExecContext(ctx, `UPDATE visitor_totals SET hidden=1 WHERE protocol=? AND device_id=? AND source_ip=?`, protocol, id, ip); e != nil {
				return e
			}
		}
		return nil
	})
}
