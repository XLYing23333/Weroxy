package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	"weroxy/server/internal/metrics"
)

var ErrConnectionPage = errors.New("invalid connection page")

// SaveConnections upserts a bounded event batch. Replays and out-of-order
// active snapshots cannot reopen a terminal row or double its byte totals.
func (db *DB) SaveConnections(ctx context.Context, items []metrics.Session) error {
	if !db.TelemetryAllowed() {
		return ErrTelemetryDisk
	}
	if len(items) == 0 {
		return nil
	}
	if len(items) > 512 {
		return ErrConnectionPage
	}
	return db.DoLow(ctx, func(tx *sql.Tx) error {
		for _, item := range items {
			if item.RunID == "" || item.ID == "" || (item.Protocol != metrics.Legacy && item.Protocol != metrics.Weroxy) || item.Started.IsZero() || item.Up > math.MaxInt64 || item.Down > math.MaxInt64 {
				return ErrConnectionPage
			}
			// Stable ID resolves concurrent rename before a delayed metrics flush.
			var canonical string
			if e := tx.QueryRowContext(ctx, "SELECT name FROM "+item.Protocol+"_devices WHERE id=?", item.DeviceID).Scan(&canonical); e == nil {
				item.Device = canonical
			} else if !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			ready, setup := any(nil), any(nil)
			if !item.ReadyAt.IsZero() {
				if item.SetupMS < 0 {
					return ErrConnectionPage
				}
				ready, setup = connectionTime(item.ReadyAt), item.SetupMS
			}
			closed := any(nil)
			if !item.Ended.IsZero() {
				closed = connectionTime(item.Ended)
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO connection_details
				(run_id,protocol,session_id,device_id,forward_id,device_name,forward_listen,source_ip,client_os,data_port,started_at,last_at,ready_at,setup_ms,closed_at,close_reason,up_bytes,down_bytes)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
				ON CONFLICT(run_id,protocol,session_id) DO UPDATE SET
				device_name=CASE WHEN excluded.device_name<>'' THEN excluded.device_name ELSE device_name END,
				forward_listen=CASE WHEN excluded.forward_listen<>'' THEN excluded.forward_listen ELSE forward_listen END,
				source_ip=CASE WHEN excluded.source_ip<>'' THEN excluded.source_ip ELSE source_ip END,
				client_os=CASE WHEN excluded.client_os<>'' THEN excluded.client_os ELSE client_os END,
				data_port=CASE WHEN excluded.data_port<>0 THEN excluded.data_port ELSE data_port END,
				last_at=max(last_at,excluded.last_at),
				ready_at=COALESCE(ready_at,excluded.ready_at),
				setup_ms=COALESCE(setup_ms,excluded.setup_ms),
				closed_at=COALESCE(closed_at,excluded.closed_at),
				close_reason=CASE WHEN close_reason<>'' THEN close_reason ELSE excluded.close_reason END,
				up_bytes=max(up_bytes,excluded.up_bytes),
				down_bytes=max(down_bytes,excluded.down_bytes)`,
				item.RunID, item.Protocol, item.ID, item.DeviceID, item.ForwardID, item.Device, item.Listen, item.IP, item.OS, item.DataPort,
				connectionTime(item.Started), connectionTime(item.Last), ready, setup, closed, item.Reason, int64(item.Up), int64(item.Down))
			if err != nil {
				return err
			}
		}
		// Keep only the newest thirty detail rows for each affected device. An
		// active session may lose its detail row, but the live relay and counters
		// are independent of this history table.
		type deviceKey struct {
			protocol string
			id       int64
		}
		affected := map[deviceKey]struct{}{}
		for _, item := range items {
			affected[deviceKey{item.Protocol, item.DeviceID}] = struct{}{}
		}
		for device := range affected {
			if _, err := tx.ExecContext(ctx, `DELETE FROM connection_details WHERE protocol=? AND device_id=? AND id NOT IN
				(SELECT id FROM connection_details WHERE protocol=? AND device_id=? ORDER BY started_at DESC,id DESC LIMIT 30)`,
				device.protocol, device.id, device.protocol, device.id); err != nil {
				return err
			}
		}
		return nil
	})
}

// InterruptOpenConnections closes records left active by a previous process.
func (db *DB) InterruptOpenConnections(ctx context.Context) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE connection_details SET closed_at=last_at, close_reason='process_restart' WHERE closed_at IS NULL`)
		return err
	})
}

type ConnectionRow struct {
	ID          int64  `json:"id"`
	Protocol    string `json:"protocol"`
	SessionID   string `json:"session_id"`
	DeviceID    int64  `json:"device_id"`
	ForwardID   int64  `json:"forward_id"`
	Device      string `json:"device"`
	Listen      string `json:"forward_listen"`
	SourceIP    string `json:"source_ip"`
	OS          string `json:"client_os"`
	DataPort    int    `json:"data_port"`
	StartedAt   string `json:"started_at"`
	LastAt      string `json:"last_at"`
	ReadyAt     string `json:"ready_at,omitempty"`
	SetupMS     *int64 `json:"setup_ms,omitempty"`
	ClosedAt    string `json:"closed_at,omitempty"`
	CloseReason string `json:"close_reason,omitempty"`
	Up          uint64 `json:"up_bytes"`
	Down        uint64 `json:"down_bytes"`
	Status      string `json:"status"`
}

// Connections returns a cursor page. The caller supplies a two-second query
// deadline; no endpoint can request an unbounded full table scan.
func (db *DB) Connections(ctx context.Context, protocol, device string, before int64, limit int) ([]ConnectionRow, int64, error) {
	if limit < 1 || limit > 100 || before < 1 || protocol != "" && protocol != metrics.Legacy && protocol != metrics.Weroxy {
		return nil, 0, ErrConnectionPage
	}
	rows, err := db.QueryRows(ctx, `SELECT id,protocol,session_id,device_id,forward_id,device_name,forward_listen,source_ip,client_os,data_port,started_at,last_at,ready_at,setup_ms,closed_at,close_reason,up_bytes,down_bytes
		FROM connection_details WHERE id<? AND (?='' OR protocol=?) AND (?='' OR device_name=?) ORDER BY id DESC LIMIT ?`, before, protocol, protocol, device, device, limit+1)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]ConnectionRow, 0, limit+1)
	for rows.Next() {
		var item ConnectionRow
		var closed, ready sql.NullString
		var setup sql.NullInt64
		var up, down int64
		if err := rows.Scan(&item.ID, &item.Protocol, &item.SessionID, &item.DeviceID, &item.ForwardID, &item.Device, &item.Listen, &item.SourceIP, &item.OS, &item.DataPort, &item.StartedAt, &item.LastAt, &ready, &setup, &closed, &item.CloseReason, &up, &down); err != nil {
			return nil, 0, err
		}
		if up < 0 || down < 0 {
			return nil, 0, ErrConnectionPage
		}
		item.Up, item.Down = uint64(up), uint64(down)
		if ready.Valid {
			item.ReadyAt = ready.String
		}
		if setup.Valid {
			if setup.Int64 < 0 {
				return nil, 0, ErrConnectionPage
			}
			value := setup.Int64
			item.SetupMS = &value
		}
		item.Status = "active"
		if closed.Valid {
			item.ClosedAt = closed.String
			item.Status = "closed"
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	next := int64(0)
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].ID
	}
	return out, next, nil
}

// PruneConnections enforces both age and row count in a bounded write.
func (db *DB) PruneConnections(ctx context.Context, now time.Time) error {
	settings, err := db.HistoryRetention(ctx)
	if err != nil {
		return err
	}
	return db.runRetention(ctx, "connection_history", now, func(tx *sql.Tx) (int64, error) {
		result, err := tx.ExecContext(ctx, `DELETE FROM connection_details WHERE id IN (SELECT id FROM connection_details WHERE closed_at < ? ORDER BY id LIMIT 2048)`, connectionTime(now.Add(-time.Duration(settings.ConnectionDays)*24*time.Hour)))
		if err != nil {
			return 0, err
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		var count int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM connection_details`).Scan(&count); err != nil {
			return 0, err
		}
		if count <= 100000 {
			return deleted, nil
		}
		excess := count - 100000
		if excess > 2048 {
			excess = 2048
		}
		result, err = tx.ExecContext(ctx, `DELETE FROM connection_details WHERE id IN (SELECT id FROM connection_details WHERE closed_at IS NOT NULL ORDER BY id LIMIT ?)`, excess)
		if err != nil {
			return 0, err
		}
		n, err := result.RowsAffected()
		return deleted + n, err
	})
}

func connectionTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
}
