package sqlite

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"math"
	"time"

	"weroxy/server/internal/metrics"
)

var ErrMetricBatch = errors.New("invalid metric batch")

// LoadMetricTotals recovers durable lifetime counters without resurrecting
// historical sessions or authentication state.
func (db *DB) LoadMetricTotals(ctx context.Context) (metrics.Snapshot, error) {
	return db.loadMetricTotals(ctx, false)
}

// LoadCurrentMetricTotals leaves deleted entities on disk, outside the hot cache.
func (db *DB) LoadCurrentMetricTotals(ctx context.Context) (metrics.Snapshot, error) {
	return db.loadMetricTotals(ctx, true)
}

func (db *DB) loadMetricTotals(ctx context.Context, currentOnly bool) (metrics.Snapshot, error) {
	out := metrics.Snapshot{
		DeviceUp: map[int64]uint64{}, DeviceDown: map[int64]uint64{},
		ForwardUp: map[int64]uint64{}, ForwardDown: map[int64]uint64{},
		LegacyDeviceUp: map[int64]uint64{}, LegacyDeviceDown: map[int64]uint64{},
		LegacyForwardUp: map[int64]uint64{}, LegacyForwardDown: map[int64]uint64{},
	}
	query := `SELECT scope, protocol, entity_id, up_bytes, down_bytes FROM metric_totals`
	if currentOnly {
		query += ` WHERE scope='global'
 OR (scope='device' AND protocol='weroxy' AND entity_id IN(SELECT id FROM weroxy_devices))
 OR (scope='device' AND protocol='legacy' AND entity_id IN(SELECT id FROM legacy_devices))
 OR (scope='forward' AND protocol='weroxy' AND entity_id IN(SELECT id FROM weroxy_forwards))
 OR (scope='forward' AND protocol='legacy' AND entity_id IN(SELECT id FROM legacy_forwards))`
	}
	rows, err := db.QueryRows(ctx, query)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var scope, protocol string
		var id, up, down int64
		if err := rows.Scan(&scope, &protocol, &id, &up, &down); err != nil {
			return out, err
		}
		if up < 0 || down < 0 {
			return out, ErrMetricBatch
		}
		switch {
		case scope == "global" && protocol == "all" && id == 0:
			out.GlobalUp, out.GlobalDown = uint64(up), uint64(down)
		case scope == "device" && protocol == "weroxy":
			out.DeviceUp[id], out.DeviceDown[id] = uint64(up), uint64(down)
		case scope == "forward" && protocol == "weroxy":
			out.ForwardUp[id], out.ForwardDown[id] = uint64(up), uint64(down)
		case scope == "device" && protocol == "legacy":
			out.LegacyDeviceUp[id], out.LegacyDeviceDown[id] = uint64(up), uint64(down)
		case scope == "forward" && protocol == "legacy":
			out.LegacyForwardUp[id], out.LegacyForwardDown[id] = uint64(up), uint64(down)
		default:
			return out, ErrMetricBatch
		}
	}
	return out, rows.Err()
}

// WriteMetricSnapshot stores one absolute counter snapshot. Retrying batchID
// is harmless; a new batch also uses maxima, so a repeated close cannot add
// the same bytes twice. A gap contributes to lifetime totals but not a rate.
func (db *DB) WriteMetricSnapshot(ctx context.Context, batchID string, sampledAt time.Time, snap metrics.Snapshot, sampleInterval ...time.Duration) error {
	if !db.TelemetryAllowed() {
		return ErrTelemetryDisk
	}
	expectedInterval := 5 * time.Second
	if len(sampleInterval) > 0 {
		expectedInterval = sampleInterval[0]
	}
	if expectedInterval < time.Second || expectedInterval > time.Minute {
		return errors.New("invalid sample interval")
	}
	if len(batchID) != 32 || sampledAt.IsZero() || sampledAt.Location() == nil {
		return ErrMetricBatch
	}
	if _, err := hex.DecodeString(batchID); err != nil {
		return ErrMetricBatch
	}
	if snap.GlobalUp > math.MaxInt64 || snap.GlobalDown > math.MaxInt64 {
		return ErrMetricBatch
	}
	return db.DoLow(ctx, func(tx *sql.Tx) error {
		at := sampledAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
		written := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
		result, err := tx.ExecContext(ctx, `INSERT INTO metric_batches(batch_id, sampled_at, written_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, batchID, at, written)
		if err != nil {
			return err
		}
		inserted, err := result.RowsAffected()
		if err != nil || inserted == 0 {
			return err
		}
		var previousUp, previousDown int64
		err = tx.QueryRowContext(ctx, `SELECT up_bytes, down_bytes FROM metric_totals WHERE scope='global' AND protocol='all' AND entity_id=0`).Scan(&previousUp, &previousDown)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var priorAt string
		err = tx.QueryRowContext(ctx, `SELECT sampled_at FROM metric_samples ORDER BY sampled_at DESC LIMIT 1`).Scan(&priorAt)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		interval := time.Duration(0)
		if priorAt != "" {
			prior, err := time.Parse(time.RFC3339Nano, priorAt)
			if err != nil {
				return err
			}
			interval = sampledAt.Sub(prior)
		}
		gap := interval <= 0 || interval > 2*expectedInterval || uint64(previousUp) > snap.GlobalUp || uint64(previousDown) > snap.GlobalDown
		upDelta, downDelta := int64(0), int64(0)
		if !gap {
			upDelta = int64(snap.GlobalUp) - previousUp
			downDelta = int64(snap.GlobalDown) - previousDown
		}
		if err := writeMetricTotals(ctx, tx, at, snap); err != nil {
			return err
		}
		gapNumber := 0
		if gap {
			gapNumber = 1
		}
		ms := interval.Milliseconds()
		if ms < 0 {
			ms = 0
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO metric_samples(batch_id, sampled_at, interval_ms, up_bytes, down_bytes, gap) VALUES (?, ?, ?, ?, ?, ?)`, batchID, at, ms, upDelta, downDelta, gapNumber)
		if err != nil {
			return err
		}
		for _, bucket := range []struct {
			table    string
			duration time.Duration
		}{
			{"metric_minutes", time.Minute}, {"metric_five_minutes", 5 * time.Minute}, {"metric_hours", time.Hour},
		} {
			bucketAt := sampledAt.UTC().Truncate(bucket.duration).Format(time.RFC3339)
			query := `INSERT INTO ` + bucket.table + `(bucket_at, up_bytes, down_bytes, samples, gaps) VALUES (?, ?, ?, 1, ?)
				ON CONFLICT(bucket_at) DO UPDATE SET up_bytes=up_bytes+excluded.up_bytes, down_bytes=down_bytes+excluded.down_bytes, samples=samples+1, gaps=gaps+excluded.gaps`
			if _, err := tx.ExecContext(ctx, query, bucketAt, upDelta, downDelta, gapNumber); err != nil {
				return err
			}
		}
		return nil
	})
}

func writeMetricTotals(ctx context.Context, tx *sql.Tx, at string, snap metrics.Snapshot) error {
	write := func(scope, protocol string, id int64, up, down uint64) error {
		if up > math.MaxInt64 || down > math.MaxInt64 {
			return ErrMetricBatch
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO metric_totals(scope, protocol, entity_id, up_bytes, down_bytes, updated_at) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(scope, protocol, entity_id) DO UPDATE SET
			up_bytes=max(up_bytes,excluded.up_bytes), down_bytes=max(down_bytes,excluded.down_bytes), updated_at=excluded.updated_at`, scope, protocol, id, int64(up), int64(down), at)
		return err
	}
	if err := write("global", "all", 0, snap.GlobalUp, snap.GlobalDown); err != nil {
		return err
	}
	for _, group := range []struct {
		scope, protocol string
		up, down        map[int64]uint64
	}{
		{"device", "legacy", snap.LegacyDeviceUp, snap.LegacyDeviceDown},
		{"forward", "legacy", snap.LegacyForwardUp, snap.LegacyForwardDown},
		{"device", "weroxy", snap.DeviceUp, snap.DeviceDown},
		{"forward", "weroxy", snap.ForwardUp, snap.ForwardDown},
	} {
		ids := map[int64]struct{}{}
		for id := range group.up {
			ids[id] = struct{}{}
		}
		for id := range group.down {
			ids[id] = struct{}{}
		}
		for id := range ids {
			if err := write(group.scope, group.protocol, id, group.up[id], group.down[id]); err != nil {
				return err
			}
		}
	}
	return nil
}

// PruneMetricHistory uses small bounded deletions. Lifetime totals are never
// removed by time-series retention.
func (db *DB) PruneMetricHistory(ctx context.Context, now time.Time) error {
	settings, err := db.HistoryRetention(ctx)
	if err != nil {
		return err
	}
	return db.runRetention(ctx, "metric_history", now, func(tx *sql.Tx) (int64, error) {
		var deleted int64
		cutoffs := []struct {
			table string
			age   time.Duration
		}{
			{"metric_samples", time.Duration(settings.FineDays) * 24 * time.Hour}, {"metric_minutes", time.Duration(settings.FineDays) * 24 * time.Hour},
			{"metric_five_minutes", time.Duration(settings.FiveMinuteDays) * 24 * time.Hour}, {"metric_hours", time.Duration(settings.HourlyDays) * 24 * time.Hour},
			{"metric_batches", 48 * time.Hour},
		}
		for _, item := range cutoffs {
			column := "bucket_at"
			if item.table == "metric_samples" {
				column = "sampled_at"
			}
			if item.table == "metric_batches" {
				column = "written_at"
			}
			query := `DELETE FROM ` + item.table + ` WHERE rowid IN (SELECT rowid FROM ` + item.table + ` WHERE ` + column + ` < ? LIMIT 2048)`
			result, err := tx.ExecContext(ctx, query, now.Add(-item.age).UTC().Format("2006-01-02T15:04:05.000000000Z07:00"))
			if err != nil {
				return 0, err
			}
			n, err := result.RowsAffected()
			if err != nil {
				return 0, err
			}
			deleted += n
		}
		return deleted, nil
	})
}

// MetricPoint is one stored aggregate. A gap indicates a missed sampling
// interval; its byte delta is deliberately zero rather than a false spike.
type MetricPoint struct {
	At      time.Time `json:"at"`
	Up      uint64    `json:"up_bytes"`
	Down    uint64    `json:"down_bytes"`
	Samples int       `json:"samples"`
	Gaps    int       `json:"gaps"`
}

// MetricHistory chooses a coarser table for longer windows. Every query is
// time bounded by its caller and returns at most 1000 points.
func (db *DB) MetricHistory(ctx context.Context, window string) ([]MetricPoint, string, error) {
	var table, resolution string
	var age time.Duration
	switch window {
	case "1h", "":
		table, resolution, age = "metric_minutes", "1m", time.Hour
	case "24h":
		table, resolution, age = "metric_five_minutes", "5m", 24*time.Hour
	case "7d":
		table, resolution, age = "metric_hours", "1h", 7*24*time.Hour
	case "30d":
		table, resolution, age = "metric_hours", "1h", 30*24*time.Hour
	default:
		return nil, "", ErrMetricBatch
	}
	cutoff := time.Now().UTC().Add(-age).Format(time.RFC3339)
	query := `SELECT bucket_at, up_bytes, down_bytes, samples, gaps FROM ` + table + ` WHERE bucket_at >= ? ORDER BY bucket_at DESC LIMIT 1000`
	rows, err := db.QueryRows(ctx, query, cutoff)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	points := []MetricPoint{}
	for rows.Next() {
		var at string
		var up, down int64
		var samples, gaps int
		if err := rows.Scan(&at, &up, &down, &samples, &gaps); err != nil {
			return nil, "", err
		}
		if up < 0 || down < 0 {
			return nil, "", ErrMetricBatch
		}
		parsed, err := time.Parse(time.RFC3339, at)
		if err != nil {
			return nil, "", err
		}
		points = append(points, MetricPoint{At: parsed, Up: uint64(up), Down: uint64(down), Samples: samples, Gaps: gaps})
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	for left, right := 0, len(points)-1; left < right; left, right = left+1, right-1 {
		points[left], points[right] = points[right], points[left]
	}
	return points, resolution, nil
}
