package sqlite

import (
	"context"
	"database/sql"
	"errors"
)

type MetricSettings struct {
	SampleSec  int   `json:"sample_sec"`
	RefreshSec int   `json:"refresh_sec"`
	Revision   int64 `json:"-"`
}

func (db *DB) MetricSettings(ctx context.Context) (MetricSettings, error) {
	var item MetricSettings
	err := db.QueryRow(ctx, `SELECT m.sample_sec, m.refresh_sec, r.desired_revision FROM metric_settings m JOIN config_revisions r ON r.domain = 'storage' WHERE m.id = 1`).Scan(&item.SampleSec, &item.RefreshSec, &item.Revision)
	return item, err
}
func (db *DB) SetMetricSettings(ctx context.Context, item MetricSettings) error {
	if item.SampleSec < 1 || item.SampleSec > 60 || item.RefreshSec < 1 || item.RefreshSec > 60 {
		return errors.New("invalid metric interval")
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE metric_settings SET sample_sec = ?, refresh_sec = ? WHERE id = 1`, item.SampleSec, item.RefreshSec)
		return err
	})
}
