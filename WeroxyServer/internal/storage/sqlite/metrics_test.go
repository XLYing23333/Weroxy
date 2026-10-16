package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"weroxy/server/internal/metrics"
)

func TestMetricBatchRestoresTotalsWithoutDoubleCounting(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "weroxy.db")
	db, err := Open(path, DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Minute)
	snap := metrics.Snapshot{GlobalUp: 100, GlobalDown: 50, DeviceUp: map[int64]uint64{4: 100}, DeviceDown: map[int64]uint64{4: 50}}
	id := "00112233445566778899aabbccddeeff"
	if err := db.WriteMetricSnapshot(ctx, id, at, snap); err != nil {
		t.Fatal(err)
	}
	if err := db.WriteMetricSnapshot(ctx, id, at, snap); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM metric_samples`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate batch: count=%d err=%v", count, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path, DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	loaded, err := db.LoadMetricTotals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GlobalUp != 100 || loaded.GlobalDown != 50 || loaded.DeviceUp[4] != 100 {
		t.Fatalf("lost durable totals: %+v", loaded)
	}
	counter := metrics.New()
	counter.RestoreTotals(loaded)
	counter.Open(metrics.Weroxy, "new", 4, 9)
	counter.Add(metrics.Weroxy, "new", metrics.Up, 25)
	if err := db.WriteMetricSnapshot(ctx, "ffeeddccbbaa99887766554433221100", at.Add(5*time.Second), counter.TotalsSnapshot()); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT up_bytes FROM metric_samples ORDER BY sampled_at DESC LIMIT 1`).Scan(&count); err != nil || count != 25 {
		t.Fatalf("incorrect resumed delta: count=%d err=%v", count, err)
	}
	loaded, err = db.LoadMetricTotals(ctx)
	if err != nil || loaded.GlobalUp != 125 {
		t.Fatalf("incorrect lifetime total: up=%d err=%v", loaded.GlobalUp, err)
	}
	points, resolution, err := db.MetricHistory(ctx, "1h")
	if err != nil || resolution != "1m" || len(points) != 1 || points[0].Up != 25 || points[0].Gaps != 1 {
		t.Fatalf("incorrect aggregate: resolution=%s points=%+v err=%v", resolution, points, err)
	}
}

func TestCurrentTotalsExcludeDeletedEntitiesButKeepDurableHistory(t *testing.T) {
	ctx := t.Context()
	db, err := Open(filepath.Join(t.TempDir(), "state.db"), DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	snap := metrics.Snapshot{GlobalUp: 99, DeviceUp: map[int64]uint64{4: 99}, LegacyForwardDown: map[int64]uint64{5: 20}}
	if err := db.WriteMetricSnapshot(ctx, "00112233445566778899aabbccddeeff", time.Now(), snap); err != nil {
		t.Fatal(err)
	}
	live, err := db.LoadCurrentMetricTotals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if live.GlobalUp != 99 || len(live.DeviceUp) != 0 || len(live.LegacyForwardDown) != 0 {
		t.Fatal("deleted totals loaded into hot cache")
	}
	historical, err := db.LoadMetricTotals(ctx)
	if err != nil || historical.DeviceUp[4] != 99 || historical.LegacyForwardDown[5] != 20 {
		t.Fatal("durable history changed")
	}
}
