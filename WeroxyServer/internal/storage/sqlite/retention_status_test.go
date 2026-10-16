package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"weroxy/server/internal/metrics"
)

func TestConnectionDetailsRetainNewestThirtyPerDevice(t *testing.T) {
	db := openTemp(t, DefaultQueue)
	now := time.Now().UTC().Add(-time.Minute)
	var batch []metrics.Session
	for i := 0; i < 70; i++ {
		protocol := metrics.Weroxy
		if i%2 == 0 {
			protocol = metrics.Legacy
		}
		batch = append(batch, metrics.Session{RunID: "run", Protocol: protocol, ID: fmt.Sprint(i), DeviceID: 1, Device: "box", Started: now.Add(time.Duration(i) * time.Second), Last: now.Add(time.Duration(i) * time.Second)})
	}
	for i := 0; i < 4; i++ {
		batch = append(batch, metrics.Session{RunID: "run", Protocol: metrics.Weroxy, ID: fmt.Sprintf("other-%d", i), DeviceID: 2, Device: "other", Started: now, Last: now})
	}
	if err := db.SaveConnections(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[int64]int{1: 60, 2: 4} {
		var got int
		if err := db.QueryRow(context.Background(), `SELECT count(*) FROM connection_details WHERE device_id=?`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("device %d rows=%d want=%d", id, got, want)
		}
	}
	for _, protocol := range []string{metrics.Legacy, metrics.Weroxy} {
		var count int
		if err := db.QueryRow(context.Background(), `SELECT count(*) FROM connection_details WHERE device_id=1 AND protocol=?`, protocol).Scan(&count); err != nil || count != 30 {
			t.Fatalf("protocol %s: rows=%d err=%v", protocol, count, err)
		}
	}
	var old int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM connection_details WHERE device_id=1 AND session_id='0'`).Scan(&old); err != nil {
		t.Fatal(err)
	}
	if old != 0 {
		t.Fatal("oldest detail survived")
	}
}

func TestDeviceStatusSurvivesReopenWithoutInventedSamples(t *testing.T) {
	path := filepath.Join(t.TempDir(), "weroxy.db")
	db, err := Open(path, DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	samples := []DeviceStatus{{Protocol: "weroxy", Device: "box", At: at, DurationSec: 60, State: "online", Sessions: 4}, {Protocol: "weroxy", Device: "box", At: at.Add(2 * time.Minute), DurationSec: 60, State: "offline"}}
	if err := db.SaveDeviceStatus(context.Background(), samples); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = Open(path, DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	loaded, err := db.LoadDeviceStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 || loaded[0].State != "offline" || loaded[1].Sessions != 4 {
		t.Fatalf("loaded=%+v", loaded)
	}
}

func TestDeviceHistoryRestoreHasPerDeviceLimit(t *testing.T) {
	db := openTemp(t, DefaultQueue)
	// 120 devices * 180 observations exceeded the old global 20,000-row limit.
	now := time.Now().UTC()
	ctx := t.Context()
	for minute := 0; minute < 180; minute++ {
		batch := make([]DeviceStatus, 0, 120)
		for device := 0; device < 120; device++ {
			batch = append(batch, DeviceStatus{Protocol: "weroxy", Device: fmt.Sprintf("device-%03d", device), At: now.Add(-time.Duration(minute) * time.Minute), DurationSec: 60, State: "online"})
		}
		if err := db.SaveDeviceStatus(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.LoadDeviceStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, row := range rows {
		counts[row.Device]++
	}
	if len(counts) != 120 {
		t.Fatalf("restored devices %d", len(counts))
	}
	for _, count := range counts {
		if count != 180 {
			t.Fatalf("restored points %d", count)
		}
	}
}
