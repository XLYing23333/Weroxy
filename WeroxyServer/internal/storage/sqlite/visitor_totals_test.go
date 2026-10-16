package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"weroxy/server/internal/metrics"
)

func TestVisitorCheckpointReplayRestartAndEviction(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")
	db, e := Open(path, DefaultQueue)
	if e != nil {
		t.Fatal(e)
	}
	c := metrics.New()
	for i := 0; i < 1100; i++ {
		id := string(rune(i + 100))
		c.Open(metrics.Weroxy, id, 1, 1)
		c.Annotate(metrics.Weroxy, id, "box", "192.0.2.1", "")
		c.Add(metrics.Weroxy, id, metrics.Up, 2)
		c.Close(metrics.Weroxy, id)
	}
	local := c.VisitorTotals(metrics.Weroxy, 1)
	if len(local) != 1 || local[0].Connections != 1100 {
		t.Fatal("eviction lost totals")
	}
	for i := 0; i < 2; i++ {
		if e = db.SaveVisitorTotals(ctx, local); e != nil {
			t.Fatal(e)
		}
	}
	rows, _, e := db.VisitorPage(ctx, metrics.Weroxy, 1, "", 100, c.VisitorRunID(), local, c.DeviceVisitors(metrics.Weroxy, 1))
	if e != nil || len(rows) != 1 || rows[0].Connections != 1100 || rows[0].Bytes != 2200 {
		t.Fatalf("replay: %+v %v", rows, e)
	}
	db.Close()
	db, e = Open(path, DefaultQueue)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	n := metrics.New()
	n.Open(metrics.Weroxy, "new", 1, 1)
	n.Annotate(metrics.Weroxy, "new", "renamed", "192.0.2.1", "")
	rows, _, e = db.VisitorPage(ctx, metrics.Weroxy, 1, "", 100, n.VisitorRunID(), n.VisitorTotals(metrics.Weroxy, 1), n.DeviceVisitors(metrics.Weroxy, 1))
	if e != nil || len(rows) != 1 || rows[0].Connections != 1101 || rows[0].ActiveConnections != 1 {
		t.Fatalf("restart overlay: %+v %v", rows, e)
	}
	if e = db.HideVisitors(ctx, metrics.Weroxy, 1, []string{"192.0.2.1"}); e != nil {
		t.Fatal(e)
	}
	rows, _, e = db.VisitorPage(ctx, metrics.Weroxy, 1, "", 100, "", nil, nil)
	if e != nil || len(rows) != 0 {
		t.Fatal("hidden visitor restored")
	}
	if e = db.SaveVisitorTotals(ctx, n.VisitorTotals(metrics.Weroxy, 1)); e != nil {
		t.Fatal(e)
	}
	rows, _, e = db.VisitorPage(ctx, metrics.Weroxy, 1, "", 100, "", nil, nil)
	if e != nil || len(rows) != 1 || rows[0].Connections != 1101 {
		t.Fatal("new visit failed to reappear")
	}
}

func TestVisitorPaginationAndStaleHideCheckpoint(t *testing.T) {
	db, e := Open(filepath.Join(t.TempDir(), "page.db"), DefaultQueue)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	c := metrics.New()
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		c.Open(metrics.Weroxy, ip, 1, 1)
		c.Annotate(metrics.Weroxy, ip, "box", ip, "")
		c.Close(metrics.Weroxy, ip)
	}
	stale := c.VisitorTotals(metrics.Weroxy, 1)
	if e = db.SaveVisitorTotals(t.Context(), stale); e != nil {
		t.Fatal(e)
	}
	c.DeleteVisitors(metrics.Weroxy, 1, []string{"192.0.2.1"})
	if e = db.SaveVisitorTotals(t.Context(), c.VisitorTotals(metrics.Weroxy, 1)); e != nil {
		t.Fatal(e)
	}
	if e = db.SaveVisitorTotals(t.Context(), stale); e != nil {
		t.Fatal(e)
	}
	first, next, e := db.VisitorPage(t.Context(), metrics.Weroxy, 1, "", 1, "", nil, nil)
	if e != nil || len(first) != 0 || next != "192.0.2.1" {
		t.Fatalf("hidden page: %+v %q %v", first, next, e)
	}
	second, next, e := db.VisitorPage(t.Context(), metrics.Weroxy, 1, next, 1, "", nil, nil)
	if e != nil || len(second) != 1 || second[0].IP != "192.0.2.2" || next != "192.0.2.2" {
		t.Fatal("cursor skipped visitor")
	}
	rows, _, e := db.VisitorPage(t.Context(), metrics.Legacy, 1, "", 100, "", nil, nil)
	if e != nil || len(rows) != 0 {
		t.Fatal("protocol leak")
	}
	rows, _, e = db.VisitorPage(t.Context(), metrics.Weroxy, 2, "", 100, "", nil, nil)
	if e != nil || len(rows) != 0 {
		t.Fatal("new identity inherited counters")
	}
}
