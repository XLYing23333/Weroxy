package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"weroxy/server/internal/ports"
)

func TestForwardEditKeepsOldRowWhenNewPortConflicts(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "weroxy.db"), DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.AddLegacyDevice(ctx, "old", []byte("old-mac"), "old-key"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddLegacyForward(ctx, "old", "127.0.0.1:24001", "127.0.0.1:22"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddWeroxyDevice(ctx, "new", "uid-new", []byte("new-mac"), "new-key"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddWeroxyForward(ctx, "new", "127.0.0.1:24002", "127.0.0.1:80", ports.Shared, 1, 1, 1, false, false); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateLegacyForward(ctx, "old", "127.0.0.1:24001", "127.0.0.1:24002", "127.0.0.1:23"); !errors.Is(err, ErrPortConflict) {
		t.Fatalf("legacy conflict=%v", err)
	}
	_, old, err := db.ListLegacy(ctx)
	if err != nil || len(old) != 1 || old[0].Listen != "127.0.0.1:24001" || old[0].Target != "127.0.0.1:22" {
		t.Fatalf("legacy after failed edit=%v err=%v", old, err)
	}
	if err := db.UpdateWeroxyForward(ctx, "new", "127.0.0.1:24002", "127.0.0.1:24001", "127.0.0.1:81", ports.Shared, 1, 1, 1); !errors.Is(err, ErrPortConflict) {
		t.Fatalf("weroxy conflict=%v", err)
	}
	_, newer, err := db.ListWeroxy(ctx)
	if err != nil || len(newer) != 1 || newer[0].Listen != "127.0.0.1:24002" || newer[0].Target != "127.0.0.1:80" {
		t.Fatalf("weroxy after failed edit=%v err=%v", newer, err)
	}
	if err := db.UpdateLegacyForward(ctx, "old", "127.0.0.1:24001", "0.0.0.0:24001", "127.0.0.1:23"); err != nil {
		t.Fatal(err)
	}
	_, old, err = db.ListLegacy(ctx)
	if err != nil || old[0].Listen != "0.0.0.0:24001" || old[0].Target != "127.0.0.1:23" {
		t.Fatalf("legacy successful edit=%v err=%v", old, err)
	}
}

func TestWeroxyForwardEditRollsBackOnQuota(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "weroxy.db"), DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.SetPortPool(ctx, PortSettings{ForwardFirst: 24000, ForwardLast: 24099, DataFirst: 25000, DataLast: 25000, BindHost: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddWeroxyDevice(ctx, "box", "uid-box", []byte("mac-box"), "key-box"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddWeroxyForward(ctx, "box", "127.0.0.1:24001", "127.0.0.1:80", ports.Shared, 1, 1, 1, false, false); err != nil {
		t.Fatal(err)
	}
	err = db.UpdateWeroxyForward(ctx, "box", "127.0.0.1:24001", "127.0.0.1:24002", "127.0.0.1:81", ports.Exclusive, 2, 2, 2)
	if !errors.Is(err, ErrPortQuota) {
		t.Fatalf("quota edit=%v", err)
	}
	_, rows, err := db.ListWeroxy(ctx)
	if err != nil || len(rows) != 1 || rows[0].Listen != "127.0.0.1:24001" || rows[0].Target != "127.0.0.1:80" || rows[0].Min != 1 {
		t.Fatalf("row after quota=%v err=%v", rows, err)
	}
}
