package server

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"weroxy/server/internal/storage/sqlite"
)

func TestPreflightRejectsConflictingConfiguredEntrances(t *testing.T) {
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.AddLegacyDevice(ctx, "box", make([]byte, 32), "key-for-preflight"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddLegacyForward(ctx, "box", "127.0.0.1:25001", "127.0.0.1:22"); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []Config{
		{LegacyListen: "127.0.0.1:25001"},
		{LegacyListen: "127.0.0.1:26001", WeroxyControl: "127.0.0.1:26001"},
		{LegacyListen: "127.0.0.1:26001", Web: "0.0.0.0:26001"},
	} {
		if err := preflightListeners(ctx, db, cfg); err == nil || !strings.Contains(err.Error(), "conflicts") {
			t.Fatalf("cfg=%+v err=%v", cfg, err)
		}
	}
}

func TestPreflightAllowsPublicHTTPWebAndRejectsSeparateQuickList(t *testing.T) {
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := preflightListeners(ctx, db, Config{Web: "0.0.0.0:9415"}); err != nil {
		t.Fatalf("public HTTP Web: %v", err)
	}
	if err := preflightListeners(ctx, db, Config{QuickList: "127.0.0.1:8091"}); err == nil || !strings.Contains(err.Error(), "/list") {
		t.Fatalf("separate Quick List: %v", err)
	}
}
