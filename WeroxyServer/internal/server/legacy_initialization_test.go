package server

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
	"weroxy/server/internal/legacy"
	"weroxy/server/internal/metrics"
	"weroxy/server/internal/policy"
	lp "weroxy/server/internal/protocol/legacy"
	"weroxy/server/internal/storage/sqlite"
)

func TestEmptyLegacyListenerAcceptsDeviceAddedAfterStartup(t *testing.T) {
	dir := t.TempDir()
	db, e := sqlite.Open(filepath.Join(dir, "weroxy.db"), sqlite.DefaultQueue)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	svc, e := listenLegacy(ctx, dir, nil, db, "127.0.0.1:0", metrics.New(), &policy.Table{}, policy.NewAdmission(16))
	if e != nil {
		t.Fatal(e)
	}
	secret, e := legacy.LoadSecret(dir, false)
	if e != nil {
		t.Fatal(e)
	}
	key := "legacy-post-start-regression-key"
	if e = db.AddLegacyDevice(ctx, "late-device", legacy.MAC(secret, []byte(key)), key); e != nil {
		t.Fatal(e)
	}
	go pollDevices(ctx, db, svc, nil)
	var addr string
	for _, a := range svc.EntryAddresses() {
		addr = a
	}
	conn, e := net.DialTimeout("tcp", addr, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	// The first reconciliation tick loads the initial desired snapshot.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		conn.Close()
		conn, e = net.DialTimeout("tcp", addr, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		frame, _ := lp.Encode(lp.Frame{Type: lp.TypeAuth, URI: key})
		conn.Write(frame)
		until := time.Now().Add(100 * time.Millisecond)
		for time.Now().Before(until) {
			if svc.OnlineDevices()["late-device"] {
				conn.Close()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	t.Fatal("new device was not authenticated without restarting listener")
}
func TestExistingLegacyDeviceMissingSecretFails(t *testing.T) {
	dir := t.TempDir()
	db, e := sqlite.Open(filepath.Join(dir, "weroxy.db"), sqlite.DefaultQueue)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if e = db.AddLegacyDevice(t.Context(), "existing", make([]byte, 32), "existing-key"); e != nil {
		t.Fatal(e)
	}
	_, e = listenLegacy(t.Context(), dir, nil, db, "127.0.0.1:0", metrics.New(), &policy.Table{}, policy.NewAdmission(16))
	if e == nil {
		t.Fatal("missing secret silently replaced")
	}
	if _, e = os.Stat(filepath.Join(dir, legacy.SecretFile)); !os.IsNotExist(e) {
		t.Fatal("unexpected replacement secret")
	}
}
