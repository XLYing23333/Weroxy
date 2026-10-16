package sqlite

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRenamePreservesCredentialsIDsHistoryAndRollsBack(t *testing.T) {
	db := openTemp(t, DefaultQueue)
	ctx := t.Context()
	mac := []byte(strings.Repeat("m", 32))
	if e := db.AddWeroxyDevice(ctx, "before", "stable-uid", mac, "unchanged-secret"); e != nil {
		t.Fatal(e)
	}
	if e := db.AddLegacyDevice(ctx, "taken", mac, "legacy-secret"); e != nil {
		t.Fatal(e)
	}
	ds, _, _ := db.ListWeroxy(ctx)
	id := ds[0].ID
	archive, e := db.sealKey("before", "archived-secret")
	if e != nil {
		t.Fatal(e)
	}
	e = db.Do(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `INSERT INTO protocol_credential_archive VALUES(?,?,?)`, "before", archive, time.Now().UTC().Format(time.RFC3339Nano))
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	e = db.SaveDeviceStatus(ctx, []DeviceStatus{{Protocol: "weroxy", Device: "before", At: time.Now().UTC(), DurationSec: 60, State: "idle"}})
	if e != nil {
		t.Fatal(e)
	}
	if e = db.RenameDevice(ctx, "weroxy", "before", "taken"); !errors.Is(e, ErrWeroxyExists) {
		t.Fatal(e)
	}
	if e = db.RenameDevice(ctx, "weroxy", "before", "after"); e != nil {
		t.Fatal(e)
	}
	ds, _, e = db.ListWeroxy(ctx)
	if e != nil || len(ds) != 1 || ds[0].ID != id || ds[0].UID != "stable-uid" || ds[0].ClientKey != "unchanged-secret" || ds[0].Name != "after" {
		t.Fatalf("lost stable identity: %v", e)
	}
	if e = db.SaveDeviceStatus(ctx, []DeviceStatus{{DeviceID: id, Protocol: "weroxy", Device: "before", At: time.Now().UTC(), DurationSec: 60, State: "idle"}}); e != nil {
		t.Fatal(e)
	}
	var sealed string
	if e = db.QueryRow(ctx, "SELECT legacy_client_key FROM protocol_credential_archive WHERE device_name='after'").Scan(&sealed); e != nil {
		t.Fatal(e)
	}
	key, e := db.openKey("after", sealed)
	if e != nil || key != "archived-secret" {
		t.Fatal("archive not resealed")
	}
	if _, e = db.openKey("before", sealed); e == nil {
		t.Fatal("old AAD accepted")
	}
	rows, e := db.LoadDeviceStatus(ctx)
	if e != nil || len(rows) != 2 || rows[0].Device != "after" || rows[1].Device != "after" {
		t.Fatal("history lost")
	}
	e = db.Do(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, "UPDATE protocol_credential_archive SET legacy_client_key='enc:v1:corrupt' WHERE device_name='after'")
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	// Any seal error must leave both account name and its primary key untouched.
	if e = db.RenameDevice(ctx, "weroxy", "after", "failure"); e == nil {
		t.Fatal("bad archive accepted")
	}
	ds, _, e = db.ListWeroxy(ctx)
	if e != nil || ds[0].Name != "after" || ds[0].ClientKey != "unchanged-secret" {
		t.Fatal("partial rename")
	}
}
