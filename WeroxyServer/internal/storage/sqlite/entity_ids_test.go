package sqlite

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"weroxy/server/internal/legacy"
	"weroxy/server/internal/metrics"
)

func TestEntityIDsDoNotReuseDeletedDeviceOrForward(t *testing.T) {
	for _, protocol := range []string{"legacy", "weroxy"} {
		t.Run(protocol, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.db")
			db, err := Open(path, DefaultQueue)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { db.Close() }()
			ctx := t.Context()
			add := func(name string) {
				t.Helper()
				var err error
				if protocol == "legacy" {
					err = db.AddLegacyDevice(ctx, name, []byte(name), "key-"+name)
					if err == nil {
						err = db.AddLegacyForward(ctx, name, "127.0.0.1:29000", "127.0.0.1:22")
					}
				} else {
					err = db.AddWeroxyDevice(ctx, name, "uid-"+name, []byte(name), "key-"+name)
					if err == nil {
						err = db.AddWeroxyForward(ctx, name, "127.0.0.1:29000", "127.0.0.1:22", "shared", 1, 1, 4, false, false)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			ids := func() (int64, int64) {
				t.Helper()
				var d, f int64
				if err := db.QueryRow(ctx, "SELECT id FROM "+protocol+"_devices").Scan(&d); err != nil {
					t.Fatal(err)
				}
				if err := db.QueryRow(ctx, "SELECT id FROM "+protocol+"_forwards").Scan(&f); err != nil {
					t.Fatal(err)
				}
				return d, f
			}
			add("old")
			oldD, oldF := ids()
			snap := metrics.Snapshot{GlobalUp: 1234}
			if protocol == "legacy" {
				snap.LegacyDeviceUp = map[int64]uint64{oldD: 1234}
				snap.LegacyForwardUp = map[int64]uint64{oldF: 1234}
			} else {
				snap.DeviceUp = map[int64]uint64{oldD: 1234}
				snap.ForwardUp = map[int64]uint64{oldF: 1234}
			}
			if err := db.WriteMetricSnapshot(ctx, "00112233445566778899aabbccddeeff", time.Now(), snap); err != nil {
				t.Fatal(err)
			}
			if protocol == "legacy" {
				err = db.DeleteLegacyDevice(ctx, "old")
			} else {
				err = db.DeleteWeroxyDevice(ctx, "old")
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = Open(path, DefaultQueue)
			if err != nil {
				t.Fatal(err)
			}
			add("new")
			newD, newF := ids()
			if newD <= oldD || newF <= oldF {
				t.Fatal("deleted entity IDs reused across restart")
			}
			current, err := db.LoadCurrentMetricTotals(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if current.DeviceUp[newD] != 0 || current.ForwardUp[newF] != 0 || current.LegacyDeviceUp[newD] != 0 || current.LegacyForwardUp[newF] != 0 {
				t.Fatal("new entity inherited historical traffic")
			}
			history, err := db.LoadMetricTotals(ctx)
			if err != nil || history.GlobalUp != 1234 {
				t.Fatal("lifetime history lost")
			}
			if protocol == "legacy" && history.LegacyDeviceUp[oldD] != 1234 || protocol == "weroxy" && history.DeviceUp[oldD] != 1234 {
				t.Fatal("deleted entity history removed")
			}
		})
	}
}
func TestProtocolSwitchNeverReusesProtocolEntityIDs(t *testing.T) {
	ctx := t.Context()
	db, err := Open(filepath.Join(t.TempDir(), "state.db"), DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	secret := bytes.Repeat([]byte{7}, 32)
	key := "fixture-legacy-key"
	if err = db.AddLegacyDevice(ctx, "switch", legacy.MAC(secret, []byte(key)), key); err != nil {
		t.Fatal(err)
	}
	if err = db.AddLegacyForward(ctx, "switch", "127.0.0.1:29000", "127.0.0.1:22"); err != nil {
		t.Fatal(err)
	}
	var d, f int64
	db.QueryRow(ctx, `SELECT id FROM legacy_devices`).Scan(&d)
	db.QueryRow(ctx, `SELECT id FROM legacy_forwards`).Scan(&f)
	if _, err = db.SwitchProtocol(ctx, "legacy", "switch", secret); err != nil {
		t.Fatal(err)
	}
	if _, err = db.SwitchProtocol(ctx, "weroxy", "switch", secret); err != nil {
		t.Fatal(err)
	}
	var newD, newF int64
	db.QueryRow(ctx, `SELECT id FROM legacy_devices`).Scan(&newD)
	db.QueryRow(ctx, `SELECT id FROM legacy_forwards`).Scan(&newF)
	if newD <= d || newF <= f {
		t.Fatal("protocol return reused old identity")
	}
}
func TestOldSnapshotUpgradePreservesLiveIDAndRevisionWatermarks(t *testing.T) {
	f := newRestoreFixture(t)
	ctx := t.Context()
	if err := f.db.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE entity_id_sequences SET last_id=1000; UPDATE config_revisions SET desired_revision=200,applied_revision=200`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	old, err := sql.Open("sqlite", filepath.Join(f.dir, "backups", f.backup))
	if err != nil {
		t.Fatal(err)
	}
	// Reconstruct a genuine previous 0.3.0 schema, not merely a fake version row.
	for _, table := range []string{"legacy_devices", "legacy_forwards", "weroxy_devices", "weroxy_forwards"} {
		if _, err := old.Exec(`DROP TRIGGER ` + table + `_id_high_water`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := old.Exec(`DROP TABLE visitor_checkpoints;DROP TABLE visitor_totals;DROP TABLE entity_id_sequences;DELETE FROM schema_migrations WHERE version>=41`); err != nil {
		t.Fatal(err)
	}
	old.Close()
	if err = f.db.RestoreFile(ctx, filepath.Join(f.dir, "backups"), f.backup); err != nil {
		t.Fatal(err)
	}
	f.restored(t)
	if err = f.db.AddWeroxyDevice(ctx, "post-restore", "uid-post", []byte("mac-post"), "key-post"); err != nil {
		t.Fatal(err)
	}
	var id int64
	f.db.QueryRow(ctx, `SELECT id FROM weroxy_devices WHERE name='post-restore'`).Scan(&id)
	if id <= 1000 {
		t.Fatal("restore reused a live historical ID ceiling")
	}
	var revision int64
	f.db.QueryRow(ctx, `SELECT desired_revision FROM config_revisions WHERE domain='credential'`).Scan(&revision)
	if revision <= 200 {
		t.Fatal("restore did not wake credential reconciler")
	}
}
