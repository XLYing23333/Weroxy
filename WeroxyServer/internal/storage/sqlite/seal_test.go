package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeviceKeysEncryptedAndMasterRequired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weroxy.db")
	db, err := Open(path, DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := db.AddLegacyDevice(ctx, "old", []byte("legacy-mac"), "secret-legacy-key"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddWeroxyDevice(ctx, "new", "uid-1", []byte("token-mac"), "secret-new-token"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"legacy_devices", "weroxy_devices"} {
		var stored string
		if err := db.QueryRow(ctx, `SELECT client_key FROM `+table).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(stored, sealPrefix) || strings.Contains(stored, "secret-") {
			t.Fatalf("unencrypted %s key", table)
		}
	}
	legacy, _, err := db.ListLegacy(ctx)
	if err != nil || legacy[0].ClientKey != "secret-legacy-key" {
		t.Fatalf("legacy key unavailable: %v", err)
	}
	modern, _, err := db.ListWeroxy(ctx)
	if err != nil || modern[0].ClientKey != "secret-new-token" {
		t.Fatalf("weroxy key unavailable: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, sealFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("master mode: %v, %v", info, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, sealFile), filepath.Join(dir, "saved-seal.key")); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path, DefaultQueue); err == nil {
		opened.Close()
		t.Fatal("opened encrypted DB without master secret")
	}
	if err := os.Rename(filepath.Join(dir, "saved-seal.key"), filepath.Join(dir, sealFile)); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(path, DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	opened.Close()
}

func TestRestoreRejectsForeignSealAndDisablesRestoredDevices(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "weroxy.db"), DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.AddLegacyDevice(ctx, "old", []byte("old-mac"), "old-key"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddWeroxyDevice(ctx, "new", "uid-1", []byte("new-mac"), "new-key"); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(dir, "backups")
	backup, err := db.BackupFile(ctx, backupDir)
	if err != nil {
		t.Fatal(err)
	}
	otherDir := t.TempDir()
	other, err := Open(filepath.Join(otherDir, "weroxy.db"), DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := other.BackupFile(ctx, filepath.Join(otherDir, "backups"))
	other.Close()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(otherDir, "backups", foreign))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "foreign.db"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := db.RestoreFile(ctx, backupDir, "foreign.db"); err == nil {
		t.Fatal("foreign master secret was accepted")
	}
	currentBytes, err := os.ReadFile(filepath.Join(backupDir, backup))
	if err != nil {
		t.Fatal(err)
	}
	olderPath := filepath.Join(backupDir, "old-schema.db")
	if err := os.WriteFile(olderPath, currentBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	older, err := sql.Open("sqlite", olderPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := older.Exec(`DELETE FROM schema_migrations WHERE version = 14`); err != nil {
		older.Close()
		t.Fatal(err)
	}
	if err := older.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.RestoreFile(ctx, backupDir, "old-schema.db"); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("incompatible backup accepted: %v", err)
	}
	if err := db.RestoreFile(ctx, backupDir, backup); err != nil {
		t.Fatal(err)
	}
	legacy, _, err := db.ListLegacy(ctx)
	if err != nil || len(legacy) != 1 || !legacy[0].Paused {
		t.Fatalf("legacy restored enabled: %v %v", legacy, err)
	}
	modern, _, err := db.ListWeroxy(ctx)
	if err != nil || len(modern) != 1 || !modern[0].Paused || !modern[0].Revoked {
		t.Fatalf("weroxy restored enabled: %v %v", modern, err)
	}
}
