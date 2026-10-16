package config

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func TestUserPathWithoutHomeEnvironment(t *testing.T) {
	t.Setenv("HOME", "")
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	path, err := DefaultUserPath()
	if err != nil || path != filepath.Join(account.HomeDir, ".config", "weroxy_client", "client.conf") {
		t.Fatalf("path=%s err=%v", path, err)
	}
}

func TestInitialProfileCanBeConfiguredAndIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "weroxy_client", "client.conf")
	if err := EnsureUserProfile(path); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Dir(path), path} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if p == filepath.Dir(path) {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("mode=%o", info.Mode().Perm())
		}
	}
	if _, err := Load(path); !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("initial profile: %v", err)
	}
	key := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if err := Save(path, "127.0.0.1", key, "29999"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := EnsureUserProfile(path); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("installer replaced an existing profile")
	}
	cfg, err := Load(path)
	if err != nil || cfg.Key != key {
		t.Fatalf("saved profile: %v", err)
	}
}

func TestProfileRefusesSymlinksAndCorruptExistingContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "client.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := EnsureUserProfile(link); err == nil {
		t.Fatal("symlink accepted")
	}
	key := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if err := Save(target, "127.0.0.1", key, "29999"); err != nil {
		t.Fatal(err)
	}
	backups, _ := filepath.Glob(target + ".repair-*.bak")
	if len(backups) != 1 {
		t.Fatal("repair backup missing")
	}
	body, _ := os.ReadFile(backups[0])
	if string(body) != "unchanged" {
		t.Fatal("backup changed")
	}
	if _, err := Load(target); err != nil {
		t.Fatal(err)
	}
}

func TestPurgeBrokenProfileRemovesOwnCredentialsOnly(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "weroxy_client")
	other := filepath.Join(root, "other")
	_ = os.Mkdir(dir, 0700)
	_ = os.Mkdir(other, 0700)
	path := filepath.Join(dir, "client.conf")
	_ = os.WriteFile(path, []byte("broken"), 0600)
	for _, name := range []string{"client.key", ".weroxy-key-orphan", "client.conf.repair-old.bak"} {
		_ = os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0600)
	}
	keep := filepath.Join(other, "client.conf")
	_ = os.WriteFile(keep, []byte(InitialProfile), 0600)
	if err := Purge(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("own credentials remain")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("other profile removed")
	}
}
