package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	token := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if err := os.WriteFile(path, []byte(token+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTokenFile(path); err == nil {
		t.Fatal("group-readable key was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTokenFile(path)
	if err != nil || len(got) != 32 {
		t.Fatalf("len=%d err=%v", len(got), err)
	}
	cfg := "server.host=127.0.0.1\nserver.port=29999\nclient.key=" + token + "\n"
	file := filepath.Join(dir, "client.conf")
	if err := os.WriteFile(file, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file); err == nil {
		t.Fatal("group-readable profile was accepted")
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Server != "127.0.0.1:29999" || loaded.Key != token {
		t.Fatalf("server=%s", loaded.Server)
	}
	if strings.Contains(cfg, "InsecureSkipVerify") {
		t.Fatal("config skips verification")
	}
}

func TestProfileSaveDropsLegacyPolicies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.conf")
	key := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if err := Save(path, "127.0.0.1", key, "29999"); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err != nil {
		t.Fatalf("load err=%v", err)
	}
	if err := Save(path, "127.0.0.2", key, "29999"); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil || cfg.Server != "127.0.0.2:29999" {
		t.Fatalf("updated=%+v err=%v", cfg, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info, err)
	}
}

func TestOldPolicyFieldsIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.conf")
	key := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if err := Save(path, "127.0.0.1", key, "29999"); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err != nil {
		t.Fatalf("load err=%v", err)
	}
	body, _ := os.ReadFile(path)
	body = append(body, []byte("tls_cert=/missing/old.crt\ntarget.allow=malformed-policy\ntarget.deny_cidr=invalid\ntarget.deny_port=broken\n")...)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, "127.0.0.1", key, "29999"); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(path)
	if strings.Contains(string(saved), "target.") || strings.Contains(string(saved), "tls_cert") {
		t.Fatal("old fields retained")
	}

}
