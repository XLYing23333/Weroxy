package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRedactAndSkipDebugShape(t *testing.T) {
	dir := t.TempDir()
	log := New(Options{Dir: dir, MaxFile: 1 << 20, MaxTotal: 4 << 20, Retain: time.Hour})
	log.Info("login password=supersecretvalue", map[string]string{
		"password":  "supersecretvalue",
		"clientKey": "client-key-value",
		"token":     "token-value",
		"username":  "admin",
	})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, activeName))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, secret := range []string{"supersecretvalue", "client-key-value", "token-value"} {
		if strings.Contains(text, secret) {
			t.Fatalf("log contains %s: %s", secret, text)
		}
	}
	if !strings.Contains(text, `"level":"INFO"`) || !strings.Contains(text, "[redacted]") {
		t.Fatalf("record = %s", text)
	}
	if !strings.Contains(text, "admin") {
		t.Fatalf("username missing: %s", text)
	}
}

func TestRotateAndRetention(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	var notes strings.Builder
	log := New(Options{
		Dir:      dir,
		MaxFile:  180,
		MaxTotal: 520,
		Retain:   time.Hour,
		Err:      &notes,
		Now:      func() time.Time { return now },
	})
	for i := 0; i < 20; i++ {
		log.Info(strings.Repeat("a", 40), nil)
	}
	old := filepath.Join(dir, "weroxy-20000101T000000.000000000Z.log")
	if err := os.WriteFile(old, []byte("old-secret-line\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	past := now.Add(-2 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	log.Info("after-retention", nil)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old file err=%v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "old-secret-line") {
			t.Fatal("expired log kept")
		}
	}
	if total > 520+400 {
		t.Fatalf("total %d entries %d", total, len(entries))
	}
	if len(entries) < 2 {
		t.Fatalf("entries %d notes=%q", len(entries), notes.String())
	}
}

func TestWriteFailureIsRateLimited(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "logs")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var notices strings.Builder
	log := New(Options{Dir: blocked, Err: &notices, MaxFile: 100, MaxTotal: 100})
	for i := 0; i < 5; i++ {
		log.Info("hello", nil)
	}
	if got := strings.Count(notices.String(), "log write degraded"); got != 1 {
		t.Fatalf("notices=%q count=%d", notices.String(), got)
	}
}

func TestRotatedFileCountIsBounded(t *testing.T) {
	dir := t.TempDir()
	log := New(Options{Dir: dir, MaxFile: 150, MaxTotal: 1 << 20, MaxFiles: 3})
	for i := 0; i < 50; i++ {
		log.Info("short rotation line", nil)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > 3 || len(entries) < 2 {
		t.Fatalf("files=%d", len(entries))
	}
}

func TestDiagnosticFloodIsBoundedAndRecovers(t *testing.T) {
	now := time.Now().UTC()
	log := New(Options{Dir: t.TempDir(), Now: func() time.Time { return now }})
	for i := 0; i < 50000; i++ {
		log.InfoLimited(fmt.Sprint("event-", i), map[string]string{"ip": fmt.Sprint(i)})
	}
	if len(log.events) > 65 || log.suppressed.Load() < 49000 {
		t.Fatalf("events=%d suppressed=%d", len(log.events), log.suppressed.Load())
	}
	body, err := os.ReadFile(filepath.Join(log.dir, activeName))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(body), "\n"); n > 650 {
		t.Fatalf("flood wrote %d lines", n)
	}
	now = now.Add(time.Minute)
	log.InfoLimited("event-49999", nil)
	body, err = os.ReadFile(filepath.Join(log.dir, activeName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "suppressed_previous_window") {
		t.Fatal("suppression summary absent")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
}
