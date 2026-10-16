package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"weroxy/server/internal/storage/sqlite"
)

func TestLegacyImportPreviewAndAtomicApply(t *testing.T) {
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	input := []byte(`[{"name":"old-a","clientKey":"private-a","status":1,"proxyMappings":[{"name":"ssh","inetPort":32001,"lan":"127.0.0.1:22"}]},{"name":"old-b","clientKey":"private-b","proxyMappings":[{"inetPort":32002,"lan":"192.0.2.9:80"}]}]`)
	file := filepath.Join(dir, "config.json")
	if err := os.WriteFile(file, input, 0o600); err != nil {
		t.Fatal(err)
	}
	invoke := func(mode string) (int, string, string) {
		var out, stderr bytes.Buffer
		code := Run([]string{"migrate", "lanproxy", "--file", file, "--data", dir, "--bind-host", "127.0.0.1", "--allow-ports", "32001-32002", mode}, Option{Stdout: &out, Stderr: &stderr})
		return code, out.String(), stderr.String()
	}
	dbPath := filepath.Join(dir, "weroxy.db")
	beforeDB, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	code, out, stderr := invoke("--dry-run")
	if code != 0 || !strings.Contains(out, "PREVIEW devices=2 forwards=2") || strings.Contains(out+stderr, "private-") {
		t.Fatalf("preview code=%d out=%s err=%s", code, out, stderr)
	}
	afterDB, err := os.ReadFile(dbPath)
	if err != nil || !bytes.Equal(beforeDB, afterDB) {
		t.Fatalf("dry-run changed source database bytes: %v", err)
	}
	afterEntries, err := os.ReadDir(dir)
	if err != nil || len(afterEntries) != len(beforeEntries) {
		t.Fatalf("dry-run changed source directory: before=%v after=%v err=%v", beforeEntries, afterEntries, err)
	}
	for i := range beforeEntries {
		if beforeEntries[i].Name() != afterEntries[i].Name() {
			t.Fatalf("dry-run added source file: before=%v after=%v", beforeEntries, afterEntries)
		}
	}
	db, err = sqlite.Open(filepath.Join(dir, "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := db.ListLegacy(context.Background())
	db.Close()
	if err != nil || len(rows) != 0 {
		t.Fatalf("preview left rows: %v %v", rows, err)
	}
	code, out, stderr = invoke("--apply")
	if code != 0 || !strings.Contains(out, "IMPORTED devices=2 forwards=2") || strings.Contains(out+stderr, "private-") {
		t.Fatalf("apply code=%d out=%s err=%s", code, out, stderr)
	}
	db, err = sqlite.Open(filepath.Join(dir, "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	rows, forwards, err := db.ListLegacy(context.Background())
	db.Close()
	if err != nil || len(rows) != 2 || len(forwards) != 2 || rows[0].ClientKey != "private-a" {
		t.Fatalf("import rows=%v forwards=%v err=%v", rows, forwards, err)
	}
	if data, _ := os.ReadFile(file); !bytes.Equal(data, input) {
		t.Fatal("source file changed")
	}
	bad := []byte(`[{"name":"third","clientKey":"private-c","proxyMappings":[{"inetPort":32003,"lan":"127.0.0.1:22"}]},{"name":"fourth","clientKey":"private-d","proxyMappings":[{"inetPort":32001,"lan":"127.0.0.1:80"}]}]`)
	if err := os.WriteFile(file, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = invoke("--apply")
	if code == 0 || !strings.Contains(out, "port_conflict") {
		t.Fatalf("conflicting import code=%d out=%s", code, out)
	}
	db, err = sqlite.Open(filepath.Join(dir, "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err = db.ListLegacy(context.Background())
	db.Close()
	if err != nil || len(rows) != 2 {
		t.Fatalf("partial import rows=%v err=%v", rows, err)
	}
}
