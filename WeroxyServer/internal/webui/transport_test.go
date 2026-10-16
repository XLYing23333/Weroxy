package webui

import (
	"context"
	"io"
	"net/http"
	"path/filepath"

	"testing"
	"time"
	"weroxy/server/internal/storage/sqlite"
)

func TestManagementWebAllowsHTTPOffLoopback(t *testing.T) {
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	addr, err := Start(ctx, Options{Addr: "0.0.0.0:0", DB: db})
	if err != nil {
		t.Fatal(err)
	}
	if addr == "" {
		t.Fatal("empty HTTP address")
	}
}

func TestQuickListUsesManagementListener(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	list := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "list:"+r.URL.Path)
	})
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	addr, err := Start(ctx, Options{Addr: "127.0.0.1:0", QuickList: list, DB: db})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	for _, path := range []string{"/list", "/healthz"} {
		res, err := client.Get("http://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		want := "list:" + path
		if path == "/healthz" {
			want = "ok\n"
		}
		if res.StatusCode != http.StatusOK || string(body) != want {
			t.Fatalf("%s: status=%d body=%q", path, res.StatusCode, body)
		}
	}
	res, err := client.Get("http://" + addr + "/api/v1/list")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("obsolete list alias: status=%d", res.StatusCode)
	}
}
