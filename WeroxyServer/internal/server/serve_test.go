package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weroxy/server/internal/logging"
)

func TestServeDoesNotRequireAdmin(t *testing.T) {
	dir := t.TempDir()
	log := logging.New(logging.Options{Dir: filepath.Join(dir, "logs")})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, dir, log, "", "", "")
	}()
	deadline := time.Now().Add(2 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		body = readLog(filepath.Join(dir, "logs"))
		// The account notice precedes database/runtime initialization. Wait for
		// full runtime before cancellation rather than racing startup.
		if strings.Contains(body, "server runtime started") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(body, "server runtime started") {
		cancel()
		<-done
		t.Fatalf("server did not start without an administrator: %s", body)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = log.Close()
	body = readLog(filepath.Join(dir, "logs"))
	if !strings.Contains(body, "not initialized") {
		t.Fatalf("log=%s", body)
	}
}

func readLog(dir string) string {
	body, err := os.ReadFile(filepath.Join(dir, "weroxy.log"))
	if err != nil {
		return ""
	}
	return string(body)
}
