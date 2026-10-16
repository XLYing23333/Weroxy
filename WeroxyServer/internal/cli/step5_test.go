package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"weroxy/server/internal/storage/sqlite"
)

func TestPoolPolicyAndCapacity(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	opt := Option{Stdout: &stdout, Stderr: &stderr}
	run := func(args ...string) {
		t.Helper()
		stdout.Reset()
		stderr.Reset()
		if code := Run(args, opt); code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, stderr.String())
		}
	}
	fail := func(args ...string) string {
		t.Helper()
		stdout.Reset()
		stderr.Reset()
		if code := Run(args, opt); code == 0 {
			t.Fatalf("%v was stored", args)
		}
		return stderr.String()
	}
	run("weroxy", "device", "add", "--data", dir, "--name", "box")
	token := tokenLine(t, stdout.String())
	walkSecret(t, filepath.Join(dir, "logs"), token)
	run("weroxy", "pool", "set", "--data", dir, "--forward-pool", "20000-20099", "--data-pool", "21000-21119", "--reserved", "10", "--bind-host", "127.0.0.1")
	run("weroxy", "device", "limit", "--data", dir, "--name", "box", "--max-data-ports", "6")
	if !strings.Contains(fail("weroxy", "forward", "add", "--data", dir, "--device", "box", "--listen", "127.0.0.1:19999", "--target", "127.0.0.1:9"), "port range") {
		t.Fatalf("outside=%s", stderr.String())
	}
	run("weroxy", "forward", "add", "--data", dir, "--device", "box", "--listen", "127.0.0.1:24150", "--target", "127.0.0.1:9", "--import")
	run("weroxy", "forward", "add", "--data", dir, "--device", "box", "--listen", "127.0.0.1:20010", "--target", "127.0.0.1:9", "--mode", "shared", "--min", "1", "--preferred", "4", "--max", "8")
	run("weroxy", "capacity", "show", "--data", dir)
	var views []struct {
		ForwardID         int64    `json:"forward_id"`
		ConfiguredMax     *int     `json:"configured_max"`
		Current           *int     `json:"current"`
		AvailableMaxTotal *int     `json:"available_max_total"`
		CanGrowBy         *int     `json:"can_grow_by"`
		LimitingReasons   []string `json:"limiting_reasons"`
		Legacy            bool     `json:"legacy"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &views); err != nil {
		t.Fatalf("capacity %s: %v", stdout.String(), err)
	}
	var matched bool
	for _, view := range views {
		if view.Legacy || view.Current == nil || *view.Current != 4 {
			continue
		}
		matched = true
		if view.ConfiguredMax == nil || *view.ConfiguredMax != 8 || view.AvailableMaxTotal == nil || *view.AvailableMaxTotal != 6 || view.CanGrowBy == nil || *view.CanGrowBy != 2 {
			t.Fatalf("view=%+v", view)
		}
		found := false
		for _, reason := range view.LimitingReasons {
			if reason == "device_port_quota" {
				found = true
			}
		}
		if !found {
			t.Fatalf("reasons=%v", view.LimitingReasons)
		}
	}
	if !matched {
		t.Fatalf("views=%s", stdout.String())
	}
	run("weroxy", "policy", "set", "--data", dir, "--scope", "global", "--max-per-ip", "1")
	if !strings.Contains(fail("weroxy", "policy", "set", "--data", dir, "--scope", "forward", "--device", "box", "--listen", "127.0.0.1:20010", "--max-per-ip", "2"), "less restrictive") {
		t.Fatalf("looser=%s", stderr.String())
	}
	run("weroxy", "policy", "set", "--data", dir, "--scope", "forward", "--device", "box", "--listen", "127.0.0.1:20010", "--max-per-ip", "0")
	db, err := sqlite.Open(filepath.Join(dir, "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	items, err := db.ListAssignments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ports := map[int]int{}
	for _, item := range items {
		ports[item.Port]++
		if item.Port > 21109 {
			t.Fatalf("reserved port %d", item.Port)
		}
	}
	if len(ports) != 4 {
		t.Fatalf("ports=%v", ports)
	}

}

func tokenLine(t *testing.T, text string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "token: ") {
			return strings.TrimPrefix(line, "token: ")
		}
	}
	t.Fatalf("token missing: %s", text)
	return ""
}
