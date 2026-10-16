package webui

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"weroxy/server/internal/auth"
	"weroxy/server/internal/storage/sqlite"
)

func TestWebInitializationOnce(t *testing.T) {
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	token, err := auth.SetupToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &api{db: db, dataDir: dir, setupToken: token, pass: auth.NewArgon(), passwordSlots: make(chan struct{}, 2)}
	send := func(origin, credential, body string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "http://localhost/api/v1/setup", strings.NewReader(body))
		req.Header.Set("Origin", origin)
		req.Header.Set("X-Weroxy-Setup", credential)
		a.serve(w, req)
		return w.Code
	}
	good := `{"username":"owner","password":"123456","confirm":"123456"}`
	if send("http://evil.example", token, good) != 403 || send("http://localhost", "", good) != 403 {
		t.Fatal("setup authorization")
	}
	if send("http://localhost", token, `{"username":"bad name","password":"123456","confirm":"123456"}`) != 400 || send("http://localhost", token, `{"username":"owner","password":"12345","confirm":"12345"}`) != 400 || send("http://localhost", token, `{"username":"owner","password":"123456","confirm":"different"}`) != 400 {
		t.Fatal("setup validation")
	}
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- send("http://localhost", token, good) }()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for code := range results {
		if code == 201 {
			success++
		} else if code == 409 {
			conflict++
		} else {
			t.Fatalf("unexpected setup result %d", code)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("concurrent initialization")
	}
	if _, err := os.Stat(auth.SetupPath(dir)); !os.IsNotExist(err) {
		t.Fatal("setup credential not removed")
	}
	if send("http://localhost", token, good) != 409 {
		t.Fatal("reinitialization")
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://localhost/api/v1/setup", nil)
	req.Header.Set("X-Weroxy-Setup", token)
	a.serve(w, req)
	if strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), `"authorized":true`) {
		t.Fatal("setup path still active")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	addr, err := Start(ctx, Options{Addr: "127.0.0.1:0", DB: db, DataDir: dir, SetupOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest("POST", "http://"+addr+"/api/v1/auth/login", strings.NewReader(`{"username":"owner","password":"123456"}`))
	req.Header.Set("Origin", "http://"+addr)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("initialized account failed after restart")
	}
}
func TestProtocolCountsAndCadenceTransition(t *testing.T) {
	h := &Hub{}
	devices := []DeviceSample{{Protocol: "weroxy", Name: "same", Online: true}, {Protocol: "legacy", Name: "same", Online: true}, {Protocol: "weroxy", Name: "offline"}}
	got := h.Dashboard(0, devices)
	if got["online_devices"] != 2 || got["online_weroxy_devices"] != 1 || got["online_legacy_devices"] != 1 {
		t.Fatal("protocol counts omit device without forwards")
	}
	base := time.Now().UTC().Truncate(time.Minute)
	h.deviceSamples = nil
	h.noteDevices(base, devices, time.Minute)
	h.noteDevices(base.Add(time.Minute), devices, 5*time.Minute)
	for _, points := range h.deviceSamples {
		if len(points) != 2 || points[1].DurationSec != 300 {
			t.Fatal("cadence transition leaves a gap")
		}
	}
}
