package quicklist

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"weroxy/server/internal/catalog"
)

func TestPublicListIsDisabledByDefaultAndOmitsTarget(t *testing.T) {
	enabled := false
	h := NewHandler(Options{Enabled: func() bool { return enabled }, Rows: func() []catalog.Row {
		return []catalog.Row{{Device: "desk", Port: 29010, Target: "127.0.0.1:22", ClientState: "ONLINE"}}
	}})
	request := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	if got := request("/list"); got.Code != http.StatusNotFound {
		t.Fatalf("disabled status %d", got.Code)
	}
	enabled = true
	got := request("/list")
	if got.Code != http.StatusOK || strings.Join(strings.Fields(got.Body.String()), " ") != "PORT DEVICE PROTOCOL STATUS 29010 desk weroxy online" || strings.Contains(got.Body.String(), "127.0.0.1") {
		t.Fatalf("list %d %s", got.Code, got.Body.String())
	}
	jsonResult := request("/api/v1/list")
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(jsonResult.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Items) != 1 || body.Items[0]["target"] != nil || body.Items[0]["port"] != float64(29010) {
		t.Fatalf("json %s", jsonResult.Body.String())
	}
}

func TestTerminalColumnsAndControls(t *testing.T) {
	h := NewHandler(Options{Enabled: func() bool { return true }, Rows: func() []catalog.Row {
		return []catalog.Row{{Port: 29000, Device: "中文机器", ClientState: "ONLINE"}, {Port: 29001, Device: "long_device_name\x1b\n", Legacy: true}}
	}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/list", nil))
	text := w.Body.String()
	if !strings.Contains(text, "\t") || strings.Contains(text, "\x1b") {
		t.Fatal("unsafe terminal output")
	}
	positions := []int{}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		parts := strings.Split(line, "\t")
		col := 0
		for _, p := range parts {
			if p == "weroxy" || p == "legacy" || p == "PROTOCOL" {
				positions = append(positions, col)
				break
			}
			col += terminalWidth(p)
			col = (col/8 + 1) * 8
		}
	}
	if len(positions) != 3 || positions[0] != positions[1] || positions[1] != positions[2] {
		t.Fatalf("unaligned protocol columns %v", positions)
	}
}
