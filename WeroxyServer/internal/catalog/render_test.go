package catalog

import (
	"strings"
	"testing"
	"time"
)

func TestTextColumnsLegacyAndClean(t *testing.T) {
	rows := []Row{
		{Port: 9, Device: "b\n\x1b[31m", Target: "10.0.0.2:22", ClientState: "OFFLINE", Legacy: true},
		{Port: 8, Device: "a box", Target: "10.0.0.1:22", ClientState: "ONLINE", Sessions: 2, DataCurrent: 1, DataMax: 4, AvailableMax: 6},
	}
	text := Text(rows, false)
	if !strings.HasPrefix(text, "PORT DEVICE TARGET CLIENT_STATE SESSIONS DATA_CUR/MAX AVAILABLE_MAX\n") {
		t.Fatalf("header=%q", text)
	}
	if strings.Contains(text, "\x1b") || strings.Contains(text, "b\n") {
		t.Fatalf("control text leaked: %q", text)
	}
	if !strings.Contains(text, "LEGACY") || !strings.Contains(text, "N/A") {
		t.Fatalf("legacy row=%q", text)
	}
	if !strings.Contains(text, "a_box") {
		t.Fatalf("space=%q", text)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "8 ") || !strings.HasPrefix(lines[2], "9 ") {
		t.Fatalf("order=%q", text)
	}
	body := string(JSON(rows, time.Date(2026, 9, 24, 0, 0, 0, 1, time.UTC), false, false, false))
	if !strings.Contains(body, `"schema_version":1`) || !strings.Contains(body, `"generated_at":"2026-09-24T00:00:00.000000001Z"`) {
		t.Fatalf("json=%s", body)
	}
	redacted := Text(rows, true)
	if strings.Contains(redacted, "10.0.0.1") || strings.Contains(redacted, "ONLINE") {
		t.Fatalf("redacted=%q", redacted)
	}
}
