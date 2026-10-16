// Package catalog renders the quick-list rows from one capacity snapshot.
package catalog

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Row is one public forward. Legacy rows leave data-port numbers unset.
type Row struct {
	ForwardID        int64    `json:"-"`
	DataPorts        []int    `json:"data_ports"`
	DataReachability string   `json:"data_reachability"`
	Listen           string   `json:"listen,omitempty"`
	DataHealthy      int      `json:"data_healthy"`
	DataDraining     int      `json:"data_draining"`
	CanGrow          int      `json:"can_grow"`
	Port             int      `json:"port"`
	Device           string   `json:"device"`
	Target           string   `json:"target"`
	ClientState      string   `json:"client_state"`
	Sessions         int      `json:"sessions"`
	DataCurrent      int      `json:"data_current"`
	DataMax          int      `json:"data_max"`
	AvailableMax     int      `json:"available_max"`
	Legacy           bool     `json:"legacy"`
	UpBytes          uint64   `json:"up_bytes"`
	DownBytes        uint64   `json:"down_bytes"`
	Reasons          []string `json:"limiting_reasons,omitempty"`
}

// Clean removes control characters so a device name cannot change the terminal.
func Clean(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r < 0x20 || r == 0x7f || unicode.Is(unicode.Cc, r) {
			continue
		}
		if unicode.IsSpace(r) {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// Sort orders rows by public port, device, then target.
func Sort(rows []Row) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Port != rows[j].Port {
			return rows[i].Port < rows[j].Port
		}
		if rows[i].Device != rows[j].Device {
			return rows[i].Device < rows[j].Device
		}
		return rows[i].Target < rows[j].Target
	})
}

// Text renders the stable quick-list columns.
func Text(rows []Row, redact bool) string {
	Sort(rows)
	var b strings.Builder
	fmt.Fprintln(&b, "PORT DEVICE TARGET CLIENT_STATE SESSIONS DATA_CUR/MAX AVAILABLE_MAX")
	for _, row := range rows {
		target := Clean(row.Target)
		state := row.ClientState
		sessions := fmt.Sprintf("%d", row.Sessions)
		data := fmt.Sprintf("%d/%d", row.DataCurrent, row.DataMax)
		available := fmt.Sprintf("%d", row.AvailableMax)
		if row.Legacy {
			data = "LEGACY"
			available = "N/A"
		}
		if redact {
			target = "-"
			state = "-"
			sessions = "-"
			data = "-"
			available = "-"
		}
		if state == "" {
			state = "OFFLINE"
		}
		fmt.Fprintf(&b, "%d %s %s %s %s %s %s\n", row.Port, Clean(row.Device), target, state, sessions, data, available)
	}
	return b.String()
}

// Document is the JSON list payload.
type Document struct {
	SchemaVersion int    `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	Stale         bool   `json:"stale"`
	Truncated     bool   `json:"truncated,omitempty"`
	Items         []Row  `json:"items"`
}

// JSON renders the same rows used by the text list.
func JSON(rows []Row, at time.Time, stale, redact, truncated bool) []byte {
	Sort(rows)
	items := make([]Row, len(rows))
	copy(items, rows)
	for i := range items {
		items[i].Device = Clean(items[i].Device)
		items[i].Target = Clean(items[i].Target)
		if items[i].ClientState == "" {
			items[i].ClientState = "OFFLINE"
		}
		if redact {
			items[i].Target = "-"
			items[i].ClientState = "-"
			items[i].Sessions = 0
			items[i].DataCurrent = 0
			items[i].DataMax = 0
			items[i].AvailableMax = 0
			items[i].UpBytes = 0
			items[i].DownBytes = 0
			items[i].Reasons = nil
		}
	}
	body, err := json.Marshal(Document{SchemaVersion: 1, GeneratedAt: at.UTC().Format(time.RFC3339Nano), Stale: stale, Truncated: truncated, Items: items})
	if err != nil {
		return []byte(`{"schema_version":1,"stale":true,"items":[]}`)
	}
	return body
}
