// Package quicklist renders the public port list from current forward state.
package quicklist

import (
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"weroxy/server/internal/catalog"
)

const maxOutput = 32 * 1024

type Options struct {
	Enabled func() bool
	Rows    func() []catalog.Row
	Now     func() time.Time
}

type item struct {
	Device   string `json:"device"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Status   string `json:"status"`
}

type handler struct {
	opt  Options
	mu   sync.Mutex
	hits map[string]hit
}
type hit struct {
	at    time.Time
	count int
}

func NewHandler(opt Options) http.Handler {
	if opt.Enabled == nil {
		opt.Enabled = func() bool { return false }
	}
	if opt.Rows == nil {
		opt.Rows = func() []catalog.Row { return nil }
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &handler{opt: opt, hits: map[string]hit{}}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.opt.Enabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet || r.ContentLength > 0 {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	now := h.opt.Now()
	h.mu.Lock()
	if len(h.hits) > 256 {
		h.hits = map[string]hit{}
	}
	state := h.hits[host]
	if now.Sub(state.at) >= time.Second {
		state = hit{at: now}
	}
	state.count++
	h.hits[host] = state
	h.mu.Unlock()
	if state.count > 8 {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	rows := h.opt.Rows()
	out := make([]item, 0, len(rows))
	for _, row := range rows {
		if row.Port < 1 || row.Port > 65535 {
			continue
		}
		protocol := "weroxy"
		if row.Legacy {
			protocol = "legacy"
		}
		status := "offline"
		if row.ClientState == "ONLINE" {
			status = "online"
		}
		out = append(out, item{Device: catalog.Clean(row.Device), Protocol: protocol, Port: row.Port, Status: status})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Device < out[j].Device
	})
	if r.URL.Path == "/api/v1/list" || strings.Contains(r.Header.Get("Accept"), "application/json") || r.URL.Query().Get("format") == "json" {
		body, _ := json.Marshal(map[string]any{"generated_at": now.UTC().Format(time.RFC3339), "items": out})
		if len(body) > maxOutput {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(body)
		return
	}
	var b strings.Builder
	columns := [][]string{{"PORT", "DEVICE", "PROTOCOL", "STATUS"}}
	inputSize := 0
	for _, row := range out {
		values := []string{strconv.Itoa(row.Port), row.Device, row.Protocol, row.Status}
		size := 0
		for _, v := range values {
			size += len(v) + 1
		}
		if inputSize+size > maxOutput/2 {
			break
		}
		inputSize += size
		columns = append(columns, values)
	}
	widths := [3]int{8, 8, 8}
	for _, values := range columns {
		for i := 0; i < 3; i++ {
			size := ((terminalWidth(values[i]) + 2 + 7) / 8) * 8
			if size > widths[i] {
				widths[i] = size
			}
		}
	}
	for _, values := range columns {
		for i, v := range values {
			b.WriteString(v)
			if i < 3 {
				b.WriteString(strings.Repeat("\t", (widths[i]-terminalWidth(v)+7)/8))
			}
		}
		b.WriteByte('\n')
	}
	if b.Len() > maxOutput {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
