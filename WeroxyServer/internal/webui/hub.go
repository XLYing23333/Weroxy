package webui

import (
	"strings"
	"sync"
	"time"

	"weroxy/server/internal/catalog"
	"weroxy/server/internal/metrics"
)

// Point is one observation of the live counters.
type Point struct {
	At   time.Time `json:"at"`
	Up   uint64    `json:"up_bytes"`
	Down uint64    `json:"down_bytes"`
}

// DeviceSample is the current view of one device.
type DeviceSample struct {
	ID         int64
	Name       string
	Protocol   string
	Online     bool
	Unknown    bool
	Sessions   int
	Up         uint64
	Down       uint64
	Forwards   int
	ControlRTT *int64
}

// DevicePoint is one real observation. Missing slots are not filled in.
type DevicePoint struct {
	DeviceID    int64     `json:"-"`
	At          time.Time `json:"at"`
	State       string    `json:"state"`
	Sessions    int       `json:"sessions"`
	Up          uint64    `json:"up_bytes"`
	Down        uint64    `json:"down_bytes"`
	DurationSec int       `json:"duration_sec"`
}

// Hub reads the same counters the forwarders update.
type Hub struct {
	mu                   sync.Mutex
	count                *metrics.Counters
	persist              *metrics.PersistStatus
	weroxyRows           func() []catalog.Row
	legacyRows           func() []catalog.Row
	dataPorts            func() int
	controlRTTs          func() map[int64]int64
	weroxyOnline         func() map[string]bool
	legacyOnline         func() map[string]bool
	samples              []Point
	deviceSamples        map[string][]DevicePoint
	pendingDeviceSamples map[string][]DevicePoint
}

// SetSources attaches the process counters and row callbacks.
func (h *Hub) SetSources(count *metrics.Counters, weroxyRows, legacyRows func() []catalog.Row, dataPorts func() int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.count = count
	h.weroxyRows = weroxyRows
	h.legacyRows = legacyRows
	h.dataPorts = dataPorts
}

// SetControlRTTs attaches fresh server-originated control probes.
func (h *Hub) SetControlRTTs(read func() map[int64]int64) {
	h.mu.Lock()
	h.controlRTTs = read
	h.mu.Unlock()
}

// ControlRTTs snapshots the observed RTTs without holding the Hub lock.
func (h *Hub) ControlRTTs() map[int64]int64 {
	h.mu.Lock()
	read := h.controlRTTs
	h.mu.Unlock()
	if read == nil {
		return map[int64]int64{}
	}
	return read()
}

func (h *Hub) SetPersistence(status *metrics.PersistStatus) {
	h.mu.Lock()
	h.persist = status
	h.mu.Unlock()
}

func (h *Hub) rows() []catalog.Row {
	h.mu.Lock()
	weroxyRows, legacyRows := h.weroxyRows, h.legacyRows
	h.mu.Unlock()
	var rows []catalog.Row
	if weroxyRows != nil {
		rows = append(rows, weroxyRows()...)
	}
	if legacyRows != nil {
		rows = append(rows, legacyRows()...)
	}
	return rows
}

// Dashboard copies current totals and appends one real sample.
func (h *Hub) Dashboard(forwardCount int, current []DeviceSample, interval ...time.Duration) map[string]any {
	snap := metrics.Snapshot{Failures: map[string]uint64{}}
	h.mu.Lock()
	count := h.count
	ports := h.dataPorts
	persist := h.persist
	h.mu.Unlock()
	if count != nil {
		snap = count.Snapshot()
	}
	active := 0
	for _, session := range snap.Sessions {
		if session.Active {
			active++
		}
	}
	var rejected uint64
	for _, n := range snap.Rejected {
		rejected += n
	}
	online := map[string]struct{}{}
	weroxyOnline, legacyOnline := 0, 0
	for _, device := range current {
		if device.Online {
			key := device.Protocol + ":" + device.Name
			if _, ok := online[key]; !ok {
				online[key] = struct{}{}
				if device.Protocol == "weroxy" {
					weroxyOnline++
				} else if device.Protocol == "legacy" {
					legacyOnline++
				}
			}
		}
	}
	dataPorts := 0
	if ports != nil {
		dataPorts = ports()
	}
	point := Point{At: time.Now().UTC(), Up: snap.GlobalUp, Down: snap.GlobalDown}
	h.mu.Lock()
	if len(h.samples) == 0 || point.At.Sub(h.samples[len(h.samples)-1].At) >= 5*time.Second {
		h.samples = append(h.samples, point)
		if len(h.samples) > 60 {
			h.samples = append([]Point(nil), h.samples[len(h.samples)-60:]...)
		}
	}
	series := append([]Point(nil), h.samples...)
	cadence := time.Minute
	if len(interval) > 0 && interval[0] > 0 {
		cadence = interval[0]
	}
	devices := h.noteDevices(point.At, current, cadence)
	h.mu.Unlock()
	result := map[string]any{
		"online_devices":        len(online),
		"active_sessions":       active,
		"forwards":              forwardCount,
		"data_ports":            dataPorts,
		"online_weroxy_devices": weroxyOnline,
		"online_legacy_devices": legacyOnline,
		"up_bytes":              snap.GlobalUp,
		"down_bytes":            snap.GlobalDown,
		"rejected":              rejected,
		"failures":              snap.Failures,
		"series":                series,
		"devices":               devices,
	}
	if persist != nil {
		result["metrics_persistence"] = persist.Snapshot()
	}
	if count != nil {
		queued, dropped := count.DetailBacklog()
		result["connection_persistence"] = map[string]any{"queued": queued, "dropped": dropped}
	}
	return result
}

func (h *Hub) noteDevices(now time.Time, current []DeviceSample, cadence time.Duration) []map[string]any {
	now = now.UTC()
	if h.deviceSamples == nil {
		h.deviceSamples = map[string][]DevicePoint{}
	}
	seen := map[string]struct{}{}
	out := make([]map[string]any, 0, len(current))
	for _, device := range current {
		key := device.Protocol + ":" + device.Name
		seen[key] = struct{}{}
		state := "offline"
		if device.Online && device.Sessions > 0 {
			state = "online"
		} else if device.Online {
			state = "idle"
		}
		if device.Unknown {
			state = "unknown"
		}
		points := h.deviceSamples[key]
		due := cadence
		if len(points) > 0 && points[len(points)-1].DurationSec > 0 {
			previous := time.Duration(points[len(points)-1].DurationSec) * time.Second
			if previous < due {
				due = previous
			}
		}
		// Allow sub-second scheduler jitter; retain actual timestamps and durations.
		// A slightly early tick must not skip an entire minute (or background interval).
		if !device.Unknown && (len(points) == 0 || now.Sub(points[len(points)-1].At) >= due-time.Second || points[len(points)-1].State != state) {
			points = append(points, DevicePoint{
				DeviceID: device.ID, At: now, State: state, Sessions: device.Sessions, Up: device.Up, Down: device.Down, DurationSec: int(cadence.Seconds()),
			})
			if len(points) > 180 {
				points = append([]DevicePoint(nil), points[len(points)-180:]...)
			}
			h.deviceSamples[key] = points
			if h.pendingDeviceSamples == nil {
				h.pendingDeviceSamples = map[string][]DevicePoint{}
			}
			h.pendingDeviceSamples[key] = append(h.pendingDeviceSamples[key], points[len(points)-1])
			if len(h.pendingDeviceSamples[key]) > 180 {
				h.pendingDeviceSamples[key] = h.pendingDeviceSamples[key][len(h.pendingDeviceSamples[key])-180:]
			}
		}
		history := append([]DevicePoint{}, h.deviceSamples[key]...)
		out = append(out, map[string]any{
			"name": device.Name, "protocol": device.Protocol, "online": device.Online, "online_known": !device.Unknown,
			"sessions": device.Sessions, "up_bytes": device.Up, "down_bytes": device.Down,
			"forwards": device.Forwards, "state": state, "history": history, "control_rtt_ms": device.ControlRTT,
		})
	}
	for key := range h.deviceSamples {
		if _, ok := seen[key]; !ok {
			delete(h.deviceSamples, key)
			delete(h.pendingDeviceSamples, key)
		}
	}
	return out
}

type live struct {
	Online   bool
	Sessions int
	Up       uint64
	Down     uint64
}

func (h *Hub) SetOnlineSources(weroxyOnline, legacyOnline func() map[string]bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.weroxyOnline = weroxyOnline
	h.legacyOnline = legacyOnline
}

func (h *Hub) liveByDevice() map[string]live {
	out := map[string]live{}
	for _, row := range h.rows() {
		key := row.Device
		if row.Legacy {
			key = "legacy:" + row.Device
		} else {
			key = "weroxy:" + row.Device
		}
		item := out[key]
		item.Sessions += row.Sessions
		item.Up += row.UpBytes
		item.Down += row.DownBytes
		if row.ClientState == "ONLINE" {
			item.Online = true
		}
		out[key] = item
	}
	h.mu.Lock()
	sources := map[string]func() map[string]bool{"weroxy": h.weroxyOnline, "legacy": h.legacyOnline}
	h.mu.Unlock()
	for protocol, read := range sources {
		if read == nil {
			continue
		}
		for name, online := range read() {
			key := protocol + ":" + name
			item := out[key]
			item.Online = online
			out[key] = item
		}
	}

	return out
}

func (h *Hub) RestoreDeviceStatus(items map[string][]DevicePoint) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deviceSamples = items
}

func (h *Hub) TakeDeviceStatus() map[string][]DevicePoint {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.pendingDeviceSamples
	h.pendingDeviceSamples = nil
	return out
}

func (h *Hub) RequeueDeviceStatus(items map[string][]DevicePoint) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pendingDeviceSamples == nil {
		h.pendingDeviceSamples = map[string][]DevicePoint{}
	}
	for key, points := range items {
		// A failed SQLite batch must not resurrect a deleted device's queue.
		if _, exists := h.deviceSamples[key]; !exists {
			continue
		}
		h.pendingDeviceSamples[key] = append(points, h.pendingDeviceSamples[key]...)
		if len(h.pendingDeviceSamples[key]) > 180 {
			h.pendingDeviceSamples[key] = h.pendingDeviceSamples[key][len(h.pendingDeviceSamples[key])-180:]
		}
	}
}

func SplitDeviceStatusKey(key string) (string, string) {
	protocol, device, _ := strings.Cut(key, ":")
	return protocol, device
}
