package legacy

import (
	"weroxy/server/internal/catalog"
	"weroxy/server/internal/metrics"
	"weroxy/server/internal/ports"
)

// Rows copies the legacy forwards for the quick list.
// Byte totals are read after the service lock is released.
func (s *Service) Rows() []catalog.Row {
	s.mu.Lock()
	forwards := append([]Forward(nil), s.forwards...)
	names := map[int64]string{}
	for _, device := range s.devices {
		names[device.ID] = device.Name
	}
	online := map[int64]bool{}
	for id, ctrl := range s.controls {
		online[id] = ctrl != nil && !ctrl.closed.Load()
	}
	sessions := map[int64]int{}
	for _, sess := range s.active {
		if sess != nil && !sess.finished.Load() {
			sessions[sess.forwardID]++
		}
	}
	s.mu.Unlock()
	snap := metrics.Snapshot{}
	if s.count != nil {
		snap = s.count.Snapshot()
	}
	rows := make([]catalog.Row, 0, len(forwards))
	for _, forward := range forwards {
		_, port, ok := ports.ParseHostPort(forward.Listen)
		if !ok {
			port = 0
		}
		state := "OFFLINE"
		if online[forward.DeviceID] {
			state = "ONLINE"
		}
		up, down := snap.LegacyForwardUp[forward.ID], snap.LegacyForwardDown[forward.ID]
		rows = append(rows, catalog.Row{
			ForwardID: forward.ID, Port: port, Device: names[forward.DeviceID], Target: forward.Target, ClientState: state,
			Sessions: sessions[forward.ID], Legacy: true, UpBytes: up, DownBytes: down,
		})
	}
	return rows
}
