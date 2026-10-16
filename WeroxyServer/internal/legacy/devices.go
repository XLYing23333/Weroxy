package legacy

import (
	"bytes"
	"context"
	"errors"
	"net"
)

// ReconcileDevices updates authenticated device credentials and pause state.
// A deleted or rotated key retires only that device's control, sessions and
// idle pool. Existing sessions on a merely paused device can finish.
func (s *Service) ReconcileDevices(ctx context.Context, desired []Device) error {
	seen := make(map[int64]bool, len(desired))
	next := make([]Device, len(desired))
	for i, device := range desired {
		if device.ID < 1 || len(device.KeyMAC) != 32 || seen[device.ID] {
			return errors.New("invalid legacy device snapshot")
		}
		seen[device.ID] = true
		next[i] = device
		next[i].KeyMAC = append([]byte(nil), device.KeyMAC...)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.mu.Lock()
	if s.ctx == nil {
		s.mu.Unlock()
		return errors.New("legacy service is not running")
	}
	replacement := make(map[int64]Device, len(next))
	for _, device := range next {
		replacement[device.ID] = device
	}
	renamed := make(map[int64]string)
	drop := make(map[int64]bool)
	for _, previous := range s.devices {
		current, ok := replacement[previous.ID]
		if ok && previous.Name != current.Name {
			renamed[current.ID] = current.Name
		}
		if !ok || !bytes.Equal(previous.KeyMAC, current.KeyMAC) {
			drop[previous.ID] = true
		}
	}
	var controls []*control
	for id, ctrl := range s.controls {
		if drop[id] {
			controls = append(controls, ctrl)
		}
	}
	s.devices = next
	s.mu.Unlock()
	if s.count != nil {
		for id, name := range renamed {
			s.count.RenameDevice("legacy", id, name)
		}
	}
	for _, ctrl := range controls {
		s.retire(ctrl)
	}
	var idle []net.Conn
	s.mu.Lock()
	for conn, id := range s.idleConns {
		if drop[id] {
			idle = append(idle, conn)
		}
	}
	s.mu.Unlock()
	for _, conn := range idle {
		_ = conn.Close()
	}
	return nil
}
