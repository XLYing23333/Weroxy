package weroxy

import (
	"bytes"
	"context"
	"errors"
)

// ReconcileDevices replaces the validated auth registry. Revoked, removed or
// rotated credentials retire that device's control and all its sessions;
// unrelated devices stay connected. Pause stops new sessions without cutting
// existing ready sessions.
func (s *Service) ReconcileDevices(ctx context.Context, desired []Device) error {
	seenIDs := make(map[int64]bool, len(desired))
	seenUIDs := make(map[string]bool, len(desired))
	next := make([]Device, len(desired))
	for i, device := range desired {
		if device.ID < 1 || device.UID == "" || len(device.TokenMAC) != 32 || device.Credential.PSK == [32]byte{} || seenIDs[device.ID] || seenUIDs[device.UID] {
			return errors.New("invalid weroxy device snapshot")
		}
		seenIDs[device.ID], seenUIDs[device.UID] = true, true
		next[i] = device
		next[i].TokenMAC = append([]byte(nil), device.TokenMAC...)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.mu.Lock()
	previousByID := make(map[int64]Device, len(s.devices))
	for _, device := range s.devices {
		previousByID[device.ID] = device
	}
	for i := range next {
		if old, ok := previousByID[next[i].ID]; ok && old.UID == next[i].UID && old.Revoked {
			next[i].Revoked = true
		}
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
		if !ok || current.Revoked || previous.UID != current.UID || !bytes.Equal(previous.TokenMAC, current.TokenMAC) || previous.Credential != current.Credential {
			drop[previous.ID] = true
		}
	}
	var controls []*control
	for id, ctrl := range s.controls {
		if drop[id] {
			controls = append(controls, ctrl)
		}
	}
	var sessions []*session
	for _, sess := range s.sessions {
		if drop[sess.deviceID] {
			sessions = append(sessions, sess)
		}
	}
	for key := range s.portHealth {
		if !seenIDs[key.deviceID] || drop[key.deviceID] {
			delete(s.portHealth, key)
		}
	}
	s.devices = next
	s.mu.Unlock()
	if s.count != nil {
		for id, name := range renamed {
			s.count.RenameDevice("weroxy", id, name)
		}
	}
	for _, ctrl := range controls {
		s.retire(ctrl)
	}
	for _, sess := range sessions {
		s.finishWithReason(sess, "credential_changed")
	}
	return nil
}
