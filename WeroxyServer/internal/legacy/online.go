package legacy

// OnlineDevices includes authenticated controls even without configured forwards.
func (s *Service) OnlineDevices() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]bool, len(s.devices))
	for _, device := range s.devices {
		ctrl := s.controls[device.ID]
		out[device.Name] = ctrl != nil && !ctrl.closed.Load()
	}
	return out
}
