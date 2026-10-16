package weroxy

import (
	"context"
	"net"
	"time"
)

// StartHealth probes at most four local pooled listeners per five-second tick.
// No global service lock is held during network work.
func (s *Service) StartHealth(ctx context.Context) {
	s.healthOnce.Do(func() { go s.pollHealth(ctx) })
}
func (s *Service) pollHealth(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	offset := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		s.mu.Lock()
		var sample []*dataPort
		count := len(s.dataPorts)
		if count > 0 {
			for i := 0; i < count && len(sample) < 4; i++ {
				dp := s.dataPorts[(offset+i)%count]
				if dp.ln != nil && !dp.failed {
					sample = append(sample, dp)
				}
			}
			offset = (offset + 4) % count
		}
		s.mu.Unlock()
		for _, dp := range sample {
			ok := s.probeTCP(ctx, dp.addr)
			if ctx.Err() != nil {
				return
			}
			s.mu.Lock()
			live := false
			for _, current := range s.dataPorts {
				if current == dp {
					live = true
					break
				}
			}
			if live {
				if ok {
					dp.probeFailures = 0
					dp.probeBad = false
					delete(s.globalQuarantine, dp.port)
				} else {
					dp.probeFailures++
					if dp.probeFailures >= 3 {
						if !dp.probeBad {
							if s.globalQuarantine == nil {
								s.globalQuarantine = map[int]time.Time{}
							}
							s.globalQuarantine[dp.port] = time.Now().Add(time.Minute)
						}
						dp.probeBad = true
					}
				}
			}
			s.mu.Unlock()
		}
	}
}
func (s *Service) probeTCP(parent context.Context, address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
