package legacy

import (
	"net"
	"strconv"
	"time"
)

// Drain rejects new work but retains existing Legacy control/data pairs until
// their business sessions end. Legacy controls must not be retired early.
func (s *Service) Drain(limit time.Duration) {
	if limit <= 0 || limit > 5*time.Minute {
		limit = 20 * time.Second
	}
	if !s.draining.CompareAndSwap(false, true) {
		return
	}
	s.mu.Lock()
	listeners := make([]net.Listener, 0, len(s.listeners))
	for _, ln := range s.listeners {
		listeners = append(listeners, ln)
	}
	pending := make([]*session, 0, len(s.pending))
	for _, sess := range s.pending {
		pending = append(pending, sess)
	}
	idle := make([]net.Conn, 0, len(s.idleConns))
	for conn := range s.idleConns {
		idle = append(idle, conn)
	}
	s.mu.Unlock()
	for _, ln := range listeners {
		_ = ln.Close()
	}
	for _, sess := range pending {
		s.finish(sess, "shutdown_pending")
	}
	for _, conn := range idle {
		_ = conn.Close()
	}
	timer := time.NewTimer(limit)
	defer timer.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
wait:
	for {
		s.mu.Lock()
		remaining := len(s.active)
		s.mu.Unlock()
		if remaining == 0 {
			break
		}
		select {
		case <-tick.C:
		case <-timer.C:
			s.mu.Lock()
			left := make([]*session, 0, len(s.active))
			for _, sess := range s.active {
				left = append(left, sess)
			}
			s.mu.Unlock()
			s.info("legacy shutdown drain timed out", map[string]string{"sessions": strconv.Itoa(len(left))})
			for _, sess := range left {
				s.finish(sess, "shutdown_drain_timeout")
			}
			break wait
		}
	}
	s.mu.Lock()
	controls := make([]*control, 0, len(s.controls))
	for _, ctrl := range s.controls {
		controls = append(controls, ctrl)
	}
	s.mu.Unlock()
	for _, ctrl := range controls {
		s.retire(ctrl)
	}
}
