package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Streams have a server-wide budget, bounded lifetime and per-frame deadlines.
// Each frame is a fresh snapshot, with no queue or persistent DB read transaction.
func (a *api) dashboardEvents(w http.ResponseWriter, r *http.Request) {
	select {
	case a.streamSlots <- struct{}{}:
		defer func() { <-a.streamSlots }()
	default:
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusServiceUnavailable, "stream_capacity")
		return
	}
	if _, ok := w.(http.Flusher); !ok {
		writeError(w, http.StatusServiceUnavailable, "stream_unavailable")
		return
	}
	controller := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	lifetime, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()
	for {
		select {
		case <-lifetime.Done():
			return
		case <-a.stopStreams:
			return
		default:
		}
		queryCtx, queryCancel := context.WithTimeout(lifetime, 2*time.Second)
		request := r.WithContext(queryCtx)
		_, _, authorized := a.session(request)
		if !authorized {
			queryCancel()
			return
		}
		board, err := a.dashboardSnapshot(request)
		queryCancel()
		if err != nil {
			return
		}
		encoded, err := json.Marshal(board)
		if err != nil || len(encoded) > 512*1024 {
			return
		}
		if controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
			return
		}
		if _, err := fmt.Fprintf(w, "retry: 10000\nevent: dashboard\ndata: %s\n\n", encoded); err != nil {
			return
		}
		if controller.Flush() != nil {
			return
		}
		if controller.SetWriteDeadline(time.Time{}) != nil {
			return
		}
		interval, ok := board["refresh_sec"].(int)
		if !ok || interval < 1 || interval > 60 {
			interval = 5
		}
		// Recheck revoked sessions within 5 seconds even for long refresh periods.
		timer := time.NewTimer(time.Duration(interval) * time.Second)
		authTick := time.NewTicker(5 * time.Second)
		waiting := true
		for waiting {
			select {
			case <-lifetime.Done():
				timer.Stop()
				authTick.Stop()
				return
			case <-a.stopStreams:
				timer.Stop()
				authTick.Stop()
				return
			case <-timer.C:
				waiting = false
			case <-authTick.C:
				ctx, cancel := context.WithTimeout(lifetime, time.Second)
				_, _, ok := a.session(r.WithContext(ctx))
				cancel()
				if !ok {
					timer.Stop()
					authTick.Stop()
					return
				}
			}
		}
		authTick.Stop()
	}
}
