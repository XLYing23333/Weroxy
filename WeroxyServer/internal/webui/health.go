package webui

import (
	"context"
	"io"
	"net"
	"net/http"
)

// Public liveness returns no configuration or operational details.
func healthHandler(ctx context.Context, ready func() bool, readiness bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if readiness {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			ip := net.ParseIP(host)
			if err != nil || ip == nil || !ip.IsLoopback() {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		if ctx.Err() != nil || readiness && ready != nil && !ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			if r.Method != http.MethodHead {
				_, _ = io.WriteString(w, "not ready\n")
			}
			return
		}
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, "ok\n")
		}
	}
}
