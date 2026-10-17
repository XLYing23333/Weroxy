package webui

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"weroxy/server/internal/buildinfo"
	"weroxy/server/internal/release"
)

type updateResult struct {
	Current   string `json:"current_version"`
	Latest    string `json:"latest_version,omitempty"`
	Available bool   `json:"available"`
	URL       string `json:"release_url,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
	Status    string `json:"status"`
}
type updateCache struct {
	mu      sync.Mutex
	result  updateResult
	attempt time.Time
	pending chan struct{}
	check   func(context.Context, string) (release.Release, error)
}

func (c *updateCache) get(ctx context.Context, force bool) updateResult {
	c.mu.Lock()
	if c.pending == nil && (c.attempt.IsZero() || time.Since(c.attempt) >= 6*time.Hour || force && time.Since(c.attempt) >= time.Minute) {
		c.pending = make(chan struct{})
		c.attempt = time.Now()
		done := c.pending
		go func() {
			deadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			check := c.check
			if check == nil {
				check = release.Check
			}
			r, e := check(deadline, "")
			c.mu.Lock()
			defer c.mu.Unlock()
			c.result.Current = buildinfo.Version
			c.result.Status = "error"
			if e == nil {
				c.result.Latest = strings.TrimPrefix(r.Tag, "v")
				c.result.Available = release.Newer(r.Tag, buildinfo.Version)
				c.result.URL = r.URL
				c.result.Status = "ok"
				c.result.CheckedAt = time.Now().UTC().Format(time.RFC3339)
			}
			c.pending = nil
			close(done)
		}()
	}
	pending := c.pending
	c.mu.Unlock()
	if pending != nil {
		select {
		case <-pending:
		case <-ctx.Done():
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.result
	out.Current = buildinfo.Version
	if out.Status == "" {
		out.Status = "checking"
	}
	return out
}
func (a *api) update(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.updates.get(r.Context(), r.Method == http.MethodPost))
}
