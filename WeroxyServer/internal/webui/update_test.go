package webui

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weroxy/server/internal/release"
)

func TestUpdateChecksCoalesceAndRetainLastSuccessOnFailure(t *testing.T) {
	var calls atomic.Int32
	cache := &updateCache{check: func(context.Context, string) (release.Release, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return release.Release{Tag: "v99.0.0", URL: "https://github.com/XLYing23333/Weroxy/releases/tag/v99.0.0"}, nil
	}}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			r := cache.get(t.Context(), true)
			if r.Status != "ok" || r.Latest != "99.0.0" {
				t.Error("missing successful check")
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("checks not coalesced")
	}
	cache.mu.Lock()
	cache.attempt = time.Now().Add(-7 * time.Hour)
	cache.check = func(context.Context, string) (release.Release, error) {
		return release.Release{}, errors.New("offline")
	}
	cache.mu.Unlock()
	r := cache.get(t.Context(), false)
	if r.Status != "error" || r.Latest != "99.0.0" || r.CheckedAt == "" {
		t.Fatal("failure lost previous result or reported success")
	}
}
