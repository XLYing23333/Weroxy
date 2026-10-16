package legacy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"weroxy/server/internal/listenaddr"
)

// ReconcileForwards prepares every new listener before replacing the active
// forwarding table. A failed bind leaves all old listeners and rules active.
func (s *Service) ReconcileForwards(ctx context.Context, desired []Forward) error {
	commit, abort, err := s.PrepareForwards(ctx, desired)
	if err != nil {
		return err
	}
	defer abort()
	commit()
	return nil
}

// PrepareForwards holds only the reconciliation mutex while preparing.
// The caller must invoke commit or abort; both are mutually idempotent.
func (s *Service) PrepareForwards(ctx context.Context, desired []Forward) (func(), func(), error) {
	s.reconcileMu.Lock()
	prepared := false
	defer func() {
		if !prepared {
			s.reconcileMu.Unlock()
		}
	}()

	s.mu.Lock()
	running := s.ctx
	current := make(map[int64]net.Listener, len(s.listeners))
	for id, ln := range s.listeners {
		current[id] = ln
	}
	s.mu.Unlock()
	if running == nil {
		return nil, nil, errors.New("legacy service is not running")
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-running.Done():
		return nil, nil, errors.New("legacy service stopped")
	default:
	}

	seenIDs := make(map[int64]bool, len(desired))
	seenAddrs := make(map[string]bool, len(desired))
	opened := make(map[int64]net.Listener)
	closeOpened := func() {
		for _, ln := range opened {
			_ = ln.Close()
		}
	}
	next := make([]Forward, len(desired))
	for i, forward := range desired {
		if forward.ID < 1 || forward.DeviceID < 1 || seenIDs[forward.ID] || seenAddrs[forward.Listen] {
			closeOpened()
			return nil, nil, errors.New("invalid legacy forward snapshot")
		}
		seenIDs[forward.ID], seenAddrs[forward.Listen] = true, true
		ln := current[forward.ID]
		if ln == nil || !listenaddr.Matches(ln.Addr(), forward.Listen) {
			var err error
			ln, err = net.Listen("tcp", forward.Listen)
			if err != nil {
				closeOpened()
				return nil, nil, fmt.Errorf("prepare legacy listener: %w", err)
			}
			opened[forward.ID] = ln
		}
		forward.Listen = ln.Addr().String()
		next[i] = forward
	}
	select {
	case <-ctx.Done():
		closeOpened()
		return nil, nil, ctx.Err()
	case <-running.Done():
		closeOpened()
		return nil, nil, errors.New("legacy service stopped")
	default:
	}

	prepared = true
	var once sync.Once
	abort := func() { once.Do(func() { closeOpened(); s.reconcileMu.Unlock() }) }
	commit := func() {
		once.Do(func() {
			defer s.reconcileMu.Unlock()

			s.mu.Lock()
			old := s.listeners
			oldStops := s.listenerStops
			active := make(map[int64]net.Listener, len(next))
			stops := make(map[int64]func() bool, len(next))
			for _, forward := range next {
				if ln := opened[forward.ID]; ln != nil {
					active[forward.ID] = ln
					stops[forward.ID] = context.AfterFunc(running, func() { _ = ln.Close() })
				} else {
					active[forward.ID] = old[forward.ID]
					if stop := oldStops[forward.ID]; stop != nil {
						stops[forward.ID] = stop
					}
				}
			}
			s.forwards = next
			s.listeners = active
			s.listenerStops = stops
			s.mu.Unlock()
			for id, ln := range old {
				if active[id] != ln {
					if stop := oldStops[id]; stop != nil {
						stop()
					}
					_ = ln.Close()
				}
			}
			for id, ln := range opened {
				go s.acceptForward(ln, id)
			}

		})
	}
	return commit, abort, nil
}
