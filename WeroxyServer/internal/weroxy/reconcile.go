package weroxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"weroxy/server/internal/listenaddr"
	"weroxy/server/internal/ports"
)

// RuntimeSnapshot is a copy of the active listener policy for rollback.
type RuntimeSnapshot struct {
	Forwards    []Forward
	Assignments []ports.Assignment
	Pool        *ports.Pool
	PoolHost    string
}

func (s *Service) SnapshotForwards() RuntimeSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := RuntimeSnapshot{Forwards: append([]Forward(nil), s.forwards...), PoolHost: s.poolHost}
	if s.pool != nil {
		copyPool := *s.pool
		out.Pool = &copyPool
	}
	for _, dp := range s.dataPorts {
		for id, state := range dp.state {
			var deviceID int64
			for _, forward := range s.forwards {
				if forward.ID == id {
					deviceID = forward.DeviceID
					break
				}
			}
			if deviceID != 0 {
				out.Assignments = append(out.Assignments, ports.Assignment{ForwardID: id, DeviceID: deviceID, Port: dp.port, State: state})
			}
		}
	}
	return out
}

// ReconcileForwards prepares all required listeners before changing the active
// forwarding table. Existing sessions keep their selected target and data port.
// Assignments are the persisted pool decision, including draining bindings.
func (s *Service) ReconcileForwards(ctx context.Context, desired []Forward, assignments []ports.Assignment, pool *ports.Pool, poolHost string) error {
	commit, abort, err := s.PrepareForwards(ctx, desired, assignments, pool, poolHost)
	if err != nil {
		return err
	}
	defer abort()
	commit()
	return nil
}

// PrepareForwards holds only the reconciliation mutex while preparing.
// The caller must invoke commit or abort; both are mutually idempotent.
func (s *Service) PrepareForwards(ctx context.Context, desired []Forward, assignments []ports.Assignment, pool *ports.Pool, poolHost string) (func(), func(), error) {
	s.reconcileMu.Lock()
	prepared := false
	defer func() {
		if !prepared {
			s.reconcileMu.Unlock()
		}
	}()

	s.mu.Lock()
	running := s.ctx
	oldForward := make(map[int64]net.Listener, len(s.forwardLns))
	for id, ln := range s.forwardLns {
		oldForward[id] = ln
	}
	oldData := make(map[int]*dataPort, len(s.dataPorts))
	oldDataStops := make(map[int]func() bool, len(s.dataStops))
	for port, stop := range s.dataStops {
		oldDataStops[port] = stop
	}
	for _, dp := range s.dataPorts {
		oldData[dp.port] = dp
	}
	s.mu.Unlock()
	if running == nil {
		return nil, nil, errors.New("weroxy service is not running")
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-running.Done():
		return nil, nil, errors.New("weroxy service stopped")
	default:
	}
	if (pool == nil) != (s.pool == nil) {
		return nil, nil, errors.New("changing the data listener mode requires restart")
	}
	if poolHost == "" {
		poolHost = "127.0.0.1"
	}

	forwardByID := make(map[int64]Forward, len(desired))
	addresses := make(map[string]bool, len(desired))
	for _, f := range desired {
		if f.ID < 1 || f.DeviceID < 1 || f.Listen == "" || forwardByID[f.ID].ID != 0 || addresses[f.Listen] {
			return nil, nil, errors.New("invalid weroxy forward snapshot")
		}
		forwardByID[f.ID] = f
		addresses[f.Listen] = true
	}
	stateByPort := map[int]map[int64]string{}
	serving := map[int64]int{}
	if pool != nil {
		for _, item := range assignments {
			f, ok := forwardByID[item.ForwardID]
			if !ok || f.DeviceID != item.DeviceID || item.Port < pool.First || item.Port > pool.Last || (item.State != ports.Serving && item.State != ports.Draining) {
				return nil, nil, errors.New("invalid weroxy data assignment snapshot")
			}
			if stateByPort[item.Port] == nil {
				stateByPort[item.Port] = map[int64]string{}
			}
			if stateByPort[item.Port][item.ForwardID] != "" {
				return nil, nil, errors.New("duplicate weroxy data assignment")
			}
			stateByPort[item.Port][item.ForwardID] = item.State
			if item.State == ports.Serving {
				serving[item.ForwardID]++
			}
		}
	}
	openedForward := map[int64]net.Listener{}
	openedData := map[int]*dataPort{}
	closeOpened := func() {
		for _, ln := range openedForward {
			_ = ln.Close()
		}
		for _, dp := range openedData {
			_ = dp.ln.Close()
		}
	}
	dataNext := map[int]*dataPort{}
	if pool != nil {
		for port, states := range stateByPort {
			active := false
			for _, state := range states {
				active = active || state == ports.Serving
			}
			old := oldData[port]
			addr := net.JoinHostPort(poolHost, strconv.Itoa(port))
			if old != nil && old.ln != nil && listenaddr.Matches(old.ln.Addr(), addr) {
				dataNext[port] = old
				continue
			}
			if old != nil && old.sessions > 0 {
				closeOpened()
				return nil, nil, fmt.Errorf("data port %d still has active sessions", port)
			}
			if !active {
				continue
			}
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				closeOpened()
				if errors.Is(err, syscall.EADDRINUSE) {
					return nil, nil, &DataPortOccupied{Port: port, Cause: err}
				}
				return nil, nil, fmt.Errorf("prepare data port %d: %w", port, err)
			}
			dp := &dataPort{port: port, addr: ln.Addr().String(), ln: ln, state: map[int64]string{}}
			openedData[port], dataNext[port] = dp, dp
		}
	}
	forwardNext := map[int64]net.Listener{}
	next := normalizeForwards(desired)
	for i := range next {
		f := &next[i]
		if !f.Enabled || (pool != nil && serving[f.ID] < f.Min) {
			continue
		}
		ln := oldForward[f.ID]
		if ln == nil || !listenaddr.Matches(ln.Addr(), f.Listen) {
			var err error
			ln, err = net.Listen("tcp", f.Listen)
			if err != nil {
				closeOpened()
				return nil, nil, fmt.Errorf("prepare forward %d: %w", f.ID, err)
			}
			openedForward[f.ID] = ln
		}
		f.Listen = ln.Addr().String()
		forwardNext[f.ID] = ln
	}
	select {
	case <-ctx.Done():
		closeOpened()
		return nil, nil, ctx.Err()
	case <-running.Done():
		closeOpened()
		return nil, nil, errors.New("weroxy service stopped")
	default:
	}

	prepared = true
	var once sync.Once
	abort := func() { once.Do(func() { closeOpened(); s.reconcileMu.Unlock() }) }
	commit := func() {
		once.Do(func() {
			defer s.reconcileMu.Unlock()

			s.mu.Lock()
			oldStops := s.forwardStops
			newStops := map[int64]func() bool{}
			for id, ln := range forwardNext {
				if openedForward[id] != nil {
					listener := ln
					newStops[id] = context.AfterFunc(running, func() { _ = listener.Close() })
				} else if oldStops[id] != nil {
					newStops[id] = oldStops[id]
				}
			}
			for port, dp := range oldData {
				if dataNext[port] != dp && dp.sessions > 0 {
					// The old listener still owns live sessions, but issues no new ones.
					dataNext[port] = dp
				}
			}
			newDataStops := map[int]func() bool{}
			dataList := make([]*dataPort, 0, len(dataNext))
			for port, dp := range dataNext {
				dp.state = stateByPort[port]
				if dp.state == nil {
					dp.state = map[int64]string{}
				}
				dataList = append(dataList, dp)
				if openedData[port] != nil {
					listener := dp.ln
					newDataStops[port] = context.AfterFunc(running, func() { _ = listener.Close() })
				} else if dataNext[port] == oldData[port] && oldDataStops[port] != nil {
					newDataStops[port] = oldDataStops[port]
				}
			}
			sort.Slice(dataList, func(i, j int) bool { return dataList[i].port < dataList[j].port })
			s.forwards = next
			s.forwardLns = forwardNext
			s.forwardStops = newStops
			s.dataPorts = dataList
			for key := range s.portHealth {
				if dataNext[key.port] == nil {
					delete(s.portHealth, key)
				}
			}
			s.dataStops = newDataStops
			if pool != nil {
				s.dataAddr = ""
				for _, dp := range dataList {
					if dp.ln != nil {
						s.dataAddr = dp.addr
						break
					}
				}
			}
			s.pool = pool
			s.poolHost = poolHost
			s.reasons = map[int64]string{}
			s.views = map[int64]ports.View{}
			for _, f := range next {
				if pool == nil || !f.Enabled {
					continue
				}
				view := ports.View{ForwardID: f.ID, ConfiguredMax: f.Max, Current: serving[f.ID]}
				for _, states := range stateByPort {
					if states[f.ID] == ports.Draining {
						view.Draining++
					}
				}
				view.AvailableMaxTotal = f.Max
				if serving[f.ID] < f.Min {
					s.reasons[f.ID] = ports.ReasonBelowMin
					view.Reasons = []string{ports.ReasonBelowMin}
				}
				s.views[f.ID] = view
			}
			s.closeIdleLocked()
			s.mu.Unlock()
			for id, ln := range oldForward {
				if forwardNext[id] != ln {
					if stop := oldStops[id]; stop != nil {
						stop()
					}
					_ = ln.Close()
				}
			}
			for port, dp := range oldData {
				if dataNext[port] != dp && dp.ln != nil {
					if stop := oldDataStops[port]; stop != nil {
						stop()
					}
					_ = dp.ln.Close()
				}
			}
			for id, ln := range openedForward {
				go s.acceptForward(ln, id)
			}
			for _, dp := range openedData {
				go s.acceptData(dp.ln)
			}

		})
	}
	return commit, abort, nil
}

// DataPortOccupied distinguishes an automatic candidate collision from fixed
// Forward bind errors and permission or address failures.
type DataPortOccupied struct {
	Port  int
	Cause error
}

func (e *DataPortOccupied) Error() string {
	return fmt.Sprintf("automatic data port %d occupied", e.Port)
}
func (e *DataPortOccupied) Unwrap() error { return e.Cause }

// PrepareAvailableForwards retries bounded automatic candidates. Draining
// bindings remain unchanged and are excluded from new allocations.
func (s *Service) PrepareAvailableForwards(ctx context.Context, desired []Forward, assignments []ports.Assignment, pool *ports.Pool, host string) (func(), func(), error) {
	if pool == nil {
		return s.PrepareForwards(ctx, desired, assignments, pool, host)
	}
	candidates := *pool
	candidates.Unavailable = make(map[int]bool)
	for port, value := range pool.Unavailable {
		candidates.Unavailable[port] = value
	}
	var drain []ports.Assignment
	for _, item := range assignments {
		if item.State == ports.Draining {
			drain = append(drain, item)
			candidates.Unavailable[item.Port] = true
		}
	}
	s.mu.Lock()
	unreachable := map[int64]map[int]bool{}
	for port, until := range s.globalQuarantine {
		if until.After(time.Now()) {
			candidates.Unavailable[port] = true
		} else {
			delete(s.globalQuarantine, port)
		}
	}
	for _, dp := range s.dataPorts {
		if dp.failed || dp.probeBad {
			candidates.Unavailable[dp.port] = true
		}
	}
	for key, health := range s.portHealth {
		if health.until.After(time.Now()) {
			if unreachable[key.deviceID] == nil {
				unreachable[key.deviceID] = map[int]bool{}
			}
			unreachable[key.deviceID][key.port] = true
		}
	}
	s.mu.Unlock()
	specs := make([]ports.Spec, 0, len(desired))
	for _, f := range desired {
		specs = append(specs, ports.Spec{ID: f.ID, DeviceID: f.DeviceID, Mode: f.Mode, Min: f.Min, Preferred: f.Preferred, Max: f.Max, DeviceMax: f.DeviceMax, Enabled: f.Enabled, UseReserved: f.UseReserved, ManualPorts: f.ManualPorts, Unavailable: unreachable[f.DeviceID]})
	}
	for _, item := range assignments {
		if item.State == ports.Serving && (unreachable[item.DeviceID][item.Port] || candidates.Unavailable[item.Port]) {
			out := ports.Allocate(candidates, specs)
			if len(out.Rejected) != 0 {
				return nil, nil, errors.New("healthy data candidates below minimum")
			}
			assignments = append(out.Assignments, drain...)
			break
		}
	}
	for {
		commit, abort, err := s.PrepareForwards(ctx, desired, assignments, pool, host)
		if err == nil {
			return commit, abort, nil
		}
		var occupied *DataPortOccupied
		if !errors.As(err, &occupied) || candidates.Unavailable[occupied.Port] {
			return nil, nil, err
		}
		candidates.Unavailable[occupied.Port] = true
		out := ports.Allocate(candidates, specs)
		if len(out.Rejected) != 0 {
			return nil, nil, err
		}
		assignments = append(out.Assignments, drain...)
	}
}
