package weroxy

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"syscall"
	"time"

	"weroxy/server/internal/catalog"
	"weroxy/server/internal/metrics"
	"weroxy/server/internal/ports"
)

// StartAllocated listens on the control address, the assigned data ports, and
// the forwards that received an allocation. Unassigned pool ports stay closed.
func (s *Service) StartAllocated(ctx context.Context, controlAddr string) (string, []string, []string, error) {
	if s.pool == nil {
		return "", nil, nil, errNoPool
	}
	specs := make([]ports.Spec, 0, len(s.forwards))
	activeDevices := make(map[int64]bool, len(s.devices))
	for _, device := range s.devices {
		activeDevices[device.ID] = true
	}
	for _, forward := range s.forwards {
		if !forward.Enabled || !activeDevices[forward.DeviceID] {
			continue
		}
		specs = append(specs, ports.Spec{
			ID: forward.ID, DeviceID: forward.DeviceID, Mode: forward.Mode,
			Min: forward.Min, Preferred: forward.Preferred, Max: forward.Max,
			DeviceMax: forward.DeviceMax, Enabled: true, UseReserved: forward.UseReserved, ManualPorts: forward.ManualPorts,
		})
	}
	var out ports.Outcome
	host := s.poolHost
	if host == "" {
		host = "127.0.0.1"
	}
	byPort := map[int]*dataPort{}
	var opened []net.Listener
	closeOpened := func() {
		for _, ln := range opened {
			_ = ln.Close()
		}
	}
	// Bind is the authority. Retry only automatic candidates occupied by another
	// listener; other errors (invalid host, permission) remain explicit.
	candidatePool := *s.pool
	candidatePool.Unavailable = make(map[int]bool, len(s.pool.Unavailable))
	for port, unavailable := range s.pool.Unavailable {
		candidatePool.Unavailable[port] = unavailable
	}
	for {
		if ctx.Err() != nil {
			closeOpened()
			return "", nil, nil, ctx.Err()
		}
		out = ports.Allocate(candidatePool, specs)
		failedPort := 0
		for _, item := range out.Assignments {
			dp := byPort[item.Port]
			if dp == nil {
				ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(item.Port)))
				if err != nil {
					closeOpened()
					if !errors.Is(err, syscall.EADDRINUSE) {
						return "", nil, nil, err
					}
					failedPort = item.Port
					break
				}
				opened = append(opened, ln)
				dp = &dataPort{port: item.Port, addr: ln.Addr().String(), ln: ln, state: map[int64]string{}}
				byPort[item.Port] = dp
			}
			dp.state[item.ForwardID] = item.State
		}
		if failedPort == 0 {
			break
		}
		candidatePool.Unavailable[failedPort] = true
		opened = nil
		byPort = map[int]*dataPort{}
	}

	controlLn, err := net.Listen("tcp", controlAddr)
	if err != nil {
		closeOpened()
		return "", nil, nil, err
	}
	opened = append(opened, controlLn)
	forwardLns := map[int64]net.Listener{}
	var bound []string
	for i := range s.forwards {
		forward := s.forwards[i]
		if _, rejected := out.Rejected[forward.ID]; rejected || !forward.Enabled || !hasAssignment(out.Assignments, forward.ID) {
			continue
		}
		ln, listenErr := net.Listen("tcp", forward.Listen)
		if listenErr != nil {
			closeOpened()
			for _, item := range forwardLns {
				_ = item.Close()
			}
			return "", nil, nil, listenErr
		}
		opened = append(opened, ln)
		forwardLns[forward.ID] = ln
		s.forwards[i].Listen = ln.Addr().String()
		bound = append(bound, ln.Addr().String())

	}
	portsLive := make([]*dataPort, 0, len(byPort))
	var dataAddrs []string
	for _, dp := range byPort {
		portsLive = append(portsLive, dp)
		dataAddrs = append(dataAddrs, dp.addr)
	}
	sort.Slice(portsLive, func(i, j int) bool { return portsLive[i].port < portsLive[j].port })
	sort.Strings(dataAddrs)
	s.mu.Lock()
	s.ctx = ctx
	s.dataPorts = portsLive
	for id, ln := range forwardLns {
		s.forwardLns[id] = ln
	}
	s.reasons = out.Rejected
	s.views = out.Views
	if len(dataAddrs) > 0 {
		s.dataAddr = dataAddrs[0]
	}
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		for _, ln := range opened {
			_ = ln.Close()
		}
	}()
	go s.acceptControl(controlLn)
	for id, ln := range s.forwardLns {
		go s.acceptForward(ln, id)
	}
	for _, dp := range portsLive {
		go s.acceptData(dp.ln)
	}
	if s.revoked != nil {
		go s.pollRevoked(ctx)
	}
	s.info("weroxy pool started", map[string]string{"control": controlLn.Addr().String(), "data_ports": strconv.Itoa(len(portsLive))})
	return controlLn.Addr().String(), dataAddrs, bound, nil
}

func hasAssignment(items []ports.Assignment, id int64) bool {
	for _, item := range items {
		if item.ForwardID == id {
			return true
		}
	}
	return false
}

// Shrink stops issuing new sessions on the highest data ports above max.
// Sessions already using a drained port continue until they finish.
func (s *Service) Shrink(forwardID int64, max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.forwards {
		if s.forwards[i].ID != forwardID {
			continue
		}
		s.forwards[i].Max = max
		if s.forwards[i].Preferred > max {
			s.forwards[i].Preferred = max
		}
	}
	var items []ports.Assignment
	for _, dp := range s.dataPorts {
		if state, ok := dp.state[forwardID]; ok {
			items = append(items, ports.Assignment{ForwardID: forwardID, Port: dp.port, State: state})
		}
	}
	for _, item := range ports.MarkDrain(items, forwardID, max) {
		for _, dp := range s.dataPorts {
			if dp.port == item.Port {
				dp.state[forwardID] = item.State
			}
		}
	}
	s.closeIdleLocked()
}

// DataPorts reports how many data listeners are open.
func (s *Service) DataPorts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, dp := range s.dataPorts {
		if dp.ln != nil {
			n++
		}
	}
	return n
}

// PortOpen reports whether a data port still accepts connections.
func (s *Service) PortOpen(port int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, dp := range s.dataPorts {
		if dp.port == port && dp.ln != nil {
			return true
		}
	}
	return false
}

// Rows copies the current forward snapshot for the quick list.
// The byte counters are read after the service lock is released.
func (s *Service) Rows() []catalog.Row {
	s.mu.Lock()
	forwards := append([]Forward(nil), s.forwards...)
	controls := map[int64]bool{}
	for id, ctrl := range s.controls {
		controls[id] = ctrl != nil && !ctrl.closed.Load()
	}
	sessions := map[int64]int{}
	for _, sess := range s.sessions {
		if !sess.finished.Load() {
			sessions[sess.forwardID]++
		}
	}
	portsLive := make([]*dataPort, len(s.dataPorts))
	copy(portsLive, s.dataPorts)
	states := make([]map[int64]string, len(portsLive))
	failed := make([]bool, len(portsLive))
	for i, dp := range portsLive {
		failed[i] = dp.failed || dp.probeBad
		states[i] = map[int64]string{}
		for id, state := range dp.state {
			states[i][id] = state
		}
	}
	reasons := map[int64]string{}
	for id, reason := range s.reasons {
		reasons[id] = reason
	}
	scaleReasons := map[int64]string{}
	for id, observation := range s.scaling {
		scaleReasons[id] = observation.reason
	}
	views := map[int64]ports.View{}
	for id, view := range s.views {
		views[id] = view
	}
	names := map[int64]string{}
	for i := range s.devices {
		names[s.devices[i].ID] = s.devices[i].Name
	}
	unreachable := map[portHealthKey]bool{}
	reachable := map[portHealthKey]bool{}
	now := time.Now()
	for key, state := range s.portHealth {
		if state.until.After(now) {
			unreachable[key] = true
		} else if !state.success.IsZero() && state.success.Add(5*time.Minute).After(now) {
			reachable[key] = true
		}
	}
	var poolCopy *ports.Pool
	if s.pool != nil {
		pool := *s.pool
		pool.Unavailable = map[int]bool{}
		for port, value := range s.pool.Unavailable {
			pool.Unavailable[port] = value
		}
		for i, dp := range portsLive {
			if failed[i] || dp.ln == nil {
				pool.Unavailable[dp.port] = true
			}
		}
		poolCopy = &pool
	}
	s.mu.Unlock()
	snap := metrics.Snapshot{}
	if s.count != nil {
		snap = s.count.Snapshot()
	}
	if poolCopy != nil {
		var specs []ports.Spec
		var actual []ports.Assignment
		for _, f := range forwards {
			blocked := map[int]bool{}
			for key, value := range unreachable {
				if key.deviceID == f.DeviceID && value {
					blocked[key.port] = true
				}
			}
			specs = append(specs, ports.Spec{ID: f.ID, DeviceID: f.DeviceID, Mode: f.Mode, Min: f.Min, Preferred: f.Preferred, Max: f.Max, DeviceMax: f.DeviceMax, Enabled: f.Enabled, UseReserved: f.UseReserved, ManualPorts: f.ManualPorts, Unavailable: blocked})
			for i, state := range states {
				value := state[f.ID]
				if value == ports.Draining || (value == ports.Serving && !failed[i] && !blocked[portsLive[i].port]) {
					actual = append(actual, ports.Assignment{ForwardID: f.ID, DeviceID: f.DeviceID, Port: portsLive[i].port, State: value})
				}
			}
		}
		views = ports.Explain(*poolCopy, specs, actual)
	}
	var rows []catalog.Row
	for _, forward := range forwards {
		_, portNum, ok := ports.ParseHostPort(forward.Listen)
		if !ok {
			portNum = 0
		}
		current := 0
		var allocatedPorts []int
		reachability := "unknown"
		observed, allReachable := 0, true
		for index, state := range states {
			if state[forward.ID] != "" {
				allocatedPorts = append(allocatedPorts, portsLive[index].port)
				if state[forward.ID] == ports.Serving {
					observed++
					allReachable = allReachable && reachable[portHealthKey{deviceID: forward.DeviceID, port: portsLive[index].port}]
				}
			}
			if state[forward.ID] == ports.Serving && unreachable[portHealthKey{deviceID: forward.DeviceID, port: portsLive[index].port}] {
				reachability = "unreachable"
			}
			if state[forward.ID] == ports.Serving {
				current++
			}
		}
		if reachability == "unknown" && observed > 0 && allReachable {
			reachability = "reachable"
		}
		online := "OFFLINE"
		if controls[forward.DeviceID] {
			online = "ONLINE"
		}
		view := views[forward.ID]
		// Faulted and draining allocations still consume device ownership.
		if forward.DeviceMax > 0 && poolCopy != nil {
			owned := map[int]bool{}
			mine := map[int]bool{}
			for i, state := range states {
				for _, f := range forwards {
					if f.DeviceID == forward.DeviceID && state[f.ID] != "" {
						owned[portsLive[i].port] = true
					}
				}
				if state[forward.ID] != "" {
					mine[portsLive[i].port] = true
				}
			}
			room := forward.DeviceMax - len(owned)
			if room < 0 {
				room = 0
			}
			if forward.Mode != ports.Exclusive {
				for port := range owned {
					if !mine[port] && !poolCopy.Unavailable[port] && !unreachable[portHealthKey{deviceID: forward.DeviceID, port: port}] {
						room++
					}
				}
			}
			if view.CanGrowBy > room {
				view.CanGrowBy = room
			}
		}
		limit := forward.Max - current
		if limit < 0 {
			limit = 0
		}
		if view.CanGrowBy > limit {
			view.CanGrowBy = limit
		}
		if poolCopy != nil {
			view.AvailableMaxTotal = view.Current + view.CanGrowBy
		}
		available := view.AvailableMaxTotal
		if available == 0 && poolCopy == nil {
			available = current
		}
		name := forward.Device
		if names[forward.DeviceID] != "" {
			name = names[forward.DeviceID]
		}
		row := catalog.Row{
			ForwardID: forward.ID,
			Port:      portNum, Device: name, Target: forward.Target, ClientState: online,
			DataPorts: allocatedPorts, DataReachability: reachability, Listen: forward.Listen, DataHealthy: view.Current, DataDraining: view.Draining, CanGrow: view.CanGrowBy,
			Sessions: sessions[forward.ID], DataCurrent: current, DataMax: forward.Max, AvailableMax: available,
			UpBytes: snap.ForwardUp[forward.ID], DownBytes: snap.ForwardDown[forward.ID],
		}
		if reason := reasons[forward.ID]; reason != "" {
			row.Reasons = append(row.Reasons, reason)
		}
		if reason := scaleReasons[forward.ID]; reason != "" {
			row.Reasons = append(row.Reasons, reason)
		}
		for index, state := range states {
			if state[forward.ID] == ports.Serving && failed[index] {
				row.Reasons = append(row.Reasons, "data_listener_failed")
				break
			}
		}
		for index, state := range states {
			if state[forward.ID] == ports.Serving && unreachable[portHealthKey{deviceID: forward.DeviceID, port: portsLive[index].port}] {
				row.Reasons = append(row.Reasons, "device_data_port_unreachable")
				break
			}
		}
		rows = append(rows, row)
	}
	return rows
}

type portHealthKey struct {
	deviceID int64
	port     int
}
type portHealth struct {
	success  time.Time
	failures int
	last     time.Time
	until    time.Time
}

// Only the affected device is quarantined after repeated data-dial failures.
// A successful data bind immediately clears its observation.
func (s *Service) reportPortFailureLocked(deviceID int64, port int) {
	if deviceID == 0 || port == 0 {
		return
	}
	now := time.Now()
	key := portHealthKey{deviceID: deviceID, port: port}
	if len(s.portHealth) >= 4096 {
		for item, state := range s.portHealth {
			if state.last.Add(10 * time.Minute).Before(now) {
				delete(s.portHealth, item)
			}
		}
		if len(s.portHealth) >= 4096 && s.portHealth[key].last.IsZero() {
			return
		}
	}
	state := s.portHealth[key]
	if now.Sub(state.last) > time.Minute {
		state.failures = 0
	}
	state.failures++
	state.last = now
	if state.failures >= 3 {
		state.until = now.Add(time.Minute)
		state.failures = 0
	}
	s.portHealth[key] = state
}

func (s *Service) reportPortSuccessLocked(deviceID int64, port int) {
	if port != 0 {
		key := portHealthKey{deviceID: deviceID, port: port}
		if _, exists := s.portHealth[key]; !exists && len(s.portHealth) >= 4096 {
			return // Unknown is preferable to an unbounded observation cache.
		}
		s.portHealth[key] = portHealth{success: time.Now()}
	}
}

func (s *Service) pickLocked(forwardID, deviceID int64) (string, int) {
	best := -1
	addr := ""
	portNum := 0
	now := time.Now()
	for _, dp := range s.dataPorts {
		if dp.state[forwardID] != ports.Serving || dp.ln == nil || dp.failed || dp.probeBad || s.portHealth[portHealthKey{deviceID: deviceID, port: dp.port}].until.After(now) {
			continue
		}
		pending := dp.sessions - dp.ready
		// A pending handshake occupies an FD and may still fail or time out.
		// Give it twice the weight of an established session.
		pressure := dp.ready + 2*pending
		if best < 0 || pressure < best {
			best = pressure
			addr = dp.addr
			portNum = dp.port
		}
	}
	return addr, portNum
}

func (s *Service) holdPort(port int) {
	if port == 0 {
		return
	}
	for _, dp := range s.dataPorts {
		if dp.port == port {
			dp.sessions++
		}
	}
}

func (s *Service) readyPortLocked(port int) {
	for _, dp := range s.dataPorts {
		if dp.port == port && dp.ready < dp.sessions {
			dp.ready++
		}
	}
}

func (s *Service) releasePort(port int, ready bool) {
	if port == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, dp := range s.dataPorts {
		if dp.port != port {
			continue
		}
		if dp.sessions > 0 {
			dp.sessions--
		}
		if ready && dp.ready > 0 {
			dp.ready--
		}
	}
	s.closeIdleLocked()
}

func (s *Service) closeIdleLocked() {
	for _, dp := range s.dataPorts {
		if dp.ln == nil || dp.sessions > 0 {
			continue
		}
		serving := false
		for _, state := range dp.state {
			if state == ports.Serving {
				serving = true
			}
		}
		if serving {
			continue
		}
		if stop := s.dataStops[dp.port]; stop != nil {
			stop()
			delete(s.dataStops, dp.port)
		}
		_ = dp.ln.Close()
		dp.ln = nil
	}
}

func (s *Service) reject(reason string) {
	if s.count != nil {
		s.count.Reject(reason)
	}
}

func visitorIP(conn net.Conn) net.IP {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

var errNoPool = poolError("weroxy data pool is not configured")

type poolError string

func (e poolError) Error() string { return string(e) }

// Ready checks known runtime shutdown and pooled listener failures. It does
// not depend on metrics persistence or any individual client's reachability.
func (s *Service) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining.Load() || s.ctx == nil || s.ctx.Err() != nil {
		return false
	}
	for _, port := range s.dataPorts {
		if port.failed || port.probeBad {
			return false
		}
	}
	return true
}
