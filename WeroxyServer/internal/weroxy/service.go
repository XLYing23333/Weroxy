// Package weroxy accepts WeroxyClient connections on an explicit TCP control port.
package weroxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"weroxy/server/internal/logging"
	"weroxy/server/internal/metrics"
	"weroxy/server/internal/policy"
	"weroxy/server/internal/ports"
	wp "weroxy/server/internal/protocol/weroxy"
	"weroxy/server/internal/secure"
)

const (
	// ControlIdle is the read deadline for an authenticated control connection.
	ControlIdle = 180 * time.Second
	// HandshakeTimeout applies until a data session reaches READY.
	HandshakeTimeout = 15 * time.Second
	// TicketTTL is how long a data ticket remains usable.
	TicketTTL = 30 * time.Second

	defaultMaxUnauth   = 64
	defaultUnauthPerIP = 32
	defaultMaxPending  = 128
	defaultWriteQueue  = 16
	controlPingEvery   = 60 * time.Second
	controlRTTFresh    = 180 * time.Second
)

// Device is an in-memory Weroxy client. TokenMAC is not the token.
type Device struct {
	ID         int64
	Name       string
	UID        string
	TokenMAC   []byte
	Credential secure.Credential
	Revoked    bool
	Paused     bool
}

// Forward is one visitor listener and the target sent in OPEN.
type Forward struct {
	ID          int64
	DeviceID    int64
	Device      string
	Listen      string
	Target      string
	Mode        string
	Min         int
	Preferred   int
	Max         int
	DeviceMax   int
	Enabled     bool
	UseReserved bool
	ManualPorts []int
}

// Options configures one v2 runtime.
type Options struct {
	Devices        []Device
	Forwards       []Forward
	Log            *logging.Logger
	Software       string
	ControlIdle    time.Duration
	Handshake      time.Duration
	TicketTTL      time.Duration
	MaxUnauth      int
	MaxUnauthPerIP int
	MaxPending     int
	Revoked        func() ([]string, error)
	RevokeEvery    time.Duration
	// OnRetire runs after a control is marked closed and before the map is updated.
	// Tests use it to install a replacement control.
	OnRetire func(generation uint64)
	// Pool assigns data ports when StartAllocated is used. Nil keeps the single --weroxy-data listener.
	Pool     *ports.Pool
	PoolHost string
	Admit    *policy.Admission
	Rules    *policy.Table
	Count    *metrics.Counters
}

// Service is the v2 control listener, the single data listener, and the forward listeners.
type Service struct {
	devices          []Device
	forwards         []Forward
	log              *logging.Logger
	software         string
	controlIdle      time.Duration
	handshake        time.Duration
	ticketTTL        time.Duration
	maxUnauth        int
	maxUnauthPerIP   int
	maxPending       int
	writeQueue       int
	draining         atomic.Bool
	revoked          func() ([]string, error)
	revokeEvery      time.Duration
	onRetire         func(uint64)
	beforeMetricOpen func()
	pool             *ports.Pool
	poolHost         string
	admission        *policy.Admission
	rules            *policy.Table
	count            *metrics.Counters

	mu               sync.Mutex
	reconcileMu      sync.Mutex
	ctx              context.Context
	forwardLns       map[int64]net.Listener
	forwardStops     map[int64]func() bool
	dataStops        map[int]func() bool
	controls         map[int64]*control
	sessions         map[string]*session
	pending          int
	unauth           int
	unauthByIP       map[string]int
	seq              uint64
	dataAddr         string
	dataPorts        []*dataPort
	portHealth       map[portHealthKey]portHealth
	reasons          map[int64]string
	views            map[int64]ports.View
	scaling          map[int64]scaleObservation
	healthOnce       sync.Once
	globalQuarantine map[int]time.Time
}

type control struct {
	deviceID   int64
	generation uint64
	conn       net.Conn
	send       chan wp.Frame
	done       chan struct{}
	closed     atomic.Bool
	pingID     uint64
	pingSent   time.Time
	pongAt     time.Time
	rtt        time.Duration
}

type session struct {
	id           string
	deviceID     int64
	uid          string
	generation   uint64
	credentialID [32]byte
	visitor      net.Conn
	data         net.Conn
	target       string
	dataAddr     string
	ticket       string
	timer        *time.Timer
	expires      time.Time
	used         bool
	ready        bool
	finished     atomic.Bool
	forwardID    int64
	port         int
	grant        *policy.Grant
}

type dataPort struct {
	port          int
	addr          string
	ln            net.Listener
	state         map[int64]string
	sessions      int
	ready         int
	failed        bool
	probeBad      bool
	probeFailures int
}

// New copies devices into memory. Packet forwarding does not read SQLite.
func New(opt Options) *Service {
	if opt.Software == "" {
		opt.Software = "0.0.0-skeleton"
	}
	if opt.ControlIdle <= 0 {
		opt.ControlIdle = ControlIdle
	}
	if opt.Handshake <= 0 {
		opt.Handshake = HandshakeTimeout
	}
	if opt.TicketTTL <= 0 {
		opt.TicketTTL = TicketTTL
	}
	if opt.MaxUnauth <= 0 {
		opt.MaxUnauth = defaultMaxUnauth
	}
	if opt.MaxUnauthPerIP <= 0 {
		opt.MaxUnauthPerIP = defaultUnauthPerIP
	}
	if opt.MaxPending <= 0 {
		opt.MaxPending = defaultMaxPending
	}
	if opt.RevokeEvery <= 0 {
		opt.RevokeEvery = 2 * time.Second
	}
	devices := make([]Device, len(opt.Devices))
	for i, device := range opt.Devices {
		devices[i] = device
		devices[i].TokenMAC = append([]byte(nil), device.TokenMAC...)
	}
	return &Service{
		devices:        devices,
		forwards:       normalizeForwards(opt.Forwards),
		log:            opt.Log,
		software:       opt.Software,
		controlIdle:    opt.ControlIdle,
		handshake:      opt.Handshake,
		ticketTTL:      opt.TicketTTL,
		maxUnauth:      opt.MaxUnauth,
		maxUnauthPerIP: opt.MaxUnauthPerIP,
		maxPending:     opt.MaxPending,
		writeQueue:     defaultWriteQueue,
		revoked:        opt.Revoked,
		revokeEvery:    opt.RevokeEvery,
		onRetire:       opt.OnRetire,
		pool:           opt.Pool,
		poolHost:       opt.PoolHost,
		admission:      opt.Admit,
		rules:          opt.Rules,
		count:          opt.Count,
		controls:       map[int64]*control{},
		forwardLns:     map[int64]net.Listener{},
		forwardStops:   map[int64]func() bool{},
		dataStops:      map[int]func() bool{},
		sessions:       map[string]*session{},
		unauthByIP:     map[string]int{},
		reasons:        map[int64]string{},
		portHealth:     map[portHealthKey]portHealth{},
	}
}

func normalizeForwards(in []Forward) []Forward {
	out := make([]Forward, len(in))
	copy(out, in)
	for i := range out {
		if out[i].Mode == "" {
			out[i].Mode = ports.Shared
		}
		if out[i].Min == 0 && out[i].Preferred == 0 && out[i].Max == 0 {
			out[i].Min, out[i].Preferred, out[i].Max = 1, 1, 4
		}
		if out[i].Mode != "" && in[i].Mode == "" {
			out[i].Enabled = true
		}
	}
	return out
}

// Start listens on the control address, the data address, and each forward.
func (s *Service) Start(ctx context.Context, controlAddr, dataAddr string) (string, string, []string, error) {
	controlLn, err := net.Listen("tcp", controlAddr)
	if err != nil {
		return "", "", nil, err
	}
	dataLn, err := net.Listen("tcp", dataAddr)
	if err != nil {
		controlLn.Close()
		return "", "", nil, err
	}
	s.dataAddr = dataLn.Addr().String()
	listeners := map[int64]net.Listener{}
	var bound []string
	for i := range s.forwards {
		if !s.forwards[i].Enabled {
			continue
		}
		ln, listenErr := net.Listen("tcp", s.forwards[i].Listen)
		if listenErr != nil {
			controlLn.Close()
			dataLn.Close()
			for _, open := range listeners {
				open.Close()
			}
			return "", "", nil, listenErr
		}
		s.forwards[i].Listen = ln.Addr().String()
		bound = append(bound, ln.Addr().String())
		listeners[s.forwards[i].ID] = ln
	}
	go func() {
		<-ctx.Done()
		controlLn.Close()
		dataLn.Close()
		for _, ln := range listeners {
			ln.Close()
		}
	}()
	go s.acceptControl(controlLn)
	go s.acceptData(dataLn)
	s.mu.Lock()
	s.ctx = ctx
	for id, ln := range listeners {
		s.forwardLns[id] = ln
	}
	s.mu.Unlock()
	for id, ln := range listeners {
		go s.acceptForward(ln, id)
	}
	if s.revoked != nil {
		go s.pollRevoked(ctx)
	}
	s.info("weroxy listener started", map[string]string{"control": controlLn.Addr().String(), "data": s.dataAddr})
	return controlLn.Addr().String(), s.dataAddr, bound, nil
}

func (s *Service) acceptControl(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if !s.admit(conn) {
			conn.Close()
			continue
		}
		go s.serveControl(conn)
	}
}

func (s *Service) acceptData(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			if s.ctx != nil && s.ctx.Err() == nil {
				for _, dp := range s.dataPorts {
					if dp.ln == ln {
						dp.failed = true
					}
				}
			}
			s.mu.Unlock()
			return
		}
		if !s.admit(conn) {
			conn.Close()
			continue
		}
		go s.serveData(conn)
	}
}

func (s *Service) acceptForward(ln net.Listener, forwardID int64) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		var forward Forward
		valid := s.forwardLns[forwardID] == ln
		if valid {
			valid = false
			for _, item := range s.forwards {
				if item.ID == forwardID && item.Enabled {
					forward, valid = item, true
					break
				}
			}
		}
		s.mu.Unlock()
		if !valid {
			_ = conn.Close()
			continue
		}
		// Admission and OPEN enqueue do not perform network I/O. Do them before
		// spawning session work so rejected bursts cannot create unbounded workers.
		s.onVisitor(forward, conn)
	}
}

func (s *Service) admit(conn net.Conn) bool {
	ip := weroxySourceIP(conn)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining.Load() || s.unauth >= s.maxUnauth || s.unauthByIP[ip] >= s.maxUnauthPerIP {
		return false
	}
	s.unauth++
	s.unauthByIP[ip]++
	return true
}

func weroxySourceIP(conn net.Conn) string {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP.String()
	}
	return conn.RemoteAddr().String()
}

func (s *Service) releaseUnauth(conn net.Conn) {
	ip := weroxySourceIP(conn)
	s.mu.Lock()
	if s.unauth > 0 {
		s.unauth--
	}
	if s.unauthByIP[ip] > 1 {
		s.unauthByIP[ip]--
	} else {
		delete(s.unauthByIP, ip)
	}
	s.mu.Unlock()
}

func (s *Service) serveControl(conn net.Conn) {
	unauth := conn
	held := true
	var ctrl *control
	defer func() {
		s.retire(ctrl)
		_ = conn.Close()
		if held {
			s.releaseUnauth(unauth)
		}
	}()
	raw := conn
	_ = conn.SetDeadline(time.Now().Add(s.handshake))
	selector, err := secure.ReadPreface(raw, 'C')
	if err != nil {
		return
	}
	device, ok := s.lookupCredential(selector)
	if !ok {
		return
	}
	welcome, _ := wp.PutStrings(s.software)
	encrypted, _, err := secure.Server(raw, 'C', selector, device.Credential.PSK, nil, welcome)
	if err != nil {
		return
	}
	conn = encrypted
	reader := wp.Reader{R: conn}
	for {
		if ctrl != nil {
			_ = conn.SetReadDeadline(time.Now().Add(s.controlIdle))
		}
		frame, err := reader.Next()
		if err != nil {
			if errors.Is(err, wp.ErrVersion) {
				_ = writeError(conn, 0, wp.CodeVersion)
			}
			if ctrl != nil {
				s.retire(ctrl)
			}
			return
		}
		switch frame.Type {
		case wp.TypeHello:
			return
		case wp.TypeDiagnose:
			if ctrl != nil {
				return
			}
			s.diagnose(conn, frame, device)
			return
		case wp.TypeAuth:
			if ctrl != nil {
				return
			}
			next, code := s.login(frame, conn, device)
			if next == nil {
				_ = writeError(conn, frame.RequestID, code)
				return
			}
			ctrl = next
			_ = conn.SetDeadline(time.Time{})
			s.releaseUnauth(raw)
			held = false
			body, _ := wp.PutStrings(strconv.FormatUint(ctrl.generation, 10), deviceUID(s, ctrl.deviceID))
			s.enqueue(ctrl, wp.Frame{Type: wp.TypeSync, RequestID: frame.RequestID, Body: body})
		case wp.TypePing:
			if ctrl == nil {
				return
			}
			s.enqueue(ctrl, wp.Frame{Type: wp.TypePong, RequestID: frame.RequestID})
		case wp.TypePong:
			if ctrl == nil {
				return
			}
			s.mu.Lock()
			if ctrl.pingID != 0 && frame.RequestID == ctrl.pingID && !ctrl.pingSent.IsZero() {
				ctrl.rtt = time.Since(ctrl.pingSent)
				ctrl.pongAt = time.Now()
				ctrl.pingID = 0
				ctrl.pingSent = time.Time{}
			}
			s.mu.Unlock()
		case wp.TypeCancel:
			if ctrl == nil {
				return
			}
			parts, err := wp.Strings(frame.Body, 2)
			if err == nil {
				s.finishID(ctrl, parts[0], parts[1])
			}
		default:
		}
	}
}

// diagnose authenticates without registering a control connection or replacing
// the running client. Only the matching device receives its serving data ports.
func (s *Service) diagnose(conn net.Conn, frame wp.Frame, authenticated Device) {
	parts, err := wp.Strings(frame.Body, 1)
	if err != nil {
		return
	}
	device, code := s.confirmCredential(authenticated, parts[0])
	if code != 0 {
		_ = writeError(conn, frame.RequestID, code)
		return
	}
	s.mu.Lock()
	portSet := map[int]struct{}{}
	for _, dp := range s.dataPorts {
		if dp.ln == nil || dp.failed {
			continue
		}
		for _, forward := range s.forwards {
			if forward.DeviceID == device.ID && dp.state[forward.ID] == ports.Serving {
				portSet[dp.port] = struct{}{}
			}
		}
	}
	if len(s.dataPorts) == 0 && s.dataAddr != "" {
		_, port, err := net.SplitHostPort(s.dataAddr)
		if err == nil {
			number, err := strconv.Atoi(port)
			if err == nil {
				portSet[number] = struct{}{}
			}
		}
	}
	s.mu.Unlock()
	portList := make([]int, 0, len(portSet))
	for port := range portSet {
		portList = append(portList, port)
	}
	sort.Ints(portList)
	values := make([]string, 0, len(portList))
	for _, port := range portList {
		values = append(values, strconv.Itoa(port))
	}
	body, err := wp.PutStrings(time.Now().UTC().Format(time.RFC3339Nano), strings.Join(values, ","))
	if err == nil {
		_ = writeFrame(conn, wp.Frame{Type: wp.TypeDiagnose, RequestID: frame.RequestID, Body: body})
	}
}

func (s *Service) login(frame wp.Frame, conn net.Conn, authenticated Device) (*control, byte) {
	parts, err := wp.Strings(frame.Body, 1)
	if err != nil {
		return nil, wp.CodeAuth
	}
	device, status := s.confirmCredential(authenticated, parts[0])
	if status != 0 {
		return nil, status
	}
	s.mu.Lock()
	device, status = s.confirmCredentialLocked(authenticated, parts[0])
	if status != 0 {
		s.mu.Unlock()
		return nil, status
	}
	if s.draining.Load() {
		s.mu.Unlock()
		return nil, wp.CodeBusy
	}
	if current := s.controls[device.ID]; current != nil && !current.closed.Load() {
		s.mu.Unlock()
		s.info("weroxy auth rejected", map[string]string{"device": device.Name, "reason": "control already healthy"})
		return nil, wp.CodeBusy
	}
	s.seq++
	next := &control{
		deviceID:   device.ID,
		generation: s.seq,
		conn:       conn,
		send:       make(chan wp.Frame, s.writeQueue),
		done:       make(chan struct{}),
	}
	s.controls[device.ID] = next
	s.mu.Unlock()
	go s.writeLoop(next)
	go s.pingControl(next)
	s.info("weroxy control attached", map[string]string{"device": device.Name})
	return next, 0
}

func (s *Service) serveData(conn net.Conn) {
	unauth := conn
	held := true
	defer func() {
		_ = conn.Close()
		if held {
			s.releaseUnauth(unauth)
		}
	}()
	raw := conn
	_ = raw.SetDeadline(time.Now().Add(s.handshake))
	selector, err := secure.ReadPreface(raw, 'D')
	if err != nil {
		return
	}
	s.mu.Lock()
	candidate := s.sessions[string(selector)]
	var snapshot struct {
		uid, id, ticket, dataAddr string
		generation                uint64
		expires                   time.Time
	}
	if candidate != nil {
		snapshot.uid = candidate.uid
		snapshot.id = candidate.id
		snapshot.ticket = candidate.ticket
		snapshot.dataAddr = candidate.dataAddr
		snapshot.generation = candidate.generation
		snapshot.expires = candidate.expires
	}
	s.mu.Unlock()
	if candidate == nil || candidate.finished.Load() || !time.Now().Before(snapshot.expires) {
		return
	}
	ticket, err := hex.DecodeString(snapshot.ticket)
	if err != nil {
		return
	}
	cred := secure.Derive(ticket, "data")
	clear(ticket)
	fields := []string{snapshot.uid, snapshot.id, strconv.FormatUint(snapshot.generation, 10), snapshot.dataAddr}
	encrypted, _, err := secure.Server(raw, 'D', selector, cred.PSK, fields, nil)
	if err != nil {
		return
	}
	conn = encrypted
	reader := wp.Reader{R: conn}
	next, err := reader.Next()
	if err != nil || next.Type != wp.TypeReady || len(next.Body) != 0 {
		return
	}
	if _, err := encrypted.Raw(); err != nil {
		return
	}
	body, _ := wp.PutStrings(snapshot.ticket, snapshot.uid, snapshot.id, snapshot.dataAddr)
	sess, _ := s.consume(wp.Frame{Body: body}, raw.LocalAddr().String())
	if sess == nil {
		return
	}
	s.releaseUnauth(raw)
	held = false
	rule := s.sessionRule(sess)
	if rule.ConnectSec.Set {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(rule.ConnectSec.Value) * time.Second))
	}
	s.mu.Lock()
	if sess.finished.Load() {
		s.mu.Unlock()
		return
	}
	sess.data = conn
	sess.ready = true
	if sess.timer != nil {
		sess.timer.Stop()
		sess.timer = nil
	}
	readyAt := time.Now()
	if s.pending > 0 {
		s.pending--
	}
	s.readyPortLocked(sess.port)
	s.reportPortSuccessLocked(sess.deviceID, sess.port)
	s.mu.Unlock()
	if s.count != nil {
		s.count.MarkReady(metrics.Weroxy, sess.id, readyAt)
	}
	if sess.grant != nil {
		sess.grant.Activate()
	}
	// Publish READY state before its acknowledgement can reach the client.
	// A simultaneous control disconnect must not retire this bound stream.
	if writeFrame(conn, wp.Frame{Type: wp.TypeReady, RequestID: next.RequestID}) != nil {
		s.finishWithReason(sess, "data_handshake")
		return
	}
	conn, err = encrypted.Raw()
	if err != nil {
		s.finishWithReason(sess, "data_handshake")
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_ = sess.visitor.SetDeadline(time.Time{})
	spliceLimited(sess.visitor, conn, func(n int) {
		if s.count != nil {
			s.count.Add(metrics.Weroxy, sess.id, metrics.Up, n)
		}
	}, func(n int) {
		if s.count != nil {
			s.count.Add(metrics.Weroxy, sess.id, metrics.Down, n)
		}
	}, rule)
	s.finish(sess)
}

func (s *Service) sessionRule(sess *session) policy.Rule {
	if s.rules == nil || sess == nil {
		return policy.Rule{}
	}
	device := ""
	listen := ""
	s.mu.Lock()
	for _, item := range s.devices {
		if item.ID == sess.deviceID {
			device = item.Name
			break
		}
	}
	for _, item := range s.forwards {
		if item.ID == sess.forwardID {
			listen = item.Listen
			if device == "" {
				device = item.Device
			}
			break
		}
	}
	s.mu.Unlock()
	return s.rules.Effective(device, device+"|"+listen)
}

func (s *Service) consume(frame wp.Frame, local string) (*session, byte) {
	parts, err := wp.Strings(frame.Body, 4)
	if err != nil {
		return nil, wp.CodeTicket
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[parts[2]]
	pooled := len(s.dataPorts) > 0
	if sess == nil || sess.used || sess.finished.Load() || sess.ticket != parts[0] || sess.uid != parts[1] || sess.dataAddr != parts[3] {
		return nil, wp.CodeTicket
	}
	if pooled {
		// Accept on a wildcard listener reports its concrete container IP.
		// The ticket still pins the session to its assigned local Data port.
		_, localPort, err := net.SplitHostPort(local)
		if err != nil || localPort != strconv.Itoa(sess.port) {
			return nil, wp.CodeTicket
		}
	}
	if !time.Now().Before(sess.expires) {
		return nil, wp.CodeTicket
	}
	device := s.deviceByUID(sess.uid)
	if device == nil || device.Revoked || device.ID != sess.deviceID || (sess.credentialID != [32]byte{} && device.Credential.ID != sess.credentialID) {
		return nil, wp.CodeTicket
	}
	sess.used = true
	return sess, 0
}

// forwardActiveLocked prevents an accepted socket from creating a session after
// its listener was removed or repointed by a configuration switch.
func (s *Service) forwardActiveLocked(forward Forward) bool {
	if s.forwardLns[forward.ID] == nil {
		return false
	}
	for _, item := range s.forwards {
		if item.ID == forward.ID {
			return item.Enabled && item.Listen == forward.Listen && item.Target == forward.Target && item.DeviceID == forward.DeviceID
		}
	}
	return false
}

func (s *Service) onVisitor(forward Forward, conn net.Conn) {
	ip := ""
	if parsed := visitorIP(conn); parsed != nil {
		ip = parsed.String()
	}
	s.mu.Lock()
	active := s.forwardActiveLocked(forward)
	device := s.deviceByID(forward.DeviceID)
	ctrl := s.controls[forward.DeviceID]
	if s.draining.Load() || !active || device == nil || device.Revoked || device.Paused || ctrl == nil || ctrl.closed.Load() || s.pending >= s.maxPending || !forward.Enabled {
		s.mu.Unlock()
		conn.Close()
		return
	}
	deviceName := device.Name
	s.mu.Unlock()
	var grant *policy.Grant
	if s.admission != nil {
		rule := s.rules.Effective(deviceName, deviceName+"|"+forward.Listen)
		var reason string
		grant, reason = s.admission.Acquire(visitorIP(conn), deviceName, deviceName+"|"+forward.Listen, rule)
		if reason != "" {
			s.reject(reason)
			if grant != nil {
				grant.Release()
			}
			conn.Close()
			return
		}
	}
	s.mu.Lock()
	active = s.forwardActiveLocked(forward)
	device = s.deviceByID(forward.DeviceID)
	ctrl = s.controls[forward.DeviceID]
	if s.draining.Load() || !active || device == nil || device.Revoked || device.Paused || ctrl == nil || ctrl.closed.Load() || s.pending >= s.maxPending {
		s.mu.Unlock()
		if grant != nil {
			grant.Release()
		}
		conn.Close()
		return
	}
	dataAddr, port := s.pickLocked(forward.ID, forward.DeviceID)
	if len(s.dataPorts) > 0 && dataAddr == "" {
		s.mu.Unlock()
		if grant != nil {
			grant.Release()
		}
		s.reject("no_port")
		conn.Close()
		return
	}
	if dataAddr == "" {
		dataAddr = s.dataAddr
	}
	if port == 0 {
		_, rawPort, splitErr := net.SplitHostPort(dataAddr)
		if splitErr == nil {
			port, _ = strconv.Atoi(rawPort)
		}
	}
	s.seq++
	var ticket [32]byte
	if _, err := rand.Read(ticket[:]); err != nil {
		s.mu.Unlock()
		if grant != nil {
			grant.Release()
		}
		conn.Close()
		return
	}
	sess := &session{
		id:           strconv.FormatUint(s.seq, 10),
		deviceID:     device.ID,
		uid:          device.UID,
		generation:   ctrl.generation,
		credentialID: device.Credential.ID,
		visitor:      conn,
		target:       forward.Target,
		dataAddr:     dataAddr,
		ticket:       hex.EncodeToString(ticket[:]),
		expires:      time.Now().Add(s.ticketTTL),
		forwardID:    forward.ID,
		port:         port,
		grant:        grant,
	}
	s.sessions[sess.id] = sess
	s.pending++
	s.holdPort(port)
	requestID := s.seq
	s.mu.Unlock()
	if s.beforeMetricOpen != nil {
		s.beforeMetricOpen()
	}
	if s.count != nil {
		s.count.Open(metrics.Weroxy, sess.id, sess.deviceID, sess.forwardID)
		s.count.Annotate(metrics.Weroxy, sess.id, deviceName, ip, "")
		s.count.SetRoute(metrics.Weroxy, sess.id, forward.Listen, sess.port)
	}
	// Retirement can win after publication but before the counter exists.
	// Close that late counter; otherwise the idempotent finish cannot revisit it.
	if sess.finished.Load() {
		if s.count != nil {
			s.count.CloseWithReason(metrics.Weroxy, sess.id, "closed")
		}
		return
	}
	s.mu.Lock()
	if !sess.finished.Load() && !sess.ready {
		sess.timer = time.AfterFunc(s.ticketTTL, func() { s.abandon(sess) })
	}
	s.mu.Unlock()
	body, err := wp.PutStrings(sess.id, sess.target, sess.dataAddr, sess.ticket)
	if err != nil || !s.enqueue(ctrl, wp.Frame{Type: wp.TypeOpen, RequestID: requestID, Body: body}) {
		s.finishWithReason(sess, "control_queue")
	}
}

// pingControl measures a server-originated control RTT without accepting
// client-supplied latency values. The outstanding probe is replaced each tick.
func (s *Service) pingControl(ctrl *control) {
	ticker := time.NewTicker(controlPingEvery)
	defer ticker.Stop()
	var seq uint64 = 1 << 63
	for {
		select {
		case <-ctrl.done:
			return
		case <-ticker.C:
			seq++
			s.mu.Lock()
			if ctrl.closed.Load() || s.controls[ctrl.deviceID] != ctrl {
				s.mu.Unlock()
				return
			}
			if s.enqueue(ctrl, wp.Frame{Type: wp.TypePing, RequestID: seq}) {
				ctrl.pingID = seq
				ctrl.pingSent = time.Now()
			}
			s.mu.Unlock()
		}
	}
}

// ControlRTTs returns fresh server-observed RTTs in milliseconds by device ID.
func (s *Service) ControlRTTs() map[int64]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[int64]int64{}
	now := time.Now()
	for id, ctrl := range s.controls {
		if ctrl.closed.Load() || ctrl.pongAt.IsZero() || now.Sub(ctrl.pongAt) > controlRTTFresh {
			continue
		}
		out[id] = ctrl.rtt.Milliseconds()
	}
	return out
}

func (s *Service) writeLoop(ctrl *control) {
	for {
		select {
		case <-ctrl.done:
			return
		case frame := <-ctrl.send:
			_ = ctrl.conn.SetWriteDeadline(time.Now().Add(s.handshake))
			if writeFrame(ctrl.conn, frame) != nil {
				go s.retire(ctrl)
				return
			}
		}
	}
}

func (s *Service) enqueue(ctrl *control, frame wp.Frame) bool {
	select {
	case <-ctrl.done:
		return false
	case ctrl.send <- frame:
		return true
	default:
		return false
	}
}

func (s *Service) retire(ctrl *control) {
	if ctrl == nil || !ctrl.closed.CompareAndSwap(false, true) {
		return
	}
	close(ctrl.done)
	_ = ctrl.conn.Close()
	if s.onRetire != nil {
		s.onRetire(ctrl.generation)
	}
	s.mu.Lock()
	if s.controls[ctrl.deviceID] == ctrl {
		delete(s.controls, ctrl.deviceID)
	}
	var drop []*session
	for _, sess := range s.sessions {
		if sess.deviceID == ctrl.deviceID && sess.generation == ctrl.generation && !sess.ready {
			drop = append(drop, sess)
		}
	}
	s.mu.Unlock()
	for _, sess := range drop {
		s.finishWithReason(sess, "control_lost")
	}
}

func (s *Service) finishID(ctrl *control, id, code string) {
	s.mu.Lock()
	sess := s.sessions[id]
	if sess == nil || sess.finished.Load() || sess.deviceID != ctrl.deviceID || sess.generation != ctrl.generation {
		s.mu.Unlock()
		return
	}
	reason := "client_closed"
	if !sess.ready {
		switch code {
		case "data":
			reason = "client_data_unreachable"
			s.reportPortFailureLocked(sess.deviceID, sess.port)
		case "data_handshake":
			reason = "data_handshake"
		case "target_denied":
			reason = "client_target_denied"
		case "target_dial":
			reason = "client_target_dial_failed"
		case "target":
			// Older Weroxy clients used one ambiguous code for both causes.
			reason = "client_target_unreachable"
		case "busy":
			reason = "client_busy"
		}
	}
	s.mu.Unlock()
	s.finishWithReason(sess, reason)
}

// Drain rejects new visitors, closes control connections, and lets READY
// sessions finish until the deadline. Pending handshakes are canceled at once.
func (s *Service) Drain(limit time.Duration) {
	if limit <= 0 || limit > 5*time.Minute {
		limit = 20 * time.Second
	}
	if !s.draining.CompareAndSwap(false, true) {
		return
	}
	s.mu.Lock()
	listeners := make([]net.Listener, 0, len(s.forwardLns))
	for _, ln := range s.forwardLns {
		listeners = append(listeners, ln)
	}
	controls := make([]*control, 0, len(s.controls))
	for _, ctrl := range s.controls {
		controls = append(controls, ctrl)
	}
	s.mu.Unlock()
	for _, ln := range listeners {
		_ = ln.Close()
	}
	for _, ctrl := range controls {
		s.retire(ctrl)
	}
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		s.mu.Lock()
		remaining := len(s.sessions)
		s.mu.Unlock()
		if remaining == 0 {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			s.mu.Lock()
			left := make([]*session, 0, len(s.sessions))
			for _, sess := range s.sessions {
				left = append(left, sess)
			}
			s.mu.Unlock()
			s.info("weroxy shutdown drain timed out", map[string]string{"sessions": strconv.Itoa(len(left))})
			for _, sess := range left {
				s.finishWithReason(sess, "shutdown_drain_timeout")
			}
			return
		}
	}
}

func (s *Service) finish(sess *session) { s.finishWithReason(sess, "closed") }

func (s *Service) finishWithReason(sess *session, reason string) {
	if sess == nil || !sess.finished.CompareAndSwap(false, true) {
		return
	}
	s.mu.Lock()
	if s.sessions[sess.id] == sess {
		delete(s.sessions, sess.id)
	}
	if sess.timer != nil {
		sess.timer.Stop()
		sess.timer = nil
	}
	visitor, data := sess.visitor, sess.data
	grant := sess.grant
	port := sess.port
	ready := sess.ready
	if !ready && s.pending > 0 {
		s.pending--
	}
	s.mu.Unlock()
	if grant != nil {
		grant.Release()
	}
	if s.count != nil {
		s.count.CloseWithReason(metrics.Weroxy, sess.id, reason)
	}
	s.releasePort(port, ready)
	if visitor != nil {
		_ = visitor.Close()
	}
	if data != nil {
		_ = data.Close()
	}
}

// abandon drops a session that never reached READY. A session that is already forwarding stays up.
func (s *Service) abandon(sess *session) {
	s.mu.Lock()
	if sess.ready || !sess.finished.CompareAndSwap(false, true) {
		s.mu.Unlock()
		return
	}
	if s.sessions[sess.id] == sess {
		delete(s.sessions, sess.id)
	}
	if sess.timer != nil {
		sess.timer.Stop()
		sess.timer = nil
	}
	visitor, data := sess.visitor, sess.data
	grant := sess.grant
	port := sess.port
	ready := sess.ready
	if !ready && s.pending > 0 {
		s.pending--
	}
	s.mu.Unlock()
	if grant != nil {
		grant.Release()
	}
	if s.count != nil {
		s.count.CloseWithReason(metrics.Weroxy, sess.id, "ticket_timeout")
	}
	s.releasePort(port, ready)
	if visitor != nil {
		_ = visitor.Close()
	}
	if data != nil {
		_ = data.Close()
	}
}

// Revoke drops the device's control connection and every session, including ready ones.
func (s *Service) Revoke(uid string) {
	s.mu.Lock()
	var deviceID int64
	for i := range s.devices {
		if s.devices[i].UID == uid {
			s.devices[i].Revoked = true
			deviceID = s.devices[i].ID
		}
	}
	ctrl := s.controls[deviceID]
	var drop []*session
	for _, sess := range s.sessions {
		if sess.uid == uid {
			drop = append(drop, sess)
		}
	}
	s.mu.Unlock()
	if ctrl != nil {
		s.retire(ctrl)
	}
	for _, sess := range drop {
		s.finishWithReason(sess, "credential_revoked")
	}
}

func (s *Service) pollRevoked(ctx context.Context) {
	ticker := time.NewTicker(s.revokeEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ids, err := s.revoked()
			if err != nil {
				continue
			}
			for _, id := range ids {
				s.Revoke(id)
			}
		}
	}
}

func deviceUID(s *Service, id int64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if device := s.deviceByID(id); device != nil {
		return device.UID
	}
	return ""
}

func (s *Service) deviceByID(id int64) *Device {
	for i := range s.devices {
		if s.devices[i].ID == id {
			return &s.devices[i]
		}
	}
	return nil
}

func (s *Service) deviceByUID(uid string) *Device {
	for i := range s.devices {
		if s.devices[i].UID == uid {
			return &s.devices[i]
		}
	}
	return nil
}

func (s *Service) info(msg string, fields map[string]string) {
	if s.log != nil {
		s.log.InfoLimited(msg, fields)
	}
}

func writeFrame(conn net.Conn, frame wp.Frame) error {
	raw, err := wp.Encode(frame)
	if err != nil {
		return err
	}
	return writeAll(conn, raw)
}

func writeError(conn net.Conn, requestID uint64, code byte) error {
	body, err := wp.PutError(code, "")
	if err != nil {
		return err
	}
	return writeFrame(conn, wp.Frame{Type: wp.TypeError, RequestID: requestID, Body: body})
}

func writeAll(conn io.Writer, raw []byte) error {
	for len(raw) > 0 {
		n, err := conn.Write(raw)
		raw = raw[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func splice(left, right net.Conn, up, down func(int)) {
	spliceLimited(left, right, up, down, policy.Rule{})
}

func spliceLimited(left, right net.Conn, up, down func(int), rule policy.Rule) {
	var wg sync.WaitGroup
	wg.Add(2)
	until := time.Time{}
	if rule.WaitSec.Set {
		until = time.Now().Add(time.Duration(rule.WaitSec.Value) * time.Second)
	}
	copyDir := func(dst, src net.Conn, add func(int)) {
		defer wg.Done()
		var srcReader io.Reader = src
		if rule.Bandwidth.Set && rule.Bandwidth.Value > 0 {
			srcReader = &paceReader{r: src, bps: rule.Bandwidth.Value}
		}
		_, err := io.Copy(countWriter{Writer: dst, add: add}, &deadlineReader{r: srcReader, c: src, idle: rule.IdleSec, until: until})
		closeWrite(dst)
		if err != nil && !errors.Is(err, io.EOF) {
			_ = dst.Close()
			_ = src.Close()
		}
	}
	go copyDir(right, left, down)
	go copyDir(left, right, up)
	wg.Wait()
}

type deadlineReader struct {
	r     io.Reader
	c     net.Conn
	idle  policy.Limit
	until time.Time
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	if d.idle.Set && d.idle.Value == 0 {
		return 0, io.EOF
	}
	deadline := time.Time{}
	if d.idle.Set && d.idle.Value > 0 {
		deadline = time.Now().Add(time.Duration(d.idle.Value) * time.Second)
	}
	if !d.until.IsZero() && (deadline.IsZero() || d.until.Before(deadline)) {
		deadline = d.until
	}
	if !deadline.IsZero() && d.c != nil {
		_ = d.c.SetReadDeadline(deadline)
	}
	return d.r.Read(p)
}

type paceReader struct {
	r     io.Reader
	bps   int
	start time.Time
	n     int64
}

func (p *paceReader) Read(buf []byte) (int, error) {
	if p.start.IsZero() {
		p.start = time.Now()
	}
	if p.bps > 0 && len(buf) > p.bps {
		buf = buf[:p.bps]
	}
	n, err := p.r.Read(buf)
	p.n += int64(n)
	if p.bps > 0 && n > 0 {
		need := time.Duration(p.n) * time.Second / time.Duration(p.bps)
		if wait := need - time.Since(p.start); wait > 0 {
			time.Sleep(wait)
		}
	}
	return n, err
}

type countWriter struct {
	io.Writer
	add func(int)
}

func (c countWriter) Write(p []byte) (int, error) {
	n, err := c.Writer.Write(p)
	if n > 0 && c.add != nil {
		c.add(n)
	}
	return n, err
}

func closeWrite(conn net.Conn) {
	type halfCloser interface{ CloseWrite() error }
	if c, ok := conn.(halfCloser); ok {
		_ = c.CloseWrite()
	}
}
