// Package legacy accepts original Lanproxy clients on one fixed TCP port.
package legacy

import (
	"context"
	"crypto/hmac"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"weroxy/server/internal/logging"
	"weroxy/server/internal/metrics"
	"weroxy/server/internal/policy"
	lp "weroxy/server/internal/protocol/legacy"
)

const (
	// ReadIdle is the original Java read-idle baseline for control connections
	// and data connections that are not carrying a business session.
	ReadIdle = 180 * time.Second
	// PendingTTL is how long a visitor may wait for a data bind.
	PendingTTL = 30 * time.Second

	defaultMaxUnauth    = 64
	defaultUnauthPerIP  = 32
	defaultMaxPending   = 128
	defaultMaxIdleTotal = 256
	defaultWriteQueue   = 16
	// MaxIdleDataPerDevice matches the Java and Go client pool size.
	// An idle data connection is one returned after a session. It binds with
	// CONNECT and is not required to send AUTH.
	MaxIdleDataPerDevice = 100
)

// Device is an in-memory legacy client. KeyMAC is not the Client Key.
type Device struct {
	ID     int64
	Name   string
	KeyMAC []byte
	Paused bool
}

// Forward is one visitor listener and the target sent in CONNECT.
type Forward struct {
	ID       int64
	DeviceID int64
	Listen   string
	Target   string
}

// Options configures one legacy runtime. Zero limits use the defaults.
type Options struct {
	Secret         []byte
	Devices        []Device
	Forwards       []Forward
	Log            *logging.Logger
	Idle           time.Duration
	PendingTTL     time.Duration
	MaxUnauth      int
	MaxUnauthPerIP int
	MaxPending     int
	// MaxIdleTotal caps parked Legacy data sockets across all devices.
	// Active business data sockets do not consume this budget.
	MaxIdleTotal int
	MaxIdleData  int
	WriteQueue   int
	Count        *metrics.Counters
	Admit        *policy.Admission
	Rules        *policy.Table
}

// Service is the fixed legacy entry and its forward listeners.
type Service struct {
	beforeMetricOpen func()
	secret           []byte
	devices          []Device
	forwards         []Forward
	log              *logging.Logger
	idle             time.Duration
	pendingTTL       time.Duration
	maxUnauth        int
	maxUnauthPerIP   int
	maxPending       int
	maxIdleTotal     int
	maxIdleData      int
	writeQueue       int
	draining         atomic.Bool
	count            *metrics.Counters
	admission        *policy.Admission
	rules            *policy.Table

	mu            sync.Mutex
	reconcileMu   sync.Mutex
	ctx           context.Context
	entries       map[string]string
	listeners     map[int64]net.Listener
	listenerStops map[int64]func() bool
	controls      map[int64]*control
	pending       map[string]*session
	active        map[string]*session
	unauth        int
	unauthByIP    map[string]int
	idleTotal     int
	userSeq       uint64
	idleConns     map[net.Conn]int64
	idleCount     map[int64]int
}

type control struct {
	deviceID   int64
	generation uint64
	conn       net.Conn
	send       chan lp.Frame
	done       chan struct{}
	closed     atomic.Bool
}

type session struct {
	id         string
	deviceID   int64
	generation uint64
	visitor    net.Conn
	data       *side
	created    time.Time
	bound      bool
	exemptIdle bool
	finished   atomic.Bool
	ready      chan struct{}
	readyOnce  sync.Once
	forwardID  int64
	grant      *policy.Grant
}

type side struct {
	conn net.Conn
	mu   sync.Mutex
}

type tracked struct {
	unauth bool
	ip     string
}

// New copies devices into the process cache. Packet forwarding does not touch SQLite.
func New(opt Options) *Service {
	if opt.Idle <= 0 {
		opt.Idle = ReadIdle
	}
	if opt.PendingTTL <= 0 {
		opt.PendingTTL = PendingTTL
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
	if opt.MaxIdleTotal <= 0 {
		opt.MaxIdleTotal = defaultMaxIdleTotal
	}
	if opt.WriteQueue <= 0 {
		opt.WriteQueue = defaultWriteQueue
	}
	if opt.MaxIdleData <= 0 {
		opt.MaxIdleData = MaxIdleDataPerDevice
	}
	devices := make([]Device, len(opt.Devices))
	for i, device := range opt.Devices {
		devices[i] = device
		devices[i].KeyMAC = append([]byte(nil), device.KeyMAC...)
	}
	return &Service{
		secret:         append([]byte(nil), opt.Secret...),
		devices:        devices,
		forwards:       append([]Forward(nil), opt.Forwards...),
		log:            opt.Log,
		count:          opt.Count,
		admission:      opt.Admit,
		rules:          opt.Rules,
		idle:           opt.Idle,
		pendingTTL:     opt.PendingTTL,
		maxUnauth:      opt.MaxUnauth,
		maxUnauthPerIP: opt.MaxUnauthPerIP,
		maxPending:     opt.MaxPending,
		maxIdleTotal:   opt.MaxIdleTotal,
		maxIdleData:    opt.MaxIdleData,
		writeQueue:     opt.WriteQueue,
		controls:       map[int64]*control{},
		listeners:      map[int64]net.Listener{},
		listenerStops:  map[int64]func() bool{},
		pending:        map[string]*session{},
		active:         map[string]*session{},
		idleConns:      map[net.Conn]int64{},
		idleCount:      map[int64]int{},
		unauthByIP:     map[string]int{},
	}
}

// Start listens on the control address and on each forward.
// It returns the bound control address and the forward addresses in order.
func (s *Service) Start(ctx context.Context, controlAddr string) (string, []string, error) {
	plainAddr := controlAddr
	for _, forward := range s.forwards {
		if s.device(forward.DeviceID) == nil {
			return "", nil, errors.New("legacy forward has no device")
		}
	}
	if plainAddr == "" {
		return "", nil, errors.New("legacy entrance is required")
	}
	var control []net.Listener
	closeAll := func(listeners []net.Listener) {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}
	if plainAddr != "" {
		ln, err := net.Listen("tcp", plainAddr)
		if err != nil {
			return "", nil, err
		}
		control = append(control, ln)
	}
	var listeners []net.Listener
	var bound []string
	for i := range s.forwards {
		ln, err := net.Listen("tcp", s.forwards[i].Listen)
		if err != nil {
			closeAll(control)
			closeAll(listeners)
			return "", nil, err
		}
		s.forwards[i].Listen = ln.Addr().String()
		bound = append(bound, ln.Addr().String())
		listeners = append(listeners, ln)
	}
	go func() {
		<-ctx.Done()
		closeAll(control)
		closeAll(listeners)
	}()
	for _, ln := range control {
		go s.acceptControl(ln)
	}
	s.mu.Lock()
	s.ctx = ctx
	s.entries = make(map[string]string)
	if plainAddr != "" {
		s.entries["legacy"] = control[0].Addr().String()
	}
	for i, ln := range listeners {
		s.listeners[s.forwards[i].ID] = ln
	}
	s.mu.Unlock()
	for i, ln := range listeners {
		go s.acceptForward(ln, s.forwards[i].ID)
	}
	s.info("legacy listener started", map[string]string{"entrances": strconv.Itoa(len(control))})
	return control[0].Addr().String(), bound, nil
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
		go s.serveConn(conn)
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
		for _, item := range s.forwards {
			if item.ID == forwardID {
				forward = item
				break
			}
		}
		current := s.listeners[forwardID] == ln && forward.Listen == ln.Addr().String()
		s.mu.Unlock()
		if !current {
			_ = conn.Close()
			continue
		}
		s.onVisitor(forward, conn)
	}
}

func (s *Service) admit(conn net.Conn) bool {
	ip := legacySourceIP(conn)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining.Load() || s.unauth >= s.maxUnauth || s.unauthByIP[ip] >= s.maxUnauthPerIP {
		return false
	}
	s.unauth++
	s.unauthByIP[ip]++
	return true
}

func legacySourceIP(conn net.Conn) string {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP.String()
	}
	return conn.RemoteAddr().String()
}

func (s *Service) releaseUnauthLocked(ip string) {
	if s.unauth > 0 {
		s.unauth--
	}
	if s.unauthByIP[ip] > 1 {
		s.unauthByIP[ip]--
	} else {
		delete(s.unauthByIP, ip)
	}
}

func (s *Service) promote(conn *tracked) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if conn.unauth {
		s.releaseUnauthLocked(conn.ip)
		conn.unauth = false
	}
}

func (s *Service) release(conn *tracked) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if conn.unauth {
		s.releaseUnauthLocked(conn.ip)
		conn.unauth = false
	}
}

func (s *Service) serveConn(conn net.Conn) {
	state := &tracked{unauth: true, ip: legacySourceIP(conn)}
	defer s.unpark(conn)
	defer s.release(state)
	defer conn.Close()
	reader := lp.Reader{R: conn}
	var ctrl *control
	var bound *session
	defer func() {
		s.retire(ctrl)
		if bound != nil {
			s.finish(bound, "client")
		}
	}()
	authDeadline := time.Now().Add(s.idle)
	link := &side{conn: conn}
	for {
		if state.unauth {
			_ = conn.SetReadDeadline(authDeadline)
		} else {
			s.armIdle(conn, bound)
		}
		frame, err := reader.Next()
		if err != nil {
			if ctrl != nil {
				s.retire(ctrl)
			}
			if bound != nil {
				s.finish(bound, "client")
			}
			return
		}
		switch frame.Type {
		case lp.TypeHeartbeat:
			reply := lp.Frame{Type: lp.TypeHeartbeat}
			if ctrl != nil {
				s.enqueue(ctrl, reply)
			} else if err := link.write(reply); err != nil {
				return
			}
		case lp.TypeAuth:
			if ctrl != nil || bound != nil {
				return
			}
			device, ok := s.match(frame.URI)
			if !ok {
				s.info("legacy auth rejected", map[string]string{"reason": "unknown"})
				return
			}
			next := s.claim(device, conn)
			if next == nil {
				s.info("legacy auth rejected", map[string]string{"device": device.Name, "reason": "control already healthy"})
				return
			}
			ctrl = next
			s.promote(state)
			s.info("legacy control attached", map[string]string{"device": device.Name})
		case lp.TypeConnect:
			if ctrl != nil {
				return
			}
			if bound != nil && !bound.finished.Load() {
				s.info("legacy bind rejected", map[string]string{"reason": "connection already bound"})
				return
			}
			next, err := s.bind(frame.URI, link)
			if err != nil {
				s.info("legacy bind rejected", map[string]string{"reason": "rejected"})
				return
			}
			bound = next
			if s.count != nil {
				_, rawPort, splitErr := net.SplitHostPort(link.conn.LocalAddr().String())
				if splitErr == nil {
					port, _ := strconv.Atoi(rawPort)
					s.count.SetRoute(metrics.Legacy, next.id, "", port)
				}
			}
			s.promote(state)
			go s.pumpVisitor(next)
		case lp.TypeDisconnect:
			if ctrl != nil {
				s.finishID(ctrl, frame.URI, "client")
				continue
			}
			if bound != nil {
				deviceID := bound.deviceID
				s.finish(bound, "pool")
				bound = nil
				if !s.park(conn, deviceID) {
					return
				}
			}
		case lp.TypeTransfer:
			if bound == nil || bound.finished.Load() {
				bound = nil
				continue
			}
			n, err := writeCount(bound.visitor, frame.Data)
			if n > 0 && s.count != nil {
				s.count.Add(metrics.Legacy, bound.id, metrics.Up, n)
			}
			if err != nil {
				s.finish(bound, "visitor")
				bound = nil
			}
		case lp.TypeWriteControl:
		default:
		}
	}
}

func (s *Service) armIdle(conn net.Conn, bound *session) {
	if bound != nil && bound.exemptIdle && !bound.finished.Load() {
		_ = conn.SetReadDeadline(time.Time{})
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(s.idle))
}

func (s *Service) onVisitor(forward Forward, conn net.Conn) {
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	s.mu.Lock()
	ctrl := s.controls[forward.DeviceID]
	deviceName := ""
	paused := false
	for _, device := range s.devices {
		if device.ID == forward.DeviceID {
			deviceName, paused = device.Name, device.Paused
			break
		}
	}
	if s.draining.Load() || ctrl == nil || ctrl.closed.Load() || len(s.pending) >= s.maxPending || deviceName == "" || paused {
		s.mu.Unlock()
		conn.Close()
		return
	}
	s.mu.Unlock()
	var grant *policy.Grant
	if s.admission != nil && s.rules != nil {
		rule := s.rules.Effective(deviceName, deviceName+"|"+forward.Listen)
		var reason string
		grant, reason = s.admission.Acquire(net.ParseIP(host), deviceName, deviceName+"|"+forward.Listen, rule)
		if grant == nil {
			if s.count != nil {
				s.count.Reject(reason)
			}
			conn.Close()
			return
		}
	}
	s.mu.Lock()
	ctrl = s.controls[forward.DeviceID]
	allowed := false
	for _, device := range s.devices {
		if device.ID == forward.DeviceID && !device.Paused {
			allowed = true
			break
		}
	}
	if s.draining.Load() || ctrl == nil || ctrl.closed.Load() || len(s.pending) >= s.maxPending || !allowed {
		s.mu.Unlock()
		if grant != nil {
			grant.Release()
		}
		conn.Close()
		return
	}
	s.userSeq++
	sess := &session{
		id:         strconv.FormatUint(s.userSeq, 10),
		deviceID:   forward.DeviceID,
		generation: ctrl.generation,
		visitor:    conn,
		created:    time.Now(),
		ready:      make(chan struct{}),
		forwardID:  forward.ID,
		grant:      grant,
	}
	s.pending[sess.id] = sess
	s.active[sess.id] = sess
	s.mu.Unlock()
	if s.beforeMetricOpen != nil {
		s.beforeMetricOpen()
	}
	if s.count != nil {
		s.count.Open(metrics.Legacy, sess.id, forward.DeviceID, forward.ID)
		s.count.Annotate(metrics.Legacy, sess.id, deviceName, host, "")
		s.count.SetRoute(metrics.Legacy, sess.id, forward.Listen, 0)
	}
	if sess.finished.Load() {
		if s.count != nil {
			s.count.CloseWithReason(metrics.Legacy, sess.id, "closed")
		}
		return
	}
	if !s.enqueue(ctrl, lp.Frame{Type: lp.TypeConnect, URI: sess.id, Data: []byte(forward.Target)}) {
		s.finish(sess, "timeout")
		return
	}
	timer := time.NewTimer(s.pendingTTL)
	go func() {
		select {
		case <-timer.C:
			s.expire(sess)
		case <-sess.ready:
			timer.Stop()
		}
	}()
}

func (s *Service) claim(device Device, conn net.Conn) *control {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining.Load() {
		return nil
	}
	if current := s.controls[device.ID]; current != nil && !current.closed.Load() {
		return nil
	}
	s.userSeq++
	generation := s.userSeq
	next := &control{
		deviceID:   device.ID,
		generation: generation,
		conn:       conn,
		send:       make(chan lp.Frame, s.writeQueue),
		done:       make(chan struct{}),
	}
	s.controls[device.ID] = next
	go s.writeLoop(next)
	return next
}

func (s *Service) writeLoop(ctrl *control) {
	for {
		select {
		case <-ctrl.done:
			return
		case frame := <-ctrl.send:
			if err := writeClient(ctrl.conn, frame); err != nil {
				go s.retire(ctrl)
				return
			}
		}
	}
}

func (s *Service) enqueue(ctrl *control, frame lp.Frame) bool {
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
	s.detach(ctrl)
	s.mu.Lock()
	var drop []*session
	for _, sess := range s.active {
		if sess.deviceID == ctrl.deviceID && sess.generation == ctrl.generation {
			drop = append(drop, sess)
		}
	}
	s.mu.Unlock()
	for _, sess := range drop {
		s.finish(sess, "control")
	}
}

func (s *Service) detach(ctrl *control) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.controls[ctrl.deviceID] == ctrl {
		delete(s.controls, ctrl.deviceID)
	}
}

func (s *Service) bind(uri string, link *side) (*session, error) {
	userID, key, ok := splitBind(uri)
	if !ok {
		return nil, errors.New("bind rejected")
	}
	device, ok := s.match(key)
	if !ok {
		return nil, errors.New("bind rejected")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining.Load() {
		return nil, errors.New("bind rejected")
	}
	sess := s.pending[userID]
	if sess == nil || sess.deviceID != device.ID || sess.bound || sess.finished.Load() {
		return nil, errors.New("bind rejected")
	}
	if time.Since(sess.created) > s.pendingTTL {
		return nil, errors.New("bind rejected")
	}
	ctrl := s.controls[device.ID]
	if ctrl == nil || ctrl.closed.Load() || ctrl.generation != sess.generation {
		return nil, errors.New("bind rejected")
	}
	sess.bound = true
	if sess.grant != nil {
		sess.grant.Activate()
	}
	sess.data = link
	sess.exemptIdle = true
	delete(s.pending, userID)
	s.unparkLocked(link.conn)
	_ = link.conn.SetReadDeadline(time.Time{})
	sess.signal()
	return sess, nil
}

func (s *Service) expire(sess *session) {
	s.mu.Lock()
	if sess.bound || sess.finished.Load() {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.finish(sess, "timeout")
}

func (s *Service) finishID(ctrl *control, userID, who string) {
	s.mu.Lock()
	sess := s.active[userID]
	if sess == nil || sess.deviceID != ctrl.deviceID || sess.generation != ctrl.generation {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.finish(sess, who)
}

func (s *Service) finish(sess *session, who string) {
	if sess == nil || !sess.finished.CompareAndSwap(false, true) {
		return
	}
	sess.signal()
	if sess.grant != nil {
		sess.grant.Release()
	}
	s.mu.Lock()
	if s.pending[sess.id] == sess {
		delete(s.pending, sess.id)
	}
	if s.active[sess.id] == sess {
		delete(s.active, sess.id)
	}
	s.mu.Unlock()
	if sess.data != nil && who == "visitor" {
		sess.data.mu.Lock()
		err := writeClient(sess.data.conn, lp.Frame{Type: lp.TypeDisconnect, URI: sess.id})
		_ = sess.data.conn.SetReadDeadline(time.Now().Add(s.idle))
		sess.exemptIdle = false
		dataConn := sess.data.conn
		sess.data.mu.Unlock()
		if err != nil || !s.park(dataConn, sess.deviceID) {
			_ = dataConn.Close()
		}
	}
	if sess.data != nil && (who == "client" || who == "control" || who == "shutdown_pending" || who == "shutdown_drain_timeout") {
		_ = sess.data.conn.Close()
	}
	if sess.visitor != nil {
		_ = sess.visitor.Close()
	}
	if s.count != nil {
		s.count.CloseWithReason(metrics.Legacy, sess.id, who)
	}
}

func (s *Service) pumpVisitor(sess *session) {
	buf := make([]byte, lp.TransferChunk)
	for {
		n, err := sess.visitor.Read(buf)
		if n > 0 {
			payload := append([]byte(nil), buf[:n]...)
			sess.data.mu.Lock()
			if sess.finished.Load() {
				sess.data.mu.Unlock()
				return
			}
			writeErr := writeClient(sess.data.conn, lp.Frame{Type: lp.TypeTransfer, URI: sess.id, Data: payload})
			sess.data.mu.Unlock()
			if writeErr == nil && s.count != nil {
				s.count.Add(metrics.Legacy, sess.id, metrics.Down, len(payload))
			}
			if writeErr != nil {
				s.finish(sess, "client")
				return
			}
		}
		if err != nil {
			s.finish(sess, "visitor")
			return
		}
	}
}

func (sess *session) signal() {
	sess.readyOnce.Do(func() { close(sess.ready) })
}

func (s *Service) park(conn net.Conn, deviceID int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining.Load() {
		return false
	}
	if _, ok := s.idleConns[conn]; ok {
		return true
	}
	if s.idleCount[deviceID] >= s.maxIdleData || s.idleTotal >= s.maxIdleTotal {
		return false
	}
	s.idleConns[conn] = deviceID
	s.idleCount[deviceID]++
	s.idleTotal++
	return true
}

func (s *Service) unpark(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unparkLocked(conn)
}

// Caller holds mu. Binding and connection cleanup release the same parked
// registration exactly once, including the global socket budget.
func (s *Service) unparkLocked(conn net.Conn) {
	deviceID, ok := s.idleConns[conn]
	if !ok {
		return
	}
	delete(s.idleConns, conn)
	if s.idleCount[deviceID] > 0 {
		s.idleCount[deviceID]--
		if s.idleCount[deviceID] == 0 {
			delete(s.idleCount, deviceID)
		}
	}
	if s.idleTotal > 0 {
		s.idleTotal--
	}
}

func (s *Service) match(clientKey string) (Device, bool) {
	mac := MAC(s.secret, []byte(clientKey))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, device := range s.devices {
		if !device.Paused && hmac.Equal(mac, device.KeyMAC) {
			return device, true
		}
	}
	return Device{}, false
}

func (s *Service) device(id int64) *Device {
	for i := range s.devices {
		if s.devices[i].ID == id {
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

func splitBind(uri string) (userID, clientKey string, ok bool) {
	at := -1
	for i := 0; i < len(uri); i++ {
		if uri[i] == '@' {
			if at >= 0 {
				return "", "", false
			}
			at = i
		}
	}
	if at <= 0 || at == len(uri)-1 {
		return "", "", false
	}
	return uri[:at], uri[at+1:], true
}

func (sd *side) write(frame lp.Frame) error {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	return writeClient(sd.conn, frame)
}

func writeClient(conn net.Conn, frame lp.Frame) error {
	raw, err := lp.EncodeClient(frame)
	if err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return writeAll(conn, raw)
}

func writeAll(conn io.Writer, raw []byte) error {
	_, err := writeCount(conn, raw)
	return err
}

func writeCount(conn io.Writer, raw []byte) (int, error) {
	written := 0
	for len(raw) > 0 {
		n, err := conn.Write(raw)
		written += n
		raw = raw[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

// EntryAddresses returns the bound ordinary entrance, including ephemeral ports.
func (s *Service) EntryAddresses() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.entries))
	for role, address := range s.entries {
		out[role] = address
	}
	return out
}

func (s *Service) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.draining.Load() && s.ctx != nil && s.ctx.Err() == nil
}
