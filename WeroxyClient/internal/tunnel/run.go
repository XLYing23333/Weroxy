// Package tunnel runs a WeroxyClient control connection and its data sessions.
package tunnel

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"weroxy/client/internal/buildinfo"
	"weroxy/client/internal/config"
	wp "weroxy/client/internal/protocol/weroxy"
	"weroxy/client/internal/secure"
	"weroxy/client/internal/status"
	"weroxy/client/internal/targetguard"
)

const (
	defaultMin      = time.Second
	defaultMax      = 30 * time.Second
	defaultPing     = 60 * time.Second
	defaultHand     = 15 * time.Second
	defaultIdle     = 180 * time.Second
	defaultAttempts = 2
	defaultPending  = 128
	defaultDrain    = 20 * time.Second
)

// ErrRejected means the server refused the credential or the protocol version.
// The client stops instead of trying the secret again.
var ErrRejected = errors.New("weroxy credential or version rejected")

// Options controls one foreground run. Token is the raw 32-byte secret.
type Options struct {
	Config       config.Config
	Token        []byte
	MinBackoff   time.Duration
	MaxBackoff   time.Duration
	PingEvery    time.Duration
	Handshake    time.Duration
	ReadIdle     time.Duration
	DataAttempts int
	MaxPending   int
	Drain        time.Duration
	StatusPath   string
	Dial         func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Run dials the server until ctx is cancelled or the credential is rejected.
func Run(ctx context.Context, opt Options) error {
	if len(opt.Token) != 32 {
		return errors.New("token 长度无效")
	}
	if opt.MinBackoff <= 0 {
		opt.MinBackoff = defaultMin
	}
	if opt.MaxBackoff < opt.MinBackoff {
		opt.MaxBackoff = defaultMax
	}
	if opt.PingEvery <= 0 {
		opt.PingEvery = defaultPing
	}
	if opt.Handshake <= 0 {
		opt.Handshake = defaultHand
	}
	if opt.ReadIdle <= 0 {
		opt.ReadIdle = defaultIdle
	}
	if opt.DataAttempts <= 0 {
		opt.DataAttempts = defaultAttempts
	}
	if opt.MaxPending <= 0 {
		opt.MaxPending = defaultPending
	}
	if opt.Drain <= 0 || opt.Drain > 5*time.Minute {
		opt.Drain = defaultDrain
	}
	r := &runner{
		opt:  opt,
		rng:  rand.New(rand.NewSource(time.Now().UnixNano())),
		live: map[net.Conn]struct{}{},
	}
	defer r.closeLive()
	if opt.StatusPath != "" {
		closeStatus, err := status.Listen(opt.StatusPath, r.snapshot)
		if err != nil {
			return err
		}
		defer closeStatus()
	}
	wait := opt.MinBackoff
	for {
		r.state.Store("connecting")
		established, err := r.once(ctx)
		r.state.Store(connectionState(err))
		if ctx.Err() != nil {
			r.state.Store("draining")
			r.drainLive(opt.Drain)
			return ctx.Err()
		}
		if errors.Is(err, ErrRejected) {
			return err
		}
		if established {
			wait = opt.MinBackoff
		}
		delay := wait + r.jitter(wait)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			r.state.Store("draining")
			r.drainLive(opt.Drain)
			return ctx.Err()
		case <-timer.C:
		}
		if !established && wait < opt.MaxBackoff {
			wait *= 2
			if wait > opt.MaxBackoff {
				wait = opt.MaxBackoff
			}
		}
	}
}

type runner struct {
	opt       Options
	rng       *rand.Rand
	mu        sync.Mutex
	live      map[net.Conn]struct{}
	state     atomic.Value
	connected atomic.Bool
	up        atomic.Uint64
	down      atomic.Uint64
}

func (r *runner) once(ctx context.Context) (bool, error) {
	conn, err := r.dial(ctx, "tcp", r.opt.Config.Server)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	rawControl := conn
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = rawControl.Close()
		case <-stop:
		}
	}()
	defer close(stop)

	_ = conn.SetDeadline(time.Now().Add(r.opt.Handshake))
	hello, _ := wp.PutStrings(buildinfo.Version)
	credential := secure.Derive(r.opt.Token, "control")
	encrypted, _, err := secure.Client(conn, 'C', credential.ID[:], credential.PSK, nil, hello)
	if err != nil {
		return false, err
	}
	conn = encrypted
	reader := wp.Reader{R: conn}
	auth, err := wp.PutStrings(r.opt.Config.DeviceID)
	if err != nil {
		return false, err
	}
	if err := writeFrame(conn, wp.Frame{Type: wp.TypeAuth, RequestID: 2, Body: auth}); err != nil {
		return false, err
	}
	var frame wp.Frame
	frame, err = reader.Next()
	if err != nil {
		return false, err
	}
	if frame.Type == wp.TypeError {
		return false, classify(frame.Body)
	}
	if frame.Type != wp.TypeSync {
		return false, errors.New("weroxy sync missing")
	}
	deviceUID := r.opt.Config.DeviceID
	generation := ""
	if parts, err := wp.Strings(frame.Body, 2); err == nil && parts[1] != "" {
		deviceUID = parts[1]
		generation = parts[0]
	}
	r.state.Store("connected")
	r.connected.Store(true)
	defer r.connected.Store(false)
	_ = conn.SetDeadline(time.Time{})

	send := make(chan wp.Frame, 16)
	done := make(chan struct{})
	pending := make(chan struct{}, r.opt.MaxPending)
	pendingCtx, cancelPending := context.WithCancel(ctx)
	defer cancelPending()
	var stopWrite sync.Once
	shutdown := func() {
		stopWrite.Do(func() { close(done) })
		_ = conn.Close()
	}
	go r.writeLoop(conn, send, done)
	go r.pingLoop(send, done)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(r.opt.ReadIdle))
		frame, err := reader.Next()
		if err != nil {
			shutdown()
			if ctx.Err() != nil {
				return true, ctx.Err()
			}
			return true, err
		}
		switch frame.Type {
		case wp.TypeOpen:
			select {
			case pending <- struct{}{}:
				go r.openData(pendingCtx, frame, send, done, deviceUID, generation, func() { <-pending })
			default:
				if parts, err := wp.Strings(frame.Body, 4); err == nil {
					body, _ := wp.PutStrings(parts[0], "busy")
					r.enqueue(send, done, wp.Frame{Type: wp.TypeCancel, RequestID: frame.RequestID, Body: body})
				}
			}
		case wp.TypePing:
			r.enqueue(send, done, wp.Frame{Type: wp.TypePong, RequestID: frame.RequestID})
		case wp.TypeError:
			if err := classify(frame.Body); errors.Is(err, ErrRejected) {
				shutdown()
				return true, err
			}
		}
	}
}

func dataDialAddress(control, advertised string) string {
	host, port, err := net.SplitHostPort(advertised)
	if err != nil {
		return advertised
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsUnspecified() {
		return advertised
	}
	controlHost, _, err := net.SplitHostPort(control)
	if err != nil || controlHost == "" {
		return advertised
	}
	return net.JoinHostPort(controlHost, port)
}

func (r *runner) openData(ctx context.Context, frame wp.Frame, send chan wp.Frame, done <-chan struct{}, deviceUID, generation string, release func()) {
	ctx, cancel := context.WithTimeout(ctx, r.opt.Handshake)
	defer cancel()
	var releaseOnce sync.Once
	releasePending := func() { releaseOnce.Do(release) }
	defer releasePending()
	parts, err := wp.Strings(frame.Body, 4)
	if err != nil {
		return
	}
	session, target, dataAddr, ticket := parts[0], parts[1], parts[2], parts[3]
	cancelHandshake := func() {
		body, _ := wp.PutStrings(session, "data_handshake")
		r.enqueue(send, done, wp.Frame{Type: wp.TypeCancel, RequestID: frame.RequestID, Body: body})
	}
	addresses, resolveErr := targetguard.Resolve(ctx, target, r.opt.Handshake)
	if resolveErr != nil {
		reason := "target_dial"
		if errors.Is(resolveErr, targetguard.ErrDenied) {
			reason = "target_denied"
		}
		body, _ := wp.PutStrings(session, reason)
		r.enqueue(send, done, wp.Frame{Type: wp.TypeCancel, RequestID: frame.RequestID, Body: body})
		return
	}
	// A wildcard listener address is valid inside the Server container but
	// cannot identify a remote endpoint. Published Data ports use the same
	// reachable host as Control; keep the original address in DATA_BIND.
	dialAddr := dataDialAddress(r.opt.Config.Server, dataAddr)
	var conn net.Conn
	for attempt := 0; attempt < r.opt.DataAttempts; attempt++ {
		if ctx.Err() != nil {
			err = ctx.Err()
			break
		}
		conn, err = r.dial(ctx, "tcp", dialAddr)
		if err == nil || attempt+1 == r.opt.DataAttempts {
			break
		}
		timer := time.NewTimer(r.opt.MinBackoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			err = ctx.Err()
		case <-timer.C:
		}
	}
	if err != nil || conn == nil {
		body, _ := wp.PutStrings(session, "data")
		r.enqueue(send, done, wp.Frame{Type: wp.TypeCancel, RequestID: frame.RequestID, Body: body})
		return
	}
	defer conn.Close()
	rawData := conn
	var bindMu sync.Mutex
	bound := false
	stopPending := context.AfterFunc(ctx, func() {
		bindMu.Lock()
		if !bound {
			_ = rawData.Close()
		}
		bindMu.Unlock()
	})
	defer stopPending()
	r.track(conn)
	defer r.untrack(conn)

	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	ticketRaw, err := hex.DecodeString(ticket)
	if err != nil {
		cancelHandshake()
		return
	}
	credential := secure.Derive(ticketRaw, "data")
	clear(ticketRaw)
	fields := []string{deviceUID, session, generation, dataAddr}
	encrypted, _, err := secure.Client(conn, 'D', []byte(session), credential.PSK, fields, nil)
	if err != nil {
		cancelHandshake()
		return
	}
	conn = encrypted
	targetConn, err := targetguard.DialResolved(ctx, addresses, r.opt.Handshake)
	if err != nil {
		cancel, _ := wp.PutStrings(session, "target_dial")
		r.enqueue(send, done, wp.Frame{Type: wp.TypeCancel, RequestID: frame.RequestID, Body: cancel})
		return
	}
	defer targetConn.Close()
	if writeFrame(conn, wp.Frame{Type: wp.TypeReady, RequestID: 2}) != nil {
		cancelHandshake()
		return
	}
	reader := wp.Reader{R: conn}
	next, err := reader.Next()
	if err != nil || next.Type != wp.TypeReady || len(next.Body) != 0 {
		cancelHandshake()
		return
	}
	conn, err = encrypted.Raw()
	if err != nil {
		cancelHandshake()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_ = targetConn.SetDeadline(time.Time{})
	bindMu.Lock()
	bound = true
	bindMu.Unlock()
	stopPending()
	releasePending()
	r.splice(targetConn, conn)
}

func (r *runner) writeLoop(conn net.Conn, send <-chan wp.Frame, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case frame := <-send:
			_ = conn.SetWriteDeadline(time.Now().Add(r.opt.Handshake))
			if writeFrame(conn, frame) != nil {
				_ = conn.Close()
				return
			}
		}
	}
}

func (r *runner) pingLoop(send chan wp.Frame, done <-chan struct{}) {
	ticker := time.NewTicker(r.opt.PingEvery)
	defer ticker.Stop()
	var id uint64 = 10
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			id++
			r.enqueue(send, done, wp.Frame{Type: wp.TypePing, RequestID: id})
		}
	}
}

func (r *runner) enqueue(send chan wp.Frame, done <-chan struct{}, frame wp.Frame) {
	select {
	case <-done:
	case send <- frame:
	default:
	}
}

func (r *runner) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if r.opt.Dial != nil {
		return r.opt.Dial(ctx, network, addr)
	}
	dialer := &net.Dialer{Timeout: r.opt.Handshake}
	return dialer.DialContext(ctx, network, addr)
}

func (r *runner) jitter(wait time.Duration) time.Duration {
	span := int64(wait / 2)
	if span <= 0 {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Duration(r.rng.Int63n(span))
}

func (r *runner) track(conn net.Conn) {
	r.mu.Lock()
	r.live[conn] = struct{}{}
	r.mu.Unlock()
}

func (r *runner) untrack(conn net.Conn) {
	r.mu.Lock()
	delete(r.live, conn)
	r.mu.Unlock()
}

// drainLive lets READY sessions finish naturally, then closes remaining data
// sockets at the deadline. The control connection is already closed by once.
func (r *runner) drainLive(limit time.Duration) {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		r.mu.Lock()
		remaining := len(r.live)
		r.mu.Unlock()
		if remaining == 0 {
			return
		}
		select {
		case <-deadline.C:
			r.closeLive()
			return
		case <-tick.C:
		}
	}
}

func (r *runner) closeLive() {
	r.mu.Lock()
	conns := make([]net.Conn, 0, len(r.live))
	for conn := range r.live {
		conns = append(conns, conn)
	}
	r.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func classify(body []byte) error {
	code, _, err := wp.ErrorBody(body)
	if err != nil {
		return err
	}
	if code == wp.CodeVersion || code == wp.CodeAuth || code == wp.CodeRevoked {
		return ErrRejected
	}
	return errors.New("weroxy error")
}

func writeFrame(conn net.Conn, frame wp.Frame) error {
	raw, err := wp.Encode(frame)
	if err != nil {
		return err
	}
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

func (r *runner) snapshot() status.Snapshot {
	state, _ := r.state.Load().(string)
	return status.Snapshot{State: status.SafeState(state), Connected: r.connected.Load(), Up: r.up.Load(), Down: r.down.Load()}
}

func (r *runner) splice(target, data net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyDir := func(dst, src net.Conn, add func(uint64)) {
		defer wg.Done()
		n, err := io.Copy(dst, &countReader{r: src, add: add})
		_ = n
		closeWrite(dst)
		if err != nil && !errors.Is(err, io.EOF) {
			_ = dst.Close()
			_ = src.Close()
		}
	}
	go copyDir(data, target, func(n uint64) { r.up.Add(n) })
	go copyDir(target, data, func(n uint64) { r.down.Add(n) })
	wg.Wait()
}

type countReader struct {
	r   io.Reader
	add func(uint64)
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 && c.add != nil {
		c.add(uint64(n))
	}
	return n, err
}

func closeWrite(conn net.Conn) {
	type halfCloser interface{ CloseWrite() error }
	if c, ok := conn.(halfCloser); ok {
		_ = c.CloseWrite()
	}
}

func connectionState(err error) string {
	if errors.Is(err, ErrRejected) {
		return "rejected"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns_failed"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "timeout"
	}
	return "reconnecting"
}
