package legacy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"weroxy/server/internal/logging"
	lp "weroxy/server/internal/protocol/legacy"
)

func TestReadIdleBaseline(t *testing.T) {
	if ReadIdle != 180*time.Second {
		t.Fatalf("idle=%s", ReadIdle)
	}
	if MaxIdleDataPerDevice != 100 {
		t.Fatalf("idle data cap=%d", MaxIdleDataPerDevice)
	}
	if lp.TransferChunk != 32*1024 {
		t.Fatalf("chunk=%d", lp.TransferChunk)
	}
}

func TestIdleDataPoolDoesNotRequireAuth(t *testing.T) {
	secret, key := testSecret(t)
	control, forward, _ := startService(t, Options{
		Secret:      secret,
		Devices:     []Device{{ID: 1, Name: "box", KeyMAC: MAC(secret, []byte(key))}},
		Forwards:    []Forward{{DeviceID: 1, Listen: "127.0.0.1:0", Target: "127.0.0.1:9"}},
		Idle:        5 * time.Second,
		PendingTTL:  2 * time.Second,
		MaxIdleData: 1,
	})
	client := dial(t, control)
	frames := readFrames(client)
	mustWrite(t, client, lp.Frame{Type: lp.TypeAuth, URI: key})
	mustWrite(t, client, lp.Frame{Type: lp.TypeHeartbeat})
	waitType(t, frames, lp.TypeHeartbeat)

	visitor := dial(t, forward)
	connect := waitType(t, frames, lp.TypeConnect)
	kept := dial(t, control)
	mustWrite(t, kept, lp.Frame{Type: lp.TypeConnect, URI: connect.URI + "@" + key})
	mustWrite(t, kept, lp.Frame{Type: lp.TypeDisconnect, URI: connect.URI})
	visitor.Close()
	mustWrite(t, kept, lp.Frame{Type: lp.TypeHeartbeat})
	if beat := mustRead(t, kept); beat.Type != lp.TypeHeartbeat {
		t.Fatal("idle data connection was closed or asked to AUTH")
	}

	extraVisitor := dial(t, forward)
	extraConnect := waitType(t, frames, lp.TypeConnect)
	extra := dial(t, control)
	mustWrite(t, extra, lp.Frame{Type: lp.TypeConnect, URI: extraConnect.URI + "@" + key})
	mustWrite(t, extra, lp.Frame{Type: lp.TypeDisconnect, URI: extraConnect.URI})
	extraVisitor.Close()
	if !closedWithin(extra, time.Second) {
		t.Fatal("idle data connection above the cap stayed open")
	}

	again := dial(t, forward)
	next := waitType(t, frames, lp.TypeConnect)
	mustWrite(t, kept, lp.Frame{Type: lp.TypeConnect, URI: next.URI + "@" + key})
	mustWrite(t, kept, lp.Frame{Type: lp.TypeTransfer, URI: "", Data: []byte("pool")})
	_ = again.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(again, buf); err != nil || string(buf) != "pool" {
		t.Fatalf("reused idle connection without AUTH: %q %v", buf, err)
	}
}

func TestEchoChunksAndEmptyURI(t *testing.T) {
	echoAddr := startEcho(t)
	secret, key := testSecret(t)
	control, forward, _ := startService(t, Options{
		Secret:     secret,
		Devices:    []Device{{ID: 1, Name: "box", KeyMAC: MAC(secret, []byte(key))}},
		Forwards:   []Forward{{DeviceID: 1, Listen: "127.0.0.1:0", Target: echoAddr}},
		Idle:       5 * time.Second,
		PendingTTL: 2 * time.Second,
	})
	client := dial(t, control)
	frames := readFrames(client)
	mustWrite(t, client, lp.Frame{Type: lp.TypeAuth, URI: key})
	mustWrite(t, client, lp.Frame{Type: lp.TypeHeartbeat})
	if beat := waitType(t, frames, lp.TypeHeartbeat); beat.Type != lp.TypeHeartbeat {
		t.Fatal("auth did not stay up")
	}
	visitor := dial(t, forward)
	connect := waitType(t, frames, lp.TypeConnect)
	if string(connect.Data) != echoAddr || connect.URI == "" {
		t.Fatalf("connect uri=%q data=%q", connect.URI, connect.Data)
	}
	data := dial(t, control)
	real := dial(t, echoAddr)
	mustWrite(t, data, lp.Frame{Type: lp.TypeConnect, URI: connect.URI + "@" + key})
	got := bridgeEcho(t, data, real)
	payload := bytes.Repeat([]byte("A"), 40*1024)
	go func() { _, _ = visitor.Write(payload) }()
	_ = visitor.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(visitor, reply); err != nil || !bytes.Equal(reply, payload) {
		t.Fatalf("echo err=%v", err)
	}
	framesN, maxN := got()
	if framesN < 2 || maxN > lp.TransferChunk {
		t.Fatalf("frames=%d max=%d", framesN, maxN)
	}
}

func TestDuplicateLoginBindAndIdle(t *testing.T) {
	dir := t.TempDir()
	log := logging.New(logging.Options{Dir: filepath.Join(dir, "logs")})
	t.Cleanup(func() { _ = log.Close() })
	secret, key := testSecret(t)
	control, forward, _ := startService(t, Options{
		Secret:     secret,
		Devices:    []Device{{ID: 7, Name: "box", KeyMAC: MAC(secret, []byte(key))}},
		Forwards:   []Forward{{DeviceID: 7, Listen: "127.0.0.1:0", Target: "127.0.0.1:9"}},
		Log:        log,
		Idle:       time.Second,
		PendingTTL: 30 * time.Second,
		MaxUnauth:  32,
		MaxPending: 1,
	})
	first := dial(t, control)
	mustWrite(t, first, lp.Frame{Type: lp.TypeAuth, URI: key})
	mustWrite(t, first, lp.Frame{Type: lp.TypeHeartbeat})
	if beat := mustRead(t, first); beat.Type != lp.TypeHeartbeat {
		t.Fatalf("heartbeat type=%d", beat.Type)
	}
	second := dial(t, control)
	mustWrite(t, second, lp.Frame{Type: lp.TypeAuth, URI: key})
	if !closedWithin(second, time.Second) {
		t.Fatal("duplicate login replaced or stayed open")
	}
	mustWrite(t, first, lp.Frame{Type: lp.TypeWriteControl})
	mustWrite(t, first, lp.Frame{Type: lp.TypeHeartbeat})
	if got := mustRead(t, first); got.Type != lp.TypeHeartbeat {
		t.Fatalf("heartbeat after write-control type=%d", got.Type)
	}
	stopBeat := heartbeat(first, 200*time.Millisecond)
	defer stopBeat()

	unknown := dial(t, control)
	mustWrite(t, unknown, lp.Frame{Type: lp.TypeAuth, URI: "other-key-0123456789"})
	if !closedWithin(unknown, time.Second) {
		t.Fatal("unknown key stayed open")
	}

	frames := readFrames(first)
	visitor := dial(t, forward)
	connect := waitType(t, frames, lp.TypeConnect)
	held := dial(t, forward)
	if !closedWithin(held, time.Second) {
		t.Fatal("pending limit left the extra visitor open")
	}
	rejected := dial(t, control)
	mustWrite(t, rejected, lp.Frame{Type: lp.TypeConnect, URI: connect.URI + "@wrong-key-0123456789"})
	if !closedWithin(rejected, time.Second) {
		t.Fatal("bad bind stayed open")
	}
	again := dial(t, control)
	mustWrite(t, again, lp.Frame{Type: lp.TypeConnect, URI: "missing@ " + key})
	if !closedWithin(again, time.Second) {
		t.Fatal("malformed bind stayed open")
	}
	data := dial(t, control)
	mustWrite(t, data, lp.Frame{Type: lp.TypeConnect, URI: connect.URI + "@" + key})
	mustWrite(t, data, lp.Frame{Type: lp.TypeTransfer, URI: "", Data: []byte("x")})
	_ = visitor.SetReadDeadline(time.Now().Add(time.Second))
	var marked [1]byte
	if _, err := io.ReadFull(visitor, marked[:]); err != nil || marked[0] != 'x' {
		t.Fatalf("first bind marker=%q err=%v", marked, err)
	}
	other := dial(t, control)
	mustWrite(t, other, lp.Frame{Type: lp.TypeConnect, URI: connect.URI + "@" + key})
	if !closedWithin(other, time.Second) {
		t.Fatal("duplicate bind stayed open")
	}
	time.Sleep(1500 * time.Millisecond)
	mustWrite(t, data, lp.Frame{Type: lp.TypeTransfer, URI: "", Data: []byte("still")})
	_ = visitor.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(visitor, buf); err != nil || string(buf) != "still" {
		t.Fatalf("bound session did not survive idle: %q %v", buf, err)
	}

	idle := dial(t, control)
	if !closedWithin(idle, 3*time.Second) {
		t.Fatal("unauthenticated connection survived idle")
	}
	body := readLog(t, filepath.Join(dir, "logs"))
	if strings.Contains(body, key) || strings.Contains(body, "other-key-0123456789") {
		t.Fatal("client key written to log")
	}
}

func TestClosePathsAndPoolReuse(t *testing.T) {
	secret, key := testSecret(t)
	control, forward, stop := startService(t, Options{
		Secret:     secret,
		Devices:    []Device{{ID: 1, Name: "box", KeyMAC: MAC(secret, []byte(key))}},
		Forwards:   []Forward{{DeviceID: 1, Listen: "127.0.0.1:0", Target: "127.0.0.1:9"}},
		Idle:       time.Second,
		PendingTTL: time.Second,
	})
	client := dial(t, control)
	frames := readFrames(client)
	mustWrite(t, client, lp.Frame{Type: lp.TypeAuth, URI: key})
	mustWrite(t, client, lp.Frame{Type: lp.TypeHeartbeat})
	waitType(t, frames, lp.TypeHeartbeat)

	t.Run("target refused", func(t *testing.T) {
		visitor := dial(t, forward)
		connect := waitType(t, frames, lp.TypeConnect)
		mustWrite(t, client, lp.Frame{Type: lp.TypeDisconnect, URI: connect.URI})
		if !closedWithin(visitor, time.Second) {
			t.Fatal("visitor stayed open after target refusal")
		}
	})

	t.Run("visitor closes", func(t *testing.T) {
		visitor := dial(t, forward)
		connect := waitType(t, frames, lp.TypeConnect)
		data := dial(t, control)
		mustWrite(t, data, lp.Frame{Type: lp.TypeConnect, URI: connect.URI + "@" + key})
		visitor.Close()
		disc := mustRead(t, data)
		if disc.Type != lp.TypeDisconnect || disc.URI != connect.URI {
			t.Fatalf("disconnect %+v", disc)
		}
		mustWrite(t, data, lp.Frame{Type: lp.TypeTransfer, Data: []byte("leak")})
		nextVisitor := dial(t, forward)
		next := waitType(t, frames, lp.TypeConnect)
		mustWrite(t, data, lp.Frame{Type: lp.TypeConnect, URI: next.URI + "@" + key})
		mustWrite(t, data, lp.Frame{Type: lp.TypeTransfer, URI: "", Data: []byte("fresh")})
		_ = nextVisitor.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 5)
		if _, err := io.ReadFull(nextVisitor, buf); err != nil || string(buf) != "fresh" {
			t.Fatalf("reused connection delivered %q err=%v", buf, err)
		}
		nextVisitor.Close()
		_ = mustRead(t, data)
	})

	t.Run("client and target close", func(t *testing.T) {
		visitor := dial(t, forward)
		connect := waitType(t, frames, lp.TypeConnect)
		data := dial(t, control)
		mustWrite(t, data, lp.Frame{Type: lp.TypeConnect, URI: connect.URI + "@" + key})
		mustWrite(t, data, lp.Frame{Type: lp.TypeDisconnect, URI: connect.URI})
		if !closedWithin(visitor, time.Second) {
			t.Fatal("visitor stayed open after client disconnect")
		}

		immediate := dial(t, forward)
		immediateConnect := waitType(t, frames, lp.TypeConnect)
		immediateData := dial(t, control)
		mustWrite(t, immediateData, lp.Frame{Type: lp.TypeConnect, URI: immediateConnect.URI + "@" + key})
		mustWrite(t, immediateData, lp.Frame{Type: lp.TypeDisconnect, URI: immediateConnect.URI})
		if !closedWithin(immediate, time.Second) {
			t.Fatal("visitor stayed open after immediate target close")
		}

		bothVisitor := dial(t, forward)
		bothConnect := waitType(t, frames, lp.TypeConnect)
		bothData := dial(t, control)
		mustWrite(t, bothData, lp.Frame{Type: lp.TypeConnect, URI: bothConnect.URI + "@" + key})
		raw, err := lp.EncodeClient(lp.Frame{Type: lp.TypeDisconnect, URI: bothConnect.URI})
		if err != nil {
			t.Fatal(err)
		}
		go bothVisitor.Close()
		go func() { _, _ = bothData.Write(raw) }()
		if !closedWithin(bothVisitor, time.Second) {
			t.Fatal("visitor stayed open after both sides closed")
		}
	})

	stop()
	expiredControl, expiredForward, _ := startService(t, Options{
		Secret:     secret,
		Devices:    []Device{{ID: 1, Name: "box", KeyMAC: MAC(secret, []byte(key))}},
		Forwards:   []Forward{{DeviceID: 1, Listen: "127.0.0.1:0", Target: "127.0.0.1:9"}},
		PendingTTL: 200 * time.Millisecond,
	})
	expiredClient := dial(t, expiredControl)
	expiredFrames := readFrames(expiredClient)
	mustWrite(t, expiredClient, lp.Frame{Type: lp.TypeAuth, URI: key})
	mustWrite(t, expiredClient, lp.Frame{Type: lp.TypeHeartbeat})
	waitType(t, expiredFrames, lp.TypeHeartbeat)
	_ = dial(t, expiredForward)
	connect := waitType(t, expiredFrames, lp.TypeConnect)
	time.Sleep(400 * time.Millisecond)
	late := dial(t, expiredControl)
	mustWrite(t, late, lp.Frame{Type: lp.TypeConnect, URI: connect.URI + "@" + key})
	if !closedWithin(late, time.Second) {
		t.Fatal("expired session accepted a bind")
	}
}

func TestOldRetireKeepsReplacement(t *testing.T) {
	secret, key := testSecret(t)
	left, right := net.Pipe()
	t.Cleanup(func() { left.Close(); right.Close() })
	nextLeft, nextRight := net.Pipe()
	t.Cleanup(func() { nextLeft.Close(); nextRight.Close() })
	svc := New(Options{Secret: secret, Devices: []Device{{ID: 1, Name: "box", KeyMAC: MAC(secret, []byte(key))}}})
	first := svc.claim(svc.devices[0], right)
	first.closed.Store(true)
	second := svc.claim(svc.devices[0], nextRight)
	if second == nil || second == first {
		t.Fatal("replacement was not registered")
	}
	svc.detach(first)
	svc.mu.Lock()
	current := svc.controls[1]
	svc.mu.Unlock()
	if current != second || second.closed.Load() {
		t.Fatal("old control cleanup removed the replacement")
	}
	second.closed.Store(true)
	close(first.done)
	close(second.done)
}

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func startService(t *testing.T, opt Options) (string, string, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	svc := New(opt)
	control, forwards, err := svc.Start(ctx, "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	if len(forwards) == 0 {
		t.Fatal("no forward")
	}
	return control, forwards[0], cancel
}

func testSecret(t *testing.T) ([]byte, string) {
	t.Helper()
	return bytes.Repeat([]byte{9}, 32), "temp-key-0123456789abcdef"
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func mustWrite(t *testing.T, conn net.Conn, frame lp.Frame) {
	t.Helper()
	raw, err := lp.EncodeClient(frame)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(raw); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, conn net.Conn) lp.Frame {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := (lp.Reader{R: conn}).Next()
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func readFrames(conn net.Conn) <-chan lp.Frame {
	out := make(chan lp.Frame, 32)
	go func() {
		defer close(out)
		reader := lp.Reader{R: conn}
		for {
			frame, err := reader.Next()
			if err != nil {
				return
			}
			out <- frame
		}
	}()
	return out
}

func waitType(t *testing.T, frames <-chan lp.Frame, kind byte) lp.Frame {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case frame, ok := <-frames:
			if !ok {
				t.Fatal("control closed")
			}
			if frame.Type == kind {
				return frame
			}
		case <-timer.C:
			t.Fatal("timed out waiting for frame")
		}
	}
}

func bridgeEcho(t *testing.T, data, real net.Conn) func() (frames, max int) {
	t.Helper()
	var mu sync.Mutex
	var frames, max int
	go func() {
		buf := make([]byte, 8*1024)
		for {
			n, err := real.Read(buf)
			if n > 0 {
				raw, encErr := lp.EncodeClient(lp.Frame{Type: lp.TypeTransfer, Data: append([]byte(nil), buf[:n]...)})
				if encErr == nil {
					_, _ = data.Write(raw)
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		reader := lp.Reader{R: data}
		for {
			frame, err := reader.Next()
			if err != nil {
				return
			}
			if frame.Type != lp.TypeTransfer {
				continue
			}
			mu.Lock()
			frames++
			if len(frame.Data) > max {
				max = len(frame.Data)
			}
			mu.Unlock()
			if _, err := real.Write(frame.Data); err != nil {
				return
			}
		}
	}()
	return func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		return frames, max
	}
}

func heartbeat(conn net.Conn, every time.Duration) func() {
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		raw, _ := lp.EncodeClient(lp.Frame{Type: lp.TypeHeartbeat})
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_, _ = conn.Write(raw)
			}
		}
	}()
	return func() { close(stop) }
}

func closedWithin(conn net.Conn, wait time.Duration) bool {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	var buf [1]byte
	_, err := conn.Read(buf[:])
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	return true
}

func readLog(t *testing.T, dir string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, "weroxy.log"))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestWildcardReloadAddsLegacyForward(t *testing.T) {
	secret, key := testSecret(t)
	svc := New(Options{Secret: secret,
		Devices:  []Device{{ID: 1, Name: "box", KeyMAC: MAC(secret, []byte(key))}},
		Forwards: []Forward{{ID: 1, DeviceID: 1, Listen: "0.0.0.0:0", Target: "127.0.0.1:9"}}})
	_, bound, err := svc.Start(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(bound[0])
	old := svc.listeners[1]
	desired := []Forward{
		{ID: 1, DeviceID: 1, Listen: net.JoinHostPort("0.0.0.0", port), Target: "127.0.0.1:9"},
		{ID: 2, DeviceID: 1, Listen: "0.0.0.0:0", Target: "127.0.0.1:9"},
	}
	if err := svc.ReconcileForwards(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	if svc.listeners[1] != old || svc.listeners[2] == nil {
		t.Fatal("listeners not retained/added")
	}
}

func TestUnexpectedAuthenticatedFrameReleasesControl(t *testing.T) {
	baseline := runtime.NumGoroutine()
	defer func() {
		until := time.Now().Add(time.Second)
		for runtime.NumGoroutine() > baseline+2 && time.Now().Before(until) {
			time.Sleep(time.Millisecond)
		}
		remaining := runtime.NumGoroutine()
		t.Logf("100 cycles: goroutines before=%d after=%d", baseline, remaining)
		if remaining > baseline+2 {
			t.Fatalf("workers retained after churn: before=%d after=%d", baseline, remaining)
		}
	}()
	secret, key := testSecret(t)
	svc := New(Options{Secret: secret, Devices: []Device{{ID: 1, Name: "box", KeyMAC: MAC(secret, []byte(key))}}})
	for i := 0; i < 100; i++ {
		server, client := net.Pipe()
		if !svc.admit(server) {
			t.Fatal("admission leaked")
		}
		done := make(chan struct{})
		go func() { svc.serveConn(server); close(done) }()
		mustWrite(t, client, lp.Frame{Type: lp.TypeAuth, URI: key})
		mustWrite(t, client, lp.Frame{Type: lp.TypeHeartbeat})
		mustRead(t, client)
		svc.mu.Lock()
		ctrl := svc.controls[1]
		svc.mu.Unlock()
		mustWrite(t, client, lp.Frame{Type: lp.TypeAuth, URI: key})
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("duplicate AUTH retained control")
		}
		select {
		case <-ctrl.done:
		default:
			t.Fatal("writer not retired")
		}
		client.Close()
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if len(svc.controls) != 0 || svc.unauth != 0 {
		t.Fatal("retained controls or admission")
	}
}

func TestRevokeClosesDataWithoutWaitingForWriterLock(t *testing.T) {
	svc := New(Options{})
	server, client := net.Pipe()
	defer client.Close()
	sess := &session{id: "busy", deviceID: 1, data: &side{conn: server}, ready: make(chan struct{})}
	sess.data.mu.Lock()
	done := make(chan struct{})
	go func() { svc.finish(sess, "control"); close(done) }()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		sess.data.mu.Unlock()
		t.Fatal("retire blocked behind data writer")
	}
	sess.data.mu.Unlock()
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked data remained open")
	}
}

func TestIdlePoolChurnDoesNotRetainDeviceIDs(t *testing.T) {
	svc := New(Options{})
	for id := int64(1); id <= 10000; id++ {
		server, client := net.Pipe()
		if !svc.park(server, id) {
			t.Fatal("pool admission rejected")
		}
		svc.unpark(server)
		svc.unpark(server)
		server.Close()
		client.Close()
	}
	if len(svc.idleCount) != 0 || len(svc.idleConns) != 0 || svc.idleTotal != 0 {
		t.Fatal("empty idle pool retained device entries")
	}
}
