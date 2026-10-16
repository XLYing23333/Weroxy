package tunnel

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"weroxy/client/internal/config"
	wp "weroxy/client/internal/protocol/weroxy"
	"weroxy/client/internal/secure"
	"weroxy/client/internal/targetguard"
)

func TestCredentialFailureDoesNotRetry(t *testing.T) {
	ln := listenTCP(t)
	var accepts atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				selector, err := secure.ReadPreface(conn, 'C')
				if err != nil {
					return
				}
				cred := secure.Derive(bytes32(1), "control")
				encrypted, _, err := secure.Server(conn, 'C', selector, cred.PSK, nil, nil)
				if err != nil {
					return
				}
				conn = encrypted
				reader := wp.Reader{R: conn}
				frame, err := reader.Next()
				if err != nil {
					return
				}
				errBody, _ := wp.PutError(wp.CodeAuth, "")
				_ = writeFrame(conn, wp.Frame{Type: wp.TypeError, RequestID: frame.RequestID, Body: errBody})
			}(conn)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := Run(ctx, Options{
		Config:     testConfig(ln.Addr().String()),
		Token:      bytes32(1),
		MinBackoff: 20 * time.Millisecond,
		MaxBackoff: 40 * time.Millisecond,
		Handshake:  time.Second,
		PingEvery:  time.Hour,
	})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err=%v accepts=%d", err, accepts.Load())
	}
	if accepts.Load() != 1 {
		t.Fatalf("accepts=%d", accepts.Load())
	}
}

func TestNetworkBackoffRetries(t *testing.T) {
	var dials atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := Run(ctx, Options{
		Config:     testConfig("127.0.0.1:9"),
		Token:      bytes32(2),
		MinBackoff: 20 * time.Millisecond,
		MaxBackoff: 50 * time.Millisecond,
		Handshake:  time.Second,
		PingEvery:  time.Hour,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("down")
		},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
	if dials.Load() < 2 || dials.Load() > 20 {
		t.Fatalf("dials=%d", dials.Load())
	}
}

func TestDataDialIsLimited(t *testing.T) {
	controlLn := listenTCP(t)
	var dataDials atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = Run(ctx, Options{
			Config:       testConfig(controlLn.Addr().String()),
			Token:        bytes32(4),
			Handshake:    time.Second,
			PingEvery:    time.Hour,
			MinBackoff:   10 * time.Millisecond,
			DataAttempts: 2,
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr == "127.0.0.1:1" {
					dataDials.Add(1)
					return nil, errors.New("down")
				}
				dialer := &net.Dialer{Timeout: time.Second}
				return dialer.DialContext(ctx, network, addr)
			},
		})
	}()
	conn, err := controlLn.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn = finishControl(t, conn, bytes32(4))
	body, _ := wp.PutStrings("1", "127.0.0.1:9", "127.0.0.1:1", "bb")
	if err := writeFrame(conn, wp.Frame{Type: wp.TypeOpen, RequestID: 5, Body: body}); err != nil {
		t.Fatal(err)
	}
	frame := readFrame(t, conn)
	if frame.Type != wp.TypeCancel {
		t.Fatalf("type=%d", frame.Type)
	}
	if dataDials.Load() != 2 {
		t.Fatalf("dials=%d", dataDials.Load())
	}
}

func TestDataSurvivesControlDrop(t *testing.T) {
	controlLn := listenTCP(t)
	dataLn := listenTCP(t)
	echo := listenEcho(t)
	go serveEcho(echo)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = Run(ctx, Options{
			Config:     testConfig(controlLn.Addr().String()),
			Token:      bytes32(5),
			Handshake:  500 * time.Millisecond,
			PingEvery:  time.Hour,
			ReadIdle:   time.Hour,
			MinBackoff: time.Hour,
		})
	}()
	control, err := controlLn.Accept()
	if err != nil {
		t.Fatal(err)
	}
	control = finishControl(t, control, bytes32(5))
	body, _ := wp.PutStrings("7", echo.Addr().String(), dataLn.Addr().String(), strings.Repeat("cc", 32))
	if err := writeFrame(control, wp.Frame{Type: wp.TypeOpen, RequestID: 6, Body: body}); err != nil {
		t.Fatal(err)
	}
	data, err := dataLn.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	selector, err := secure.ReadPreface(data, 'D')
	if err != nil {
		t.Fatal(err)
	}
	ticket, _ := hex.DecodeString(strings.Repeat("cc", 32))
	cred := secure.Derive(ticket, "data")
	encrypted, _, err := secure.Server(data, 'D', selector, cred.PSK, []string{"device", "7", "1", dataLn.Addr().String()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data = encrypted
	if got := readFrame(t, data); got.Type != wp.TypeReady {
		t.Fatalf("type=%d", got.Type)
	}
	if err := writeFrame(data, wp.Frame{Type: wp.TypeReady, RequestID: 2}); err != nil {
		t.Fatal(err)
	}
	data, err = encrypted.Raw()
	if err != nil {
		t.Fatal(err)
	}
	_ = data.SetDeadline(time.Time{})
	if _, err := data.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if string(readN(t, data, 4)) != "ping" {
		t.Fatal("echo")
	}
	_ = control.Close()
	// A setup budget never expires an already READY byte stream.
	time.Sleep(650 * time.Millisecond)
	if _, err := data.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if string(readN(t, data, 4)) != "pong" {
		t.Fatal("after control")
	}
}

func testConfig(server string) config.Config {
	return config.Config{Server: server, DeviceID: "device"}
}

func finishControl(t *testing.T, conn net.Conn, token []byte) net.Conn {
	t.Helper()
	selector, err := secure.ReadPreface(conn, 'C')
	if err != nil {
		t.Fatal(err)
	}
	cred := secure.Derive(token, "control")
	encrypted, _, err := secure.Server(conn, 'C', selector, cred.PSK, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn = encrypted
	frame := readFrame(t, conn)
	if frame.Type != wp.TypeAuth {
		t.Fatal(frame.Type)
	}
	body, _ := wp.PutStrings("1", "device")
	if err := writeFrame(conn, wp.Frame{Type: wp.TypeSync, Body: body}); err != nil {
		t.Fatal(err)
	}
	return conn
}

func readFrame(t *testing.T, conn net.Conn) wp.Frame {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := (wp.Reader{R: conn}).Next()
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func readN(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	return buf
}

func listenEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func serveEcho(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}(conn)
	}
}

func countAccepts(ln net.Listener, n *atomic.Int32) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		n.Add(1)
		_ = conn.Close()
	}
}

func listenTCP(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func bytes32(fill byte) []byte {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = fill
	}
	return buf
}

func TestServerSelectedTargetsNeedNoLocalGrant(t *testing.T) {
	for _, target := range []string{"127.0.0.1:22", "192.0.2.1:80", "[::1]:3000"} {
		if !targetguard.ValidTarget(target) {
			t.Fatal("valid Server target rejected")
		}
	}
	if targetguard.ValidTarget("invalid") {
		t.Fatal("invalid target accepted")
	}
}

func TestDataDialAddressForWildcardListener(t *testing.T) {
	cases := []struct {
		control, advertised, want string
	}{
		{"px.example:29999", "0.0.0.0:29100", "px.example:29100"},
		{"[2001:db8::1]:29999", "[::]:29101", "[2001:db8::1]:29101"},
		{"px.example:29999", "192.0.2.4:29100", "192.0.2.4:29100"},
		{"invalid", "0.0.0.0:29100", "0.0.0.0:29100"},
	}
	for _, tc := range cases {
		if got := dataDialAddress(tc.control, tc.advertised); got != tc.want {
			t.Errorf("control=%q advertised=%q got=%q want=%q", tc.control, tc.advertised, got, tc.want)
		}
	}
}

// Dial, retry delay and READY wait share one budget; expiry reports the fault.
func TestDataTotalBudgetReportsFault(t *testing.T) {
	echo := listenEcho(t)
	go serveEcho(echo)
	send := make(chan wp.Frame, 4)
	done := make(chan struct{})
	var released atomic.Int32
	r := &runner{live: make(map[net.Conn]struct{}), opt: Options{Config: testConfig("127.0.0.1:1"), Handshake: 200 * time.Millisecond, DataAttempts: 2, MinBackoff: 100 * time.Millisecond, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}}
	body, _ := wp.PutStrings("7", echo.Addr().String(), "127.0.0.1:1", strings.Repeat("cc", 32))
	start := time.Now()
	r.openData(t.Context(), wp.Frame{Type: wp.TypeOpen, RequestID: 9, Body: body}, send, done, "device", "1", func() { released.Add(1) })
	if elapsed := time.Since(start); elapsed > 400*time.Millisecond || elapsed < 150*time.Millisecond {
		t.Fatal(elapsed)
	}
	select {
	case frame := <-send:
		parts, e := wp.Strings(frame.Body, 2)
		if e != nil || frame.Type != wp.TypeCancel || parts[1] != "data" {
			t.Fatal(frame, e)
		}
	default:
		t.Fatal("fault not reported")
	}
	if released.Load() != 1 {
		t.Fatal("pending slot leaked")
	}
}

func TestDataReadyUsesRemainingBudget(t *testing.T) {
	echo := listenEcho(t)
	go serveEcho(echo)
	peer, local := net.Pipe()
	defer peer.Close()
	send := make(chan wp.Frame, 4)
	done := make(chan struct{})
	r := &runner{live: make(map[net.Conn]struct{}), opt: Options{Config: testConfig("127.0.0.1:1"), Handshake: 400 * time.Millisecond, DataAttempts: 1, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		select {
		case <-time.After(250 * time.Millisecond):
			return local, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}}
	go func() {
		selector, err := secure.ReadPreface(peer, 'D')
		if err != nil {
			return
		}
		ticket, _ := hex.DecodeString(strings.Repeat("cc", 32))
		cred := secure.Derive(ticket, "data")
		c, _, err := secure.Server(peer, 'D', selector, cred.PSK, []string{"device", "7", "1", "127.0.0.1:1"}, nil)
		if err != nil {
			return
		}
		_, _ = (wp.Reader{R: c}).Next() /* stall READY acknowledgement */
	}()
	body, _ := wp.PutStrings("7", echo.Addr().String(), "127.0.0.1:1", strings.Repeat("cc", 32))
	start := time.Now()
	r.openData(t.Context(), wp.Frame{Body: body}, send, done, "device", "1", func() {})
	if elapsed := time.Since(start); elapsed > 550*time.Millisecond || elapsed < 350*time.Millisecond {
		t.Fatal(elapsed)
	}
	select {
	case frame := <-send:
		parts, e := wp.Strings(frame.Body, 2)
		if e != nil || parts[1] != "data_handshake" {
			t.Fatal(frame, e)
		}
	default:
		t.Fatal("READY timeout not reported")
	}
}

func TestLocallyClosedSpliceReleasesQuietPeer(t *testing.T) {
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pair := func() (net.Conn, net.Conn) {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		a, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		return a, c
	}
	for i := 0; i < 100; i++ {
		a, peerA := pair()
		b, peerB := pair()
		r := &runner{}
		done := make(chan struct{})
		go func() { r.splice(a, b); close(done) }()
		a.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("splice retained a worker after local close")
		}
		b.Close()
		peerA.Close()
		peerB.Close()
	}
}
