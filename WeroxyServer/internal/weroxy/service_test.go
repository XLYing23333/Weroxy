package weroxy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"weroxy/server/internal/legacy"
	wp "weroxy/server/internal/protocol/weroxy"
	"weroxy/server/internal/secure"
)

func TestEchoSurvivesControlLossAndRevoke(t *testing.T) {
	secret := bytes32(1)
	token := bytes32(2)
	uid := hex.EncodeToString(bytes32(3)[:16])
	echo := echoServer(t)
	svc := New(Options{
		Handshake: 500 * time.Millisecond,
		TicketTTL: 5 * time.Second,
		Devices: []Device{{
			ID: 1, Name: "box", UID: uid, TokenMAC: legacy.MAC(secret, token), Credential: secure.Derive(token, "control"),
		}},
		Forwards: []Forward{{ID: 7, DeviceID: 1, Listen: "127.0.0.1:0", Target: echo}},
	})
	ctx := t.Context()
	controlAddr, dataAddr, forwards, err := svc.Start(ctx, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	control := dialTCP(t, controlAddr)
	defer control.Close()
	control = writeHello(t, control, token)
	frame := readFrame(t, control)
	if frame.Type != wp.TypeWelcome {
		t.Fatalf("type=%d", frame.Type)
	}
	parts, err := wp.Strings(frame.Body, 1)
	if err != nil || parts[0] == "1.0" {
		t.Fatalf("welcome=%v err=%v", parts, err)
	}
	writeAuth(t, control, uid, token)
	frame = readFrame(t, control)
	if frame.Type != wp.TypeSync {
		t.Fatalf("type=%d", frame.Type)
	}

	visitor := dialTCP(t, forwards[0])
	if _, err := visitor.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	frame = readFrame(t, control)
	if frame.Type != wp.TypeOpen {
		t.Fatalf("type=%d", frame.Type)
	}
	open, err := wp.Strings(frame.Body, 4)
	if err != nil {
		t.Fatal(err)
	}
	if open[1] != echo || open[2] != dataAddr {
		t.Fatalf("open=%v", open)
	}
	data := dialTCP(t, dataAddr)
	target := dialTCP(t, echo)
	defer target.Close()
	bind, _ := wp.PutStrings(open[3], uid, open[0], dataAddr)
	data = bindData(t, data, bind)
	if err := writeFrame(data, wp.Frame{Type: wp.TypeReady, RequestID: 2}); err != nil {
		t.Fatal(err)
	}
	ready := readFrame(t, data)
	if ready.Type != wp.TypeReady {
		t.Fatalf("type=%d", ready.Type)
	}
	_ = data.SetDeadline(time.Time{})
	_ = target.SetDeadline(time.Time{})
	_ = visitor.SetDeadline(time.Time{})
	go splice(target, data, nil, nil)
	if got := readN(t, visitor, 2); string(got) != "hi" {
		t.Fatalf("early=%q", got)
	}
	if _, err := visitor.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, visitor, 2); string(got) != "ab" {
		t.Fatalf("echo=%q", got)
	}

	time.Sleep(900 * time.Millisecond)
	if _, err := visitor.Write([]byte("cd")); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, visitor, 2); string(got) != "cd" {
		t.Fatalf("idle=%q", got)
	}

	_ = control.Close()
	if _, err := visitor.Write([]byte("ef")); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, visitor, 2); string(got) != "ef" {
		t.Fatalf("after control=%q", got)
	}

	svc.Revoke(uid)
	_ = visitor.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4)
	if _, err := visitor.Read(buf); err == nil {
		t.Fatal("visitor stayed open after revoke")
	}
}

func TestTicketReplayDeviceAndPort(t *testing.T) {
	secret := bytes32(4)
	token := bytes32(5)
	uid := hex.EncodeToString(bytes32(6)[:16])
	echo := echoServer(t)
	svc := New(Options{
		Handshake: 2 * time.Second,
		TicketTTL: 5 * time.Second,
		Devices:   []Device{{ID: 1, Name: "box", UID: uid, TokenMAC: legacy.MAC(secret, token), Credential: secure.Derive(token, "control")}},
		Forwards:  []Forward{{ID: 1, DeviceID: 1, Listen: "127.0.0.1:0", Target: echo}},
	})
	controlAddr, dataAddr, forwards, err := svc.Start(t.Context(), "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	control := dialTCP(t, controlAddr)
	defer control.Close()
	control = writeHello(t, control, token)
	_ = readFrame(t, control)
	writeAuth(t, control, uid, token)
	_ = readFrame(t, control)
	visitor := dialTCP(t, forwards[0])
	defer visitor.Close()
	openFrame := readFrame(t, control)
	open, err := wp.Strings(openFrame.Body, 4)
	if err != nil {
		t.Fatal(err)
	}

	data := dialTCP(t, dataAddr)
	defer data.Close()
	body, _ := wp.PutStrings(open[3], uid, open[0], dataAddr)
	data = bindData(t, data, body)
	if err := writeFrame(data, wp.Frame{Type: wp.TypeReady, RequestID: 2}); err != nil {
		t.Fatal(err)
	}
	if got := readFrame(t, data); got.Type != wp.TypeReady {
		t.Fatalf("type=%d", got.Type)
	}

	replay := dialTCP(t, dataAddr)
	defer replay.Close()
	rejectData(t, replay, body)

	deviceVisitor := dialTCP(t, forwards[0])
	defer deviceVisitor.Close()
	deviceOpen, err := wp.Strings(readFrame(t, control).Body, 4)
	if err != nil {
		t.Fatal(err)
	}
	wrongDevice := dialTCP(t, dataAddr)
	defer wrongDevice.Close()
	other := hex.EncodeToString(bytes32(9)[:16])
	badDevice, _ := wp.PutStrings(deviceOpen[3], other, deviceOpen[0], dataAddr)
	rejectData(t, wrongDevice, badDevice)

	portVisitor := dialTCP(t, forwards[0])
	defer portVisitor.Close()
	portOpen, err := wp.Strings(readFrame(t, control).Body, 4)
	if err != nil {
		t.Fatal(err)
	}
	wrongPort := dialTCP(t, dataAddr)
	defer wrongPort.Close()
	badPort, _ := wp.PutStrings(portOpen[3], uid, portOpen[0], "127.0.0.1:1")
	rejectData(t, wrongPort, badPort)
}

func TestTicketExpiryAndBusy(t *testing.T) {
	secret := bytes32(7)
	token := bytes32(8)
	uid := hex.EncodeToString(bytes32(9)[:16])
	echo := echoServer(t)
	svc := New(Options{
		Handshake: 2 * time.Second,
		TicketTTL: 80 * time.Millisecond,
		Devices:   []Device{{ID: 1, Name: "box", UID: uid, TokenMAC: legacy.MAC(secret, token), Credential: secure.Derive(token, "control")}},
		Forwards:  []Forward{{ID: 1, DeviceID: 1, Listen: "127.0.0.1:0", Target: echo}},
	})
	controlAddr, dataAddr, forwards, err := svc.Start(t.Context(), "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	control := dialTCP(t, controlAddr)
	defer control.Close()
	control = writeHello(t, control, token)
	_ = readFrame(t, control)
	writeAuth(t, control, uid, token)
	_ = readFrame(t, control)

	second := dialTCP(t, controlAddr)
	defer second.Close()
	second = writeHello(t, second, token)
	_ = readFrame(t, second)
	writeAuth(t, second, uid, token)
	if code := errorCode(t, second); code != wp.CodeBusy {
		t.Fatalf("busy=%d", code)
	}
	if err := writeFrame(control, wp.Frame{Type: wp.TypePing, RequestID: 9}); err != nil {
		t.Fatal(err)
	}
	if got := readFrame(t, control); got.Type != wp.TypePong || got.RequestID != 9 {
		t.Fatalf("pong type=%d id=%d", got.Type, got.RequestID)
	}

	visitor := dialTCP(t, forwards[0])
	defer visitor.Close()
	openFrame := readFrame(t, control)
	open, err := wp.Strings(openFrame.Body, 4)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	late := dialTCP(t, dataAddr)
	defer late.Close()
	body, _ := wp.PutStrings(open[3], uid, open[0], dataAddr)
	rejectData(t, late, body)
}

func TestOldControlCannotDropReplacement(t *testing.T) {
	secret := bytes32(10)
	token := bytes32(11)
	uid := hex.EncodeToString(bytes32(12)[:16])
	echo := echoServer(t)
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	svc := New(Options{
		Handshake: 2 * time.Second,
		TicketTTL: 5 * time.Second,
		Devices:   []Device{{ID: 1, Name: "box", UID: uid, TokenMAC: legacy.MAC(secret, token), Credential: secure.Derive(token, "control")}},
		Forwards:  []Forward{{ID: 1, DeviceID: 1, Listen: "127.0.0.1:0", Target: echo}},
		OnRetire: func(uint64) {
			once.Do(func() {
				close(started)
				<-release
			})
		},
	})
	controlAddr, dataAddr, forwards, err := svc.Start(t.Context(), "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	first := dialTCP(t, controlAddr)
	first = writeHello(t, first, token)
	_ = readFrame(t, first)
	writeAuth(t, first, uid, token)
	_ = readFrame(t, first)
	visitor, data := bindEcho(t, first, "", dataAddr, forwards[0], echo, uid)
	if _, err := visitor.Write([]byte("aa")); err != nil {
		t.Fatal(err)
	}
	if string(readN(t, visitor, 2)) != "aa" {
		t.Fatal("first echo")
	}
	_ = first.Close()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("retire did not start")
	}
	second := dialTCP(t, controlAddr)
	defer second.Close()
	second = writeHello(t, second, token)
	_ = readFrame(t, second)
	writeAuth(t, second, uid, token)
	if got := readFrame(t, second); got.Type != wp.TypeSync {
		t.Fatalf("replacement type=%d", got.Type)
	}
	if _, err := visitor.Write([]byte("bb")); err != nil {
		t.Fatal(err)
	}
	if string(readN(t, visitor, 2)) != "bb" {
		t.Fatal("echo during retire")
	}
	close(release)
	if _, err := visitor.Write([]byte("cc")); err != nil {
		t.Fatal(err)
	}
	if string(readN(t, visitor, 2)) != "cc" {
		t.Fatal("echo after replacement")
	}
	_ = data.Close()
	nextVisitor := dialTCP(t, forwards[0])
	defer nextVisitor.Close()
	if got := readFrame(t, second); got.Type != wp.TypeOpen {
		t.Fatalf("new open type=%d", got.Type)
	}
}

func TestRevokePollClosesReadySession(t *testing.T) {
	secret := bytes32(13)
	token := bytes32(14)
	uid := hex.EncodeToString(bytes32(15)[:16])
	echo := echoServer(t)
	var mu sync.Mutex
	revoked := false
	svc := New(Options{
		Handshake:   2 * time.Second,
		TicketTTL:   5 * time.Second,
		RevokeEvery: 30 * time.Millisecond,
		Revoked: func() ([]string, error) {
			mu.Lock()
			defer mu.Unlock()
			if !revoked {
				return nil, nil
			}
			return []string{uid}, nil
		},
		Devices:  []Device{{ID: 1, Name: "box", UID: uid, TokenMAC: legacy.MAC(secret, token), Credential: secure.Derive(token, "control")}},
		Forwards: []Forward{{ID: 1, DeviceID: 1, Listen: "127.0.0.1:0", Target: echo}},
	})
	controlAddr, dataAddr, forwards, err := svc.Start(t.Context(), "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	control := dialTCP(t, controlAddr)
	defer control.Close()
	control = writeHello(t, control, token)
	_ = readFrame(t, control)
	writeAuth(t, control, uid, token)
	_ = readFrame(t, control)
	visitor, _ := bindEcho(t, control, "", dataAddr, forwards[0], echo, uid)
	mu.Lock()
	revoked = true
	mu.Unlock()
	_ = visitor.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4)
	if _, err := visitor.Read(buf); err == nil {
		t.Fatal("poll did not close the visitor")
	}
}

func TestBadVersionReturnsError(t *testing.T) {
	svc := New(Options{Handshake: time.Second})
	controlAddr, _, _, err := svc.Start(t.Context(), "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn := dialTCP(t, controlAddr)
	defer conn.Close()
	raw, err := wp.Encode(wp.Frame{Type: wp.TypeHello, RequestID: 1})
	if err != nil {
		t.Fatal(err)
	}
	raw[4] = 9
	if _, err := conn.Write(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := (wp.Reader{R: conn}).Next(); err == nil {
		t.Fatal("old protocol accepted")
	}
}

func bindEcho(t *testing.T, control net.Conn, dir, dataAddr, forward, echo, uid string) (net.Conn, net.Conn) {
	t.Helper()
	visitor := dialTCP(t, forward)
	if _, err := visitor.Write([]byte("zz")); err != nil {
		t.Fatal(err)
	}
	frame := readFrame(t, control)
	open, err := wp.Strings(frame.Body, 4)
	if err != nil || frame.Type != wp.TypeOpen {
		t.Fatalf("type=%d err=%v", frame.Type, err)
	}
	data := dialTCP(t, dataAddr)
	target := dialTCP(t, echo)
	body, _ := wp.PutStrings(open[3], uid, open[0], dataAddr)
	data = bindData(t, data, body)
	if err := writeFrame(data, wp.Frame{Type: wp.TypeReady, RequestID: 2}); err != nil {
		t.Fatal(err)
	}
	if got := readFrame(t, data); got.Type != wp.TypeReady {
		t.Fatalf("ready type=%d", got.Type)
	}
	_ = data.SetDeadline(time.Time{})
	_ = target.SetDeadline(time.Time{})
	_ = visitor.SetDeadline(time.Time{})
	go splice(target, data, nil, nil)
	if string(readN(t, visitor, 2)) != "zz" {
		t.Fatal("bind echo")
	}
	return visitor, data
}

func dialTCP(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
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
	}()
	return ln.Addr().String()
}

// Welcome is carried in the actual Noise response, not an extra roundtrip.
func writeHello(t *testing.T, conn net.Conn, token []byte) net.Conn {
	t.Helper()
	credential := secure.Derive(token, "control")
	encrypted, welcome, err := secure.Client(conn, 'C', credential.ID[:], credential.PSK, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := wp.Encode(wp.Frame{Type: wp.TypeWelcome, Body: welcome})
	return &testControl{Conn: encrypted, prefix: bytes.NewReader(encoded)}
}

func writeAuth(t *testing.T, conn net.Conn, uid string, token []byte) {
	t.Helper()
	body, err := wp.PutStrings(uid)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(conn, wp.Frame{Type: wp.TypeAuth, RequestID: 2, Body: body}); err != nil {
		t.Fatal(err)
	}
}

func readFrame(t *testing.T, conn net.Conn) wp.Frame {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := (wp.Reader{R: conn}).Next()
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := conn.(*testControl); ok {
		if frame.Type == wp.TypeSync {
			parts, _ := wp.Strings(frame.Body, 2)
			if len(parts) == 2 {
				c.generation = parts[0]
			}
		}
		if frame.Type == wp.TypeOpen {
			parts, _ := wp.Strings(frame.Body, 4)
			if len(parts) == 4 {
				testGenerations.Store(parts[3], c.generation)
			}
		}
	}
	if c, ok := conn.(*testData); ok && frame.Type == wp.TypeReady {
		raw, err := c.encrypted.Raw()
		if err != nil {
			t.Fatal(err)
		}
		c.Conn = raw
	}
	return frame
}

func errorCode(t *testing.T, conn net.Conn) byte {
	t.Helper()
	frame := readFrame(t, conn)
	if frame.Type != wp.TypeError {
		t.Fatalf("type=%d", frame.Type)
	}
	code, _, err := wp.ErrorBody(frame.Body)
	if err != nil {
		t.Fatal(err)
	}
	return code
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

func bytes32(fill byte) []byte {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = fill
	}
	return buf
}

func TestNoControlRejectsVisitor(t *testing.T) {
	svc := New(Options{
		Devices:  []Device{{ID: 1, Name: "box", UID: "aa", TokenMAC: bytes32(2)}},
		Forwards: []Forward{{ID: 1, DeviceID: 1, Listen: "127.0.0.1:0", Target: "127.0.0.1:9"}},
	})
	_, _, forwards, err := svc.Start(t.Context(), "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn := dialTCP(t, forwards[0])
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("visitor accepted without a control connection")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("visitor was left open")
	}
}

func TestLocallyClosedSpliceReleasesQuietPeer(t *testing.T) {
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

		done := make(chan struct{})
		go func() { splice(a, b, nil, nil); close(done) }()
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

func TestUnexpectedAuthenticatedHelloReleasesControl(t *testing.T) {
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
	secret, token := bytes32(1), bytes32(2)
	uid := hex.EncodeToString(bytes32(3)[:16])
	svc := New(Options{Devices: []Device{{ID: 1, Name: "box", UID: uid, TokenMAC: legacy.MAC(secret, token), Credential: secure.Derive(token, "control")}}, Handshake: time.Second})
	for i := 0; i < 100; i++ {
		server, client := net.Pipe()
		if !svc.admit(server) {
			t.Fatal("admission leaked")
		}
		done := make(chan struct{})
		go func() { svc.serveControl(server); close(done) }()
		client = writeHello(t, client, token)
		readFrame(t, client)
		writeAuth(t, client, uid, token)
		readFrame(t, client)
		svc.mu.Lock()
		ctrl := svc.controls[1]
		svc.mu.Unlock()
		_ = writeFrame(client, wp.Frame{Type: wp.TypeHello})
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("unexpected frame retained control")
		}
		select {
		case <-ctrl.done:
		default:
			t.Fatal("control worker was not retired")
		}
		client.Close()
		svc.mu.Lock()
		retained := len(svc.controls) + svc.unauth
		svc.mu.Unlock()
		if retained != 0 {
			t.Fatalf("retained=%d", retained)
		}
	}
}

func TestUnauthenticatedHelloCannotExtendBudget(t *testing.T) {
	svc := New(Options{Handshake: 80 * time.Millisecond})
	server, client := net.Pipe()
	defer client.Close()
	svc.admit(server)
	done := make(chan struct{})
	go func() { svc.serveControl(server); close(done) }()
	go func() {
		for {
			if writeFrame(client, wp.Frame{Type: wp.TypeHello}) != nil {
				return
			}
			if _, err := (wp.Reader{R: client}).Next(); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	select {
	case <-done:
	case <-time.After(400 * time.Millisecond):
		t.Fatal("HELLO flood extended authentication indefinitely")
	}
}
