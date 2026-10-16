package weroxy

import (
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
	"weroxy/server/internal/legacy"
	"weroxy/server/internal/metrics"
	wp "weroxy/server/internal/protocol/weroxy"
	"weroxy/server/internal/secure"
)

func TestFinishedBeforeMetricOpenCannotLeaveActiveCounters(t *testing.T) {
	count := metrics.New()
	forward := Forward{ID: 1, DeviceID: 1, Listen: "127.0.0.1:29000", Target: "127.0.0.1:22", Enabled: true}
	svc := New(Options{Count: count, Devices: []Device{{ID: 1, Name: "review", UID: "uid"}}, Forwards: []Forward{forward}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	svc.forwardLns[1] = ln
	svc.dataAddr = "127.0.0.1:29100"
	for i := 0; i < 5000; i++ {
		server, peer := net.Pipe()
		visitor, visitorPeer := net.Pipe()
		ctrl := &control{deviceID: 1, generation: uint64(i + 1), conn: server, send: make(chan wp.Frame, 16), done: make(chan struct{})}
		svc.controls[1] = ctrl
		svc.beforeMetricOpen = func() { svc.retire(ctrl) }
		svc.onVisitor(forward, visitor)
		svc.retire(ctrl)
		peer.Close()
		visitorPeer.Close()
	}
	if len(svc.sessions)+svc.pending != 0 {
		t.Fatal("runtime sessions retained")
	}
	snapshot := count.Snapshot()
	for _, entry := range snapshot.Sessions {
		if entry.Active {
			t.Fatal("active ghost metric retained")
		}
	}
	if len(snapshot.Sessions) > 1024 {
		t.Fatalf("closed detail budget exceeded: %d", len(snapshot.Sessions))
	}
	t.Logf("5000 forced interleavings: active=0, closed=%d", len(snapshot.Sessions))
}

func TestSplicePreservesResponseAfterRequestHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pair := func() (*net.TCPConn, *net.TCPConn) {
		peer, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		server, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		return server.(*net.TCPConn), peer.(*net.TCPConn)
	}
	left, visitor := pair()
	right, target := pair()
	defer visitor.Close()
	defer target.Close()
	defer left.Close()
	defer right.Close()
	visitor.SetDeadline(time.Now().Add(time.Second))
	target.SetDeadline(time.Now().Add(time.Second))
	done := make(chan struct{})
	go func() { splice(left, right, nil, nil); close(done) }()
	visitor.Write([]byte("request"))
	visitor.CloseWrite()
	request, err := io.ReadAll(target)
	if err != nil || string(request) != "request" {
		t.Fatal("request half-close failed")
	}
	target.Write([]byte("response"))
	target.CloseWrite()
	response, err := io.ReadAll(visitor)
	if err != nil || string(response) != "response" {
		t.Fatal("response dropped after half-close")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("splice not released")
	}
}

func TestRealTCPReconnectsReleaseSessionCounters(t *testing.T) {
	secret, token := bytes32(1), bytes32(2)
	uid := hex.EncodeToString(bytes32(3)[:16])
	count := metrics.New()
	echo := echoServer(t)
	svc := New(Options{Count: count, Devices: []Device{{ID: 1, Name: "tcp", UID: uid, TokenMAC: legacy.MAC(secret, token), Credential: secure.Derive(token, "control")}}, Forwards: []Forward{{ID: 1, DeviceID: 1, Listen: "127.0.0.1:0", Target: echo}}})
	controlAddr, dataAddr, forwards, err := svc.Start(t.Context(), "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		control := dialTCP(t, controlAddr)
		control = writeHello(t, control, token)
		readFrame(t, control)
		writeAuth(t, control, uid, token)
		readFrame(t, control)
		visitor := dialTCP(t, forwards[0])
		visitor.Write([]byte("request"))
		open := readFrame(t, control)
		parts, err := wp.Strings(open.Body, 4)
		if err != nil {
			t.Fatal(err)
		}
		data := dialTCP(t, dataAddr)
		target := dialTCP(t, echo)
		body, _ := wp.PutStrings(parts[3], uid, parts[0], dataAddr)
		data = bindData(t, data, body)
		writeFrame(data, wp.Frame{Type: wp.TypeReady})
		readFrame(t, data)
		data.SetDeadline(time.Time{})
		target.SetDeadline(time.Time{})
		copies := make(chan struct{})
		go func() { splice(target, data, nil, nil); close(copies) }()
		if got := readN(t, visitor, 7); string(got) != "request" {
			t.Fatal("TCP forwarding failed")
		}
		control.Close()
		visitor.Close()
		select {
		case <-copies:
		case <-time.After(time.Second):
			t.Fatal("peer copier not released")
		}
		data.Close()
		target.Close()
		deadline := time.Now().Add(time.Second)
		for {
			active := 0
			for _, s := range count.Snapshot().Sessions {
				if s.Active {
					active++
				}
			}
			svc.mu.Lock()
			controls := len(svc.controls)
			sessions := len(svc.sessions)
			svc.mu.Unlock()
			if active == 0 && controls == 0 && sessions == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("TCP reconnect retained runtime or metric session")
			}
			time.Sleep(time.Millisecond)
		}
	}
	t.Log("50 real TCP authentication/forward/control-loss/close cycles: active metrics and runtime sessions both zero")
}
