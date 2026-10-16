package weroxy

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"weroxy/server/internal/legacy"
	wp "weroxy/server/internal/protocol/weroxy"
	"weroxy/server/internal/secure"
)

type captureConn struct {
	net.Conn
	written bytes.Buffer
}

func (c *captureConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	c.written.Write(b[:n])
	return n, e
}
func readNoiseReply(c net.Conn) error {
	var h [2]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		return e
	}
	_, e := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(h[:])))
	return e
}
func newNoiseService(t *testing.T) (*Service, string, string, string, []byte, string) {
	t.Helper()
	token := bytes32(73)
	uid := hex.EncodeToString(bytes32(74)[:16])
	s := New(Options{Devices: []Device{{ID: 1, Name: "box", UID: uid, TokenMAC: legacy.MAC(bytes32(72), token), Credential: secure.Derive(token, "control")}}, Forwards: []Forward{{ID: 1, DeviceID: 1, Listen: "127.0.0.1:0", Target: echoServer(t)}}, Handshake: time.Second})
	control, data, forwards, e := s.Start(t.Context(), "127.0.0.1:0", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	return s, control, data, forwards[0], token, uid
}
func TestNoiseControlFirstFlightAndAuthReplayCannotRegister(t *testing.T) {
	s, addr, _, _, token, uid := newNoiseService(t)
	raw := dialTCP(t, addr)
	defer raw.Close()
	capture := &captureConn{Conn: raw}
	cred := secure.Derive(token, "control")
	c, _, e := secure.Client(capture, 'C', cred.ID[:], cred.PSK, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	first := append([]byte(nil), capture.written.Bytes()...)
	body, _ := wp.PutStrings(uid)
	if e = writeFrame(c, wp.Frame{Type: wp.TypeAuth, Body: body}); e != nil {
		t.Fatal(e)
	}
	if f := readFrame(t, c); f.Type != wp.TypeSync {
		t.Fatal(f.Type)
	}
	auth := append([]byte(nil), capture.written.Bytes()[len(first):]...)
	s.mu.Lock()
	current := s.controls[1]
	s.mu.Unlock()
	replay := dialTCP(t, addr)
	defer replay.Close()
	replay.SetDeadline(time.Now().Add(time.Second))
	replay.Write(first)
	if e = readNoiseReply(replay); e != nil {
		t.Fatal(e)
	}
	replay.Write(auth)
	if _, e = (wp.Reader{R: replay}).Next(); e == nil {
		t.Fatal("replayed final proof accepted")
	}
	s.mu.Lock()
	same := s.controls[1] == current && !current.closed.Load()
	s.mu.Unlock()
	if !same {
		t.Fatal("replay replaced control")
	}
	if bytes.Contains(capture.written.Bytes(), token) || bytes.Contains(capture.written.Bytes(), []byte(hex.EncodeToString(token))) {
		t.Fatal("credential on wire")
	}
}
func TestNoiseDataReplayCannotConsumeThenConcurrentProofConsumesOnce(t *testing.T) {
	s, addr, data, fwd, token, uid := newNoiseService(t)
	control := authControl(t, addr, "", uid, token)
	open := openVisitor(t, control, fwd)
	raw := dialTCP(t, data)
	defer raw.Close()
	capture := &captureConn{Conn: raw}
	ticket, _ := hex.DecodeString(open[3])
	cred := secure.Derive(ticket, "data")
	g, _ := testGenerations.Load(open[3])
	fields := []string{uid, open[0], g.(string), open[2]}
	c, _, e := secure.Client(capture, 'D', []byte(open[0]), cred.PSK, fields, nil)
	if e != nil {
		t.Fatal(e)
	}
	first := append([]byte(nil), capture.written.Bytes()...)
	// An observer can replay the first packet but cannot confirm fresh keys.
	replay := dialTCP(t, data)
	defer replay.Close()
	replay.SetDeadline(time.Now().Add(time.Second))
	replay.Write(first)
	if e = readNoiseReply(replay); e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	used := s.sessions[open[0]].used
	s.mu.Unlock()
	if used {
		t.Fatal("first packet consumed ticket")
	}
	if e = writeFrame(c, wp.Frame{Type: wp.TypeReady}); e != nil {
		t.Fatal(e)
	}
	if f := readFrame(t, c); f.Type != wp.TypeReady {
		t.Fatal(f.Type)
	}
	proof := append([]byte(nil), capture.written.Bytes()[len(first):]...)
	replay.Write(proof)
	if _, e = (wp.Reader{R: replay}).Next(); e == nil {
		t.Fatal("replayed READY accepted")
	}
	if bytes.Contains(capture.written.Bytes(), ticket) || bytes.Contains(capture.written.Bytes(), []byte(open[3])) {
		t.Fatal("ticket on wire")
	}
	// Independent fresh handshakes with the same Ticket may race; one wins.
	next := openVisitor(t, control, fwd)
	ticket, _ = hex.DecodeString(next[3])
	cred = secure.Derive(ticket, "data")
	g, _ = testGenerations.Load(next[3])
	fields = []string{uid, next[0], g.(string), next[2]}
	var peers []*secure.Conn
	for i := 0; i < 2; i++ {
		r := dialTCP(t, data)
		defer r.Close()
		p, _, err := secure.Client(r, 'D', []byte(next[0]), cred.PSK, fields, nil)
		if err != nil {
			t.Fatal(err)
		}
		peers = append(peers, p)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for _, p := range peers {
		wg.Add(1)
		go func(p *secure.Conn) {
			defer wg.Done()
			_ = p.SetDeadline(time.Now().Add(time.Second))
			err := writeFrame(p, wp.Frame{Type: wp.TypeReady})
			if err != nil {
				results <- false
				return
			}
			f, err := (wp.Reader{R: p}).Next()
			results <- err == nil && f.Type == wp.TypeReady
		}(p)
	}
	wg.Wait()
	close(results)
	wins := 0
	for win := range results {
		if win {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("winners=%d", wins)
	}
	s.mu.Lock()
	generation := s.sessions[next[0]].generation
	s.mu.Unlock()
	if strconv.FormatUint(generation, 10) != fields[2] {
		t.Fatal("generation changed")
	}
}

func TestNoiseKeyRotationInvalidatesPendingProofAndExistingSession(t *testing.T) {
	s, addr, data, fwd, old, uid := newNoiseService(t)
	control := authControl(t, addr, "", uid, old)
	visitor, bound := bindEcho(t, control, "", data, fwd, echoServer(t), uid)
	defer visitor.Close()
	defer bound.Close()
	pending := dialTCP(t, addr)
	defer pending.Close()
	cred := secure.Derive(old, "control")
	p, _, e := secure.Client(pending, 'C', cred.ID[:], cred.PSK, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	next := bytes32(75)
	d := Device{ID: 1, Name: "box", UID: uid, TokenMAC: legacy.MAC(bytes32(72), next), Credential: secure.Derive(next, "control")}
	if e = s.ReconcileDevices(t.Context(), []Device{d}); e != nil {
		t.Fatal(e)
	}
	body, _ := wp.PutStrings(uid)
	_ = writeFrame(p, wp.Frame{Type: wp.TypeAuth, Body: body})
	f, e := (wp.Reader{R: p}).Next()
	if e == nil && f.Type == wp.TypeSync {
		t.Fatal("stale final proof registered")
	}
	visitor.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = visitor.Read(make([]byte, 1)); e == nil {
		t.Fatal("old session survived key rotation")
	}
	fresh := authControl(t, addr, "", uid, next)
	defer fresh.Close()
}
