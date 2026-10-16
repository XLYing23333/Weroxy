package secure

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

func testPair(t *testing.T, kind byte, fields []string) (*Conn, *Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	cred := Derive(bytes.Repeat([]byte{7}, 32), "control")
	done := make(chan *Conn, 1)
	errs := make(chan error, 1)
	go func() {
		sel, e := ReadPreface(b, kind)
		if e != nil {
			errs <- e
			return
		}
		c, p, e := Server(b, kind, sel, cred.PSK, fields, []byte("reply"))
		if e == nil && !bytes.Equal(p, []byte("request")) {
			e = ErrProtocol
		}
		if e != nil {
			errs <- e
			return
		}
		done <- c
	}()
	c, p, e := Client(a, kind, cred.ID[:], cred.PSK, fields, []byte("request"))
	if e != nil {
		t.Fatal(e)
	}
	if string(p) != "reply" {
		t.Fatal("response")
	}
	select {
	case s := <-done:
		return c, s
	case e := <-errs:
		t.Fatal(e)
	}
	return nil, nil
}
func TestRecordsLargeFrameAndRawTransition(t *testing.T) {
	c, s := testPair(t, 'D', []string{"device", "session", "9", "0.0.0.0:29100"})
	large := bytes.Repeat([]byte{3}, 65536)
	done := make(chan error, 1)
	go func() { _, e := c.Write(large); done <- e }()
	got := make([]byte, len(large))
	if _, e := io.ReadFull(s, got); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, large) {
		t.Fatal("record split")
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	rawC, e := c.Raw()
	if e != nil {
		t.Fatal(e)
	}
	rawS, e := s.Raw()
	if e != nil {
		t.Fatal(e)
	}
	go func() { _, e := rawC.Write([]byte("SSH-2.0-test\r\n")); done <- e }()
	got = make([]byte, 14)
	if _, e := io.ReadFull(rawS, got); e != nil {
		t.Fatal(e)
	}
	if string(got) != "SSH-2.0-test\r\n" {
		t.Fatal(string(got))
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func TestMismatchKeyAndContext(t *testing.T) {
	for _, wrongKey := range []bool{true, false} {
		t.Run(map[bool]string{true: "key", false: "context"}[wrongKey], func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(time.Second))
			b.SetDeadline(time.Now().Add(time.Second))
			cred := Derive(bytes.Repeat([]byte{1}, 32), "control")
			done := make(chan error, 1)
			go func() {
				defer b.Close()
				sel, e := ReadPreface(b, 'C')
				if e != nil {
					done <- e
					return
				}
				psk := cred.PSK
				fields := []string{"correct"}
				if wrongKey {
					psk[0] ^= 1
				} else {
					fields[0] = "wrong"
				}
				_, _, e = Server(b, 'C', sel, psk, fields, nil)
				done <- e
			}()
			if _, _, e := Client(a, 'C', cred.ID[:], cred.PSK, []string{"correct"}, nil); e == nil {
				t.Fatal("mismatch accepted")
			}
			if e := <-done; e == nil {
				t.Fatal("server accepted mismatch")
			}
		})
	}
}
func TestRecordReplayAndTamper(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		t.Run(map[bool]string{true: "tamper", false: "replay"}[tamper], func(t *testing.T) {
			c, s := testPair(t, 'C', nil)
			ciphertext, e := c.tx.Encrypt(nil, nil, []byte("ping"))
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- writeMessage(c.Conn, ciphertext) }()
			b := make([]byte, 4)
			if _, e := io.ReadFull(s, b); e != nil {
				t.Fatal(e)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			if tamper {
				ciphertext, e = c.tx.Encrypt(nil, nil, []byte("ping"))
				if e != nil {
					t.Fatal(e)
				}
				ciphertext[len(ciphertext)-1] ^= 1
			}
			go func() { done <- writeMessage(c.Conn, ciphertext) }()
			if _, e := s.Read(b); e == nil {
				t.Fatal("invalid record accepted")
			}
			<-done
		})
	}
}
func TestDerivationVector(t *testing.T) {
	c := Derive(bytes.Repeat([]byte{7}, 32), "control")
	got := hex.EncodeToString(c.ID[:]) + ":" + hex.EncodeToString(c.PSK[:])
	const want = "f8c56163fab3d293b27866685130c704d500608836c217f4e21d75f4c21a7a1e:88ba5b86fec002a9464f2cb1553877d453d5b7357a250ab52188a1a51959807b"
	if got != want {
		t.Fatal(got)
	}
	d := Derive(bytes.Repeat([]byte{7}, 32), "data")
	if c.ID == c.PSK || c.PSK == d.PSK {
		t.Fatal("domain separation")
	}
}
func TestRawRejectsUnreadAuthenticatedBytes(t *testing.T) {
	c, s := testPair(t, 'D', nil)
	done := make(chan error, 1)
	go func() { _, e := c.Write([]byte("READYsurplus")); done <- e }()
	b := make([]byte, 5)
	if _, e := io.ReadFull(s, b); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Raw(); e == nil {
		t.Fatal("surplus dropped")
	}
	<-done
}
func FuzzPreface(f *testing.F) {
	f.Add(Context('C', bytes.Repeat([]byte{1}, 32)))
	f.Add([]byte("WRXY\x01"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ReadPreface(bytes.NewReader(b), 'C') })
}
func FuzzRecord(f *testing.F) {
	f.Add([]byte{0, 16})
	f.Add([]byte{255, 255})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = readMessage(bytes.NewReader(b)) })
}

func TestContextBindsEachDataField(t *testing.T) {
	base := []string{"uid", "session", "17", "0.0.0.0:29100"}
	for i := range base {
		t.Run(base[i], func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(time.Second))
			b.SetDeadline(time.Now().Add(time.Second))
			cred := Derive(bytes.Repeat([]byte{4}, 32), "data")
			bad := append([]string(nil), base...)
			bad[i] += "changed"
			done := make(chan error, 1)
			go func() {
				defer b.Close()
				sel, e := ReadPreface(b, 'D')
				if e == nil {
					_, _, e = Server(b, 'D', sel, cred.PSK, bad, nil)
				}
				done <- e
			}()
			if _, _, e := Client(a, 'D', []byte("session"), cred.PSK, base, nil); e == nil {
				t.Fatal("context substitution accepted")
			}
			if e := <-done; e == nil {
				t.Fatal("responder accepted substitution")
			}
		})
	}
}
func TestPartialRecordReadCanResumeAfterDeadline(t *testing.T) {
	c, s := testPair(t, 'C', nil)
	cipher, e := c.tx.Encrypt(nil, nil, []byte("ping"))
	if e != nil {
		t.Fatal(e)
	}
	var wire bytes.Buffer
	if e = writeMessage(&wire, cipher); e != nil {
		t.Fatal(e)
	}
	b := wire.Bytes()
	done := make(chan error, 1)
	go func() { _, e := c.Conn.Write(b[:3]); done <- e }()
	s.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	buf := make([]byte, 4)
	if _, e = s.Read(buf); e == nil {
		t.Fatal("expected temporary timeout")
	}
	<-done
	s.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, e := c.Conn.Write(b[3:]); done <- e }()
	if _, e = io.ReadFull(s, buf); e != nil {
		t.Fatal(e)
	}
	if string(buf) != "ping" {
		t.Fatal("lost record framing")
	}
	<-done
}
