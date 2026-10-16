// Package secure implements the bounded Weroxy v2 Noise transport.
package secure

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/flynn/noise"
)

const Suite = "Noise_NNpsk0_25519_ChaChaPoly_SHA256"
const maxRecord = 65535
const chunk = 16384

var ErrProtocol = errors.New("secure protocol rejected")

// Credential contains a public lookup identifier and a secret, purpose-specific PSK.
type Credential struct {
	ID  [32]byte
	PSK [32]byte
}

func Derive(key []byte, purpose string) Credential {
	if len(key) != 32 {
		return Credential{}
	}
	var c Credential
	id, err := hkdf.Key(sha256.New, key, nil, "weroxy/v2/"+purpose+"/lookup", 32)
	if err != nil {
		panic(err)
	}
	psk, err := hkdf.Key(sha256.New, key, nil, "weroxy/v2/"+purpose+"/psk", 32)
	if err != nil {
		panic(err)
	}
	copy(c.ID[:], id)
	copy(c.PSK[:], psk)
	clear(id)
	clear(psk)
	return c
}

// Context encodes unambiguous handshake-bound fields, including the wire preface.
func Context(kind byte, selector []byte, fields ...string) []byte {
	b := append([]byte("WRXY\x02"), kind)
	b = binary.BigEndian.AppendUint16(b, uint16(len(selector)))
	b = append(b, selector...)
	for _, f := range fields {
		b = binary.BigEndian.AppendUint16(b, uint16(len(f)))
		b = append(b, f...)
	}
	return b
}
func WritePreface(w io.Writer, kind byte, selector []byte) error {
	if len(selector) == 0 || len(selector) > 128 {
		return ErrProtocol
	}
	return writeAll(w, Context(kind, selector))
}
func ReadPreface(r io.Reader, kind byte) ([]byte, error) {
	var h [8]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	if string(h[:5]) != "WRXY\x02" || h[5] != kind {
		return nil, ErrProtocol
	}
	n := int(binary.BigEndian.Uint16(h[6:]))
	if n == 0 || n > 128 {
		return nil, ErrProtocol
	}
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return b, e
}
func readMessage(r io.Reader) ([]byte, error) {
	var h [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n < 16 {
		return nil, ErrProtocol
	}
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return b, e
}
func writeMessage(w io.Writer, b []byte) error {
	if len(b) < 16 || len(b) > maxRecord {
		return ErrProtocol
	}
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(b)))
	if e := writeAll(w, h[:]); e != nil {
		return e
	}
	return writeAll(w, b)
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func state(init bool, psk [32]byte, context []byte) (*noise.HandshakeState, error) {
	return noise.NewHandshakeState(noise.Config{CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256), Pattern: noise.HandshakeNN, Initiator: init, PresharedKey: psk[:], PresharedKeyPlacement: 0, Prologue: context})
}

// Client completes the two-message handshake. Applications must subsequently
// confirm the final keys before taking authentication or Ticket side effects.
func Client(raw net.Conn, kind byte, selector []byte, psk [32]byte, fields []string, payload []byte) (*Conn, []byte, error) {
	if e := WritePreface(raw, kind, selector); e != nil {
		return nil, nil, e
	}
	h, e := state(true, psk, Context(kind, selector, fields...))
	if e != nil {
		return nil, nil, e
	}
	b, _, _, e := h.WriteMessage(nil, payload)
	if e != nil {
		return nil, nil, e
	}
	if e = writeMessage(raw, b); e != nil {
		return nil, nil, e
	}
	b, e = readMessage(raw)
	if e != nil {
		return nil, nil, e
	}
	reply, tx, rx, e := h.ReadMessage(nil, b)
	if e != nil {
		return nil, nil, e
	}
	return &Conn{Conn: raw, tx: tx, rx: rx}, reply, nil
}

// Server expects a preface already read and validated by the bounded lookup.
func Server(raw net.Conn, kind byte, selector []byte, psk [32]byte, fields []string, payload []byte) (*Conn, []byte, error) {
	h, e := state(false, psk, Context(kind, selector, fields...))
	if e != nil {
		return nil, nil, e
	}
	b, e := readMessage(raw)
	if e != nil {
		return nil, nil, e
	}
	request, _, _, e := h.ReadMessage(nil, b)
	if e != nil {
		return nil, nil, e
	}
	b, rx, tx, e := h.WriteMessage(nil, payload)
	if e != nil {
		return nil, nil, e
	}
	if e = writeMessage(raw, b); e != nil {
		return nil, nil, e
	}
	return &Conn{Conn: raw, tx: tx, rx: rx}, request, nil
}

// Conn reads exactly one encrypted record at a time without buffering raw bytes.
// Each direction owns a separate cipher state, serialized for concurrent users.
type Conn struct {
	net.Conn
	tx, rx            *noise.CipherState
	wm, rm            sync.Mutex
	pending           []byte
	header            [2]byte
	headerN           int
	record            []byte
	recordN           int
	readErr, writeErr error
}

func (c *Conn) Read(p []byte) (int, error) {
	c.rm.Lock()
	defer c.rm.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for len(c.pending) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		b, e := c.readRecord()
		if e == nil {
			c.pending, e = c.rx.Decrypt(nil, nil, b)
		}
		if e != nil {
			var timeout net.Error
			if errors.As(e, &timeout) && timeout.Timeout() {
				return 0, e
			}
			c.readErr = e
			_ = c.Conn.Close()
			return 0, e
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *Conn) Write(p []byte) (int, error) {
	c.wm.Lock()
	defer c.wm.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > chunk {
			n = chunk
		}
		b, e := c.tx.Encrypt(nil, nil, p[:n])
		if e == nil {
			e = writeMessage(c.Conn, b)
		}
		if e != nil {
			c.writeErr = e
			_ = c.Conn.Close()
			return total, e
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Raw is safe only at the agreed end of the encrypted handshake. Reject
// surplus authenticated bytes rather than silently discarding them.
func (c *Conn) Raw() (net.Conn, error) {
	c.rm.Lock()
	defer c.rm.Unlock()
	if len(c.pending) != 0 || c.readErr != nil || c.headerN != 0 || c.recordN != 0 {
		return nil, ErrProtocol
	}
	return c.Conn, nil
}

// Retain partial record framing across temporary read deadlines, like net.Conn.
func (c *Conn) readRecord() ([]byte, error) {
	if c.headerN < 2 {
		n, e := io.ReadFull(c.Conn, c.header[c.headerN:])
		c.headerN += n
		if e != nil {
			return nil, e
		}
	}
	if c.record == nil {
		size := int(binary.BigEndian.Uint16(c.header[:]))
		if size < 16 {
			return nil, ErrProtocol
		}
		c.record = make([]byte, size)
	}
	n, e := io.ReadFull(c.Conn, c.record[c.recordN:])
	c.recordN += n
	if e != nil {
		return nil, e
	}
	result := c.record
	c.record = nil
	c.recordN = 0
	c.headerN = 0
	return result, nil
}
