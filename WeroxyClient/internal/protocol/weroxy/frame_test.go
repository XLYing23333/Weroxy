package weroxy

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

func TestHelloVector(t *testing.T) {
	body, err := PutStrings("0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Encode(Frame{Type: TypeHello, RequestID: 1, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	// Fixed protocol vector; module tests must not depend on local-only directories.
	want, err := hex.DecodeString("57525859020001000000000000000001000000070005302e312e30")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("vector changed: %x", raw)
	}
	got, err := Reader{R: bytes.NewReader(raw)}.Next()
	if err != nil {
		t.Fatal(err)
	}
	parts, err := Strings(got.Body, 1)
	if err != nil || got.Type != TypeHello || got.RequestID != 1 || parts[0] != "0.1.0" {
		t.Fatalf("decoded %+v %v %v", got, parts, err)
	}
}

func TestPartialStickyAndOverflow(t *testing.T) {
	first, err := Encode(Frame{Type: TypePing, RequestID: 7})
	if err != nil {
		t.Fatal(err)
	}
	body, err := PutStrings("a", "b")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encode(Frame{Type: TypeAuth, RequestID: 8, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	reader := Reader{R: &oneByte{rest: append(append([]byte{}, first...), second...)}}
	ping, err := reader.Next()
	if err != nil || ping.Type != TypePing || ping.RequestID != 7 || len(ping.Body) != 0 {
		t.Fatalf("ping %+v err=%v", ping, err)
	}
	auth, err := reader.Next()
	if err != nil || auth.Type != TypeAuth {
		t.Fatal(err)
	}
	parts, err := Strings(auth.Body, 2)
	if err != nil || parts[0] != "a" || parts[1] != "b" {
		t.Fatalf("parts=%v err=%v", parts, err)
	}

	huge := &countRead{}
	hdr := make([]byte, HeaderSize)
	copy(hdr, Magic)
	hdr[4] = Major
	binary.BigEndian.PutUint32(hdr[16:20], MaxFrame)
	_, _ = huge.Write(hdr)
	if _, err := (Reader{R: huge}).Next(); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err=%v", err)
	}
	if huge.n != HeaderSize {
		t.Fatalf("oversized frame read body, bytes=%d", huge.n)
	}
}

func TestErrorAndTruncatedField(t *testing.T) {
	body, err := PutError(CodeTicket, "replay")
	if err != nil {
		t.Fatal(err)
	}
	code, text, err := ErrorBody(body)
	if err != nil || code != CodeTicket || text != "replay" {
		t.Fatalf("code=%d text=%s err=%v", code, text, err)
	}
	if _, err := Strings([]byte{0x00, 0x02, 'x'}, 1); !errors.Is(err, ErrBody) {
		t.Fatalf("err=%v", err)
	}
	raw, err := Encode(Frame{Type: TypeWelcome, Body: []byte{0xff}})
	if err != nil {
		t.Fatal(err)
	}
	raw[4] = 9
	if _, err := (Reader{R: bytes.NewReader(raw)}).Next(); !errors.Is(err, ErrVersion) {
		t.Fatalf("err=%v", err)
	}
}

type oneByte struct{ rest []byte }

func (o *oneByte) Read(p []byte) (int, error) {
	if len(o.rest) == 0 {
		return 0, io.EOF
	}
	p[0] = o.rest[0]
	o.rest = o.rest[1:]
	return 1, nil
}

type countRead struct {
	bytes.Buffer
	n int
}

func (c *countRead) Read(p []byte) (int, error) {
	n, err := c.Buffer.Read(p)
	c.n += n
	return n, err
}
