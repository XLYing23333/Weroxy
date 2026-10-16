package legacy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRoundTripAndPartialReads(t *testing.T) {
	original := Frame{Type: TypeHeartbeat, Serial: 0x0102030405060708, URI: "hb", Data: []byte("ping")}
	raw, err := Encode(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Reader{R: &oneByte{rest: raw}}.Next()
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != original.Type || got.Serial != original.Serial || got.URI != original.URI || !bytes.Equal(got.Data, original.Data) {
		t.Fatalf("got %+v", got)
	}
}

func TestRejectShortAndOverflowBeforeBody(t *testing.T) {
	short := &countRead{}
	binary.Write(short, binary.BigEndian, uint32(9))
	if _, err := (Reader{R: short}).Next(); !errors.Is(err, ErrShortBody) {
		t.Fatalf("err=%v", err)
	}
	if short.n != 4 {
		t.Fatalf("short frame allocated or read body, bytes=%d", short.n)
	}

	huge := &countRead{}
	binary.Write(huge, binary.BigEndian, uint32(MaxFrame))
	if _, err := (Reader{R: huge}).Next(); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err=%v", err)
	}
	if huge.n != 4 {
		t.Fatalf("oversized frame read body, bytes=%d", huge.n)
	}
}

func TestURI127And128(t *testing.T) {
	uri127 := strings.Repeat("a", 127)
	raw, err := EncodeClient(Frame{Type: TypeAuth, URI: uri127})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw[4:])
	if err != nil || got.URI != uri127 {
		t.Fatalf("uri127 err=%v len=%d", err, len(got.URI))
	}

	uri128 := strings.Repeat("b", 128)
	if _, err := EncodeClient(Frame{Type: TypeAuth, URI: uri128}); !errors.Is(err, ErrURIClient) {
		t.Fatalf("client encode err=%v", err)
	}
	raw, err = Encode(Frame{Type: TypeConnect, URI: uri128})
	if err != nil {
		t.Fatal(err)
	}
	got, err = Decode(raw[4:])
	if err != nil || len(got.URI) != 128 {
		t.Fatalf("unsigned uri128 err=%v len=%d", err, len(got.URI))
	}
	if raw[13] != 128 {
		t.Fatalf("length byte=%d", raw[13])
	}
}

func TestURIPastBodyAndClientFrameCap(t *testing.T) {
	body := make([]byte, minBody)
	body[9] = 11
	if _, err := Decode(body); !errors.Is(err, ErrURIBounds) {
		t.Fatalf("err=%v", err)
	}
	big := Frame{Type: TypeTransfer, Data: bytes.Repeat([]byte("x"), ClientMaxFrame)}
	if _, err := EncodeClient(big); !errors.Is(err, ErrClientFrame) {
		t.Fatalf("err=%v", err)
	}
}

func TestEmptyURITransfer(t *testing.T) {
	raw, err := Encode(Frame{Type: TypeTransfer, Data: []byte("abc")})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw[4:])
	if err != nil || got.URI != "" || !bytes.Equal(got.Data, []byte("abc")) {
		t.Fatalf("got uri=%q data=%q err=%v", got.URI, got.Data, err)
	}
}

type oneByte struct {
	rest []byte
}

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
