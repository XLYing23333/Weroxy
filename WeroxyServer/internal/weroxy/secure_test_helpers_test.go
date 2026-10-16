package weroxy

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	wp "weroxy/server/internal/protocol/weroxy"
	"weroxy/server/internal/secure"
)

var testGenerations sync.Map // random Ticket -> control generation
// The prefix exposes the genuine Noise response to existing lifecycle fixtures.
type testControl struct {
	net.Conn
	prefix     *bytes.Reader
	generation string
}

func (c *testControl) Read(p []byte) (int, error) {
	if c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	return c.Conn.Read(p)
}

type testData struct {
	net.Conn
	encrypted *secure.Conn
}

func tryData(conn net.Conn, body []byte) (*secure.Conn, error) {
	parts, err := wp.Strings(body, 4)
	if err != nil {
		return nil, err
	}
	token, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	cred := secure.Derive(token, "data")
	generation, _ := testGenerations.Load(parts[0])
	g, _ := generation.(string)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	c, _, err := secure.Client(conn, 'D', []byte(parts[2]), cred.PSK, []string{parts[1], parts[2], g, parts[3]}, nil)
	return c, err
}
func bindData(t *testing.T, conn net.Conn, body []byte) net.Conn {
	t.Helper()
	c, err := tryData(conn, body)
	if err != nil {
		t.Fatal(err)
	}
	return &testData{Conn: c, encrypted: c}
}
func rejectData(t *testing.T, conn net.Conn, body []byte) {
	t.Helper()
	c, err := tryData(conn, body)
	if err != nil {
		return
	}
	defer c.Close()
	if writeFrame(c, wp.Frame{Type: wp.TypeReady}) != nil {
		return
	}
	if _, err = (wp.Reader{R: c}).Next(); err == nil {
		t.Fatal("invalid binding accepted")
	}
}

var _ io.Reader = (*testControl)(nil)
