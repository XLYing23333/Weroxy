// Package legacy is the bounded codec for the original Lanproxy frame.
// It does not speak the Weroxy v1 handshake.
package legacy

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// TypeAuth is the control login. The URI is the original Client Key.
	TypeAuth byte = 0x01
	// TypeConnect asks a client to dial a target, or binds a data connection.
	TypeConnect byte = 0x03
	// TypeDisconnect releases one session.
	TypeDisconnect byte = 0x04
	// TypeTransfer carries business bytes on a legacy data connection.
	TypeTransfer byte = 0x05
	// TypeWriteControl is defined by the original protocol and ignored here.
	TypeWriteControl byte = 0x06
	// TypeHeartbeat is answered on control and idle data connections.
	TypeHeartbeat byte = 0x07

	lengthSize = 4
	minBody    = 10

	// MaxFrame is the largest whole frame this server will accept.
	// The original Java server uses the same 2 MiB ceiling.
	MaxFrame = 2 * 1024 * 1024
	// ClientMaxFrame is the original Java client decoder ceiling.
	ClientMaxFrame = 1024 * 1024
	// MaxURIToClient is the largest URI the original Java decoder can read.
	// That decoder treats the length as a signed byte.
	MaxURIToClient = 127
	// TransferChunk is the largest business payload this server puts in one sent frame.
	TransferChunk = 32 * 1024
)

var (
	// ErrShortBody means the length header promised fewer than 10 body bytes.
	ErrShortBody = errors.New("legacy body shorter than 10 bytes")
	// ErrFrameTooLarge means the whole frame would exceed 2 MiB.
	ErrFrameTooLarge = errors.New("legacy frame exceeds 2 MiB")
	// ErrClientFrame means a frame queued for an old client exceeds 1 MiB.
	ErrClientFrame = errors.New("legacy frame exceeds 1 MiB client limit")
	// ErrURIBounds means the URI length runs past the body.
	ErrURIBounds = errors.New("legacy uri length exceeds body")
	// ErrURIClient means an outgoing URI is longer than the Java decoder accepts.
	ErrURIClient = errors.New("legacy uri exceeds 127 bytes")
	// ErrURILength means an URI does not fit in one unsigned length byte.
	ErrURILength = errors.New("legacy uri exceeds 255 bytes")
)

// Frame is one legacy message without the 4-byte length prefix.
type Frame struct {
	Type   byte
	Serial uint64
	URI    string
	Data   []byte
}

// Encode serializes a frame this server is willing to store or parse.
// URIs longer than 127 bytes stay intact; use EncodeClient before writing to an old client.
func Encode(f Frame) ([]byte, error) {
	n, err := bodyLen(f)
	if err != nil {
		return nil, err
	}
	if lengthSize+n > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	return encode(f, n), nil
}

// EncodeClient serializes a frame that will be written to an old client.
// It refuses URIs above 127 bytes and whole frames above 1 MiB instead of truncating them.
func EncodeClient(f Frame) ([]byte, error) {
	if len(f.URI) > MaxURIToClient {
		return nil, ErrURIClient
	}
	n, err := bodyLen(f)
	if err != nil {
		return nil, err
	}
	if lengthSize+n > ClientMaxFrame {
		return nil, ErrClientFrame
	}
	return encode(f, n), nil
}

func bodyLen(f Frame) (int, error) {
	if len(f.URI) > 255 {
		return 0, ErrURILength
	}
	return 1 + 8 + 1 + len(f.URI) + len(f.Data), nil
}

func encode(f Frame, n int) []byte {
	buf := make([]byte, lengthSize+n)
	binary.BigEndian.PutUint32(buf[:lengthSize], uint32(n))
	buf[4] = f.Type
	binary.BigEndian.PutUint64(buf[5:13], f.Serial)
	buf[13] = byte(len(f.URI))
	copy(buf[14:], f.URI)
	copy(buf[14+len(f.URI):], f.Data)
	return buf
}

// Decode parses a body that has already been limited by the length header.
// The URI length is an unsigned byte.
func Decode(body []byte) (Frame, error) {
	if len(body) < minBody {
		return Frame{}, ErrShortBody
	}
	uriLen := int(body[9])
	rest := body[10:]
	if uriLen > len(rest) {
		return Frame{}, ErrURIBounds
	}
	return Frame{
		Type:   body[0],
		Serial: binary.BigEndian.Uint64(body[1:9]),
		URI:    string(body[10 : 10+uriLen]),
		Data:   append([]byte(nil), rest[uriLen:]...),
	}, nil
}

// Reader pulls one frame at a time. The body buffer is allocated only after the length is accepted.
type Reader struct {
	R io.Reader
}

// Next reads a 4-byte length and then exactly that many body bytes.
func (r Reader) Next() (Frame, error) {
	var hdr [lengthSize]byte
	if _, err := io.ReadFull(r.R, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < minBody {
		return Frame{}, ErrShortBody
	}
	if uint64(lengthSize)+uint64(n) > MaxFrame {
		return Frame{}, ErrFrameTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r.R, body); err != nil {
		return Frame{}, err
	}
	return Decode(body)
}
