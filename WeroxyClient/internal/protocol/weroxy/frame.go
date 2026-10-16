// Package weroxy is the bounded codec for Weroxy v1 control frames.
// Business bytes never use this framing. The client module has its own copy.
package weroxy

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	Magic           = "WRXY"
	Major      byte = 2
	Minor      byte = 0
	HeaderSize      = 20
	MaxFrame        = 64 * 1024
	maxField        = 4096

	TypeHello    byte = 1
	TypeWelcome  byte = 2
	TypeAuth     byte = 3
	TypeOpen     byte = 4
	TypeCancel   byte = 5
	TypePing     byte = 6
	TypePong     byte = 7
	TypeSync     byte = 8
	TypeError    byte = 9
	TypeDataBind byte = 10
	TypeReady    byte = 11
	TypeDiagnose byte = 12

	CodeVersion byte = 1
	CodeAuth    byte = 2
	CodeTicket  byte = 3
	CodeTarget  byte = 4
	CodeRevoked byte = 5
	CodeBusy    byte = 6
)

var (
	ErrMagic    = errors.New("weroxy magic mismatch")
	ErrVersion  = errors.New("weroxy version mismatch")
	ErrFlags    = errors.New("weroxy flags must be zero")
	ErrTooLarge = errors.New("weroxy frame exceeds 64 KiB")
	ErrBody     = errors.New("weroxy body is truncated or padded")
	ErrField    = errors.New("weroxy field is too long")
)

// Frame is one control or handshake message. It is not a business payload.
type Frame struct {
	Type      byte
	RequestID uint64
	Body      []byte
}

// Encode writes one frame. The body must already be bounded.
func Encode(f Frame) ([]byte, error) {
	if len(f.Body) > MaxFrame-HeaderSize {
		return nil, ErrTooLarge
	}
	buf := make([]byte, HeaderSize+len(f.Body))
	copy(buf[:4], Magic)
	buf[4] = Major
	buf[5] = Minor
	buf[6] = f.Type
	binary.BigEndian.PutUint64(buf[8:16], f.RequestID)
	binary.BigEndian.PutUint32(buf[16:20], uint32(len(f.Body)))
	copy(buf[HeaderSize:], f.Body)
	return buf, nil
}

// Reader pulls one frame at a time after the fixed header has been checked.
type Reader struct {
	R io.Reader
}

// Next reads a header, rejects an illegal length before allocating, then reads the body.
func (r Reader) Next() (Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r.R, hdr[:]); err != nil {
		return Frame{}, err
	}
	if string(hdr[:4]) != Magic {
		return Frame{}, ErrMagic
	}
	if hdr[4] != Major || hdr[5] != Minor {
		return Frame{}, ErrVersion
	}
	if hdr[7] != 0 {
		return Frame{}, ErrFlags
	}
	n := binary.BigEndian.Uint32(hdr[16:20])
	if HeaderSize+int(n) > MaxFrame {
		return Frame{}, ErrTooLarge
	}
	body := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r.R, body); err != nil {
			return Frame{}, err
		}
	}
	return Frame{Type: hdr[6], RequestID: binary.BigEndian.Uint64(hdr[8:16]), Body: body}, nil
}

// PutStrings encodes a sequence of length-prefixed strings.
func PutStrings(parts ...string) ([]byte, error) {
	var buf []byte
	for _, part := range parts {
		if len(part) > maxField {
			return nil, ErrField
		}
		buf = append(buf, byte(len(part)>>8), byte(len(part)))
		buf = append(buf, part...)
	}
	return buf, nil
}

// Strings decodes exactly n strings and rejects trailing bytes.
func Strings(body []byte, n int) ([]string, error) {
	out := make([]string, 0, n)
	for len(out) < n {
		if len(body) < 2 {
			return nil, ErrBody
		}
		nlen := int(body[0])<<8 | int(body[1])
		body = body[2:]
		if nlen > maxField || len(body) < nlen {
			return nil, ErrBody
		}
		out = append(out, string(body[:nlen]))
		body = body[nlen:]
	}
	if len(body) != 0 {
		return nil, ErrBody
	}
	return out, nil
}

// PutError encodes an ERROR body.
func PutError(code byte, message string) ([]byte, error) {
	text, err := PutStrings(message)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 2+len(text))
	buf[1] = code
	copy(buf[2:], text)
	return buf, nil
}

// ErrorBody decodes an ERROR body.
func ErrorBody(body []byte) (byte, string, error) {
	if len(body) < 2 {
		return 0, "", ErrBody
	}
	parts, err := Strings(body[2:], 1)
	if err != nil {
		return 0, "", err
	}
	return body[1], parts[0], nil
}
