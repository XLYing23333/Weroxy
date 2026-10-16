package cli

import (
	"bytes"
	"errors"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// importSecret decodes JSON directly into owned, wipeable bytes. It must not
// create an immutable plaintext string for a credential or duplicate-key map.
type importSecret []byte

func (secret *importSecret) UnmarshalJSON(raw []byte) error {
	zero(*secret)
	*secret = nil
	if bytes.Equal(raw, []byte("null")) {
		return nil
	}
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' || !utf8.Valid(raw) {
		return errors.New("invalid import credential encoding")
	}
	out := make([]byte, 0, len(raw)-2)
	keep := false
	defer func() {
		if !keep {
			zero(out)
		}
	}()
	end := len(raw) - 1
	for index := 1; index < end; index++ {
		value := raw[index]
		if value != '\\' {
			if value < 0x20 || value == '"' {
				return errors.New("invalid import credential encoding")
			}
			out = append(out, value)
			continue
		}
		index++
		if index >= end {
			return errors.New("invalid import credential encoding")
		}
		switch raw[index] {
		case '"', '\\', '/':
			out = append(out, raw[index])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			if index+4 >= end {
				return errors.New("invalid import credential encoding")
			}
			code, err := strconv.ParseUint(string(raw[index+1:index+5]), 16, 16)
			if err != nil {
				return errors.New("invalid import credential encoding")
			}
			index += 4
			point := rune(code)
			if utf16.IsSurrogate(point) {
				if point < 0xD800 || point > 0xDBFF || index+6 >= end || raw[index+1] != '\\' || raw[index+2] != 'u' {
					return errors.New("invalid import credential encoding")
				}
				low, err := strconv.ParseUint(string(raw[index+3:index+7]), 16, 16)
				if err != nil || low < 0xDC00 || low > 0xDFFF {
					return errors.New("invalid import credential encoding")
				}
				point = utf16.DecodeRune(point, rune(low))
				index += 6
			}
			out = utf8.AppendRune(out, point)
		default:
			return errors.New("invalid import credential encoding")
		}
	}
	*secret = out
	keep = true
	return nil
}
