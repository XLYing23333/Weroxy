//go:build !linux

package menu

import (
	"errors"
	"io"
)

func openTerminal(io.Reader, io.Writer) (Terminal, error) {
	return nil, errors.New("Linux terminal required")
}

func IsTerminal() bool { return false }
