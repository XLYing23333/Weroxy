//go:build linux

package menu

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

type linuxTerminal struct {
	file     *os.File
	fd       int
	original *unix.Termios
	buffer   []byte
	active   bool
}

func IsTerminal() bool {
	_, inErr := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	_, outErr := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS)
	return inErr == nil && outErr == nil
}

func openTerminal(input io.Reader, output io.Writer) (Terminal, error) {
	f, ok := input.(*os.File)
	if !ok {
		return nil, errors.New("not a terminal")
	}
	out, ok := output.(*os.File)
	if !ok {
		return nil, errors.New("not a terminal")
	}
	if _, err := unix.IoctlGetTermios(int(out.Fd()), unix.TCGETS); err != nil {
		return nil, err
	}
	original, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if err != nil {
		return nil, err
	}
	t := &linuxTerminal{file: f, fd: int(f.Fd()), original: original}
	if err = t.Resume(); err != nil {
		return nil, err
	}
	return t, nil
}
func (t *linuxTerminal) Resume() error {
	raw := *t.original
	raw.Lflag &^= unix.ICANON | unix.ECHO
	raw.Iflag &^= unix.ICRNL
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(t.fd, unix.TCSETS, &raw); err != nil {
		return err
	}
	t.active = true
	return nil
}
func (t *linuxTerminal) Pause() error {
	if !t.active {
		return nil
	}
	err := unix.IoctlSetTermios(t.fd, unix.TCSETS, t.original)
	if err == nil {
		t.active = false
	}
	return err
}
func (t *linuxTerminal) Close() error { return t.Pause() }
func (t *linuxTerminal) Size() (int, int) {
	s, err := unix.IoctlGetWinsize(t.fd, unix.TIOCGWINSZ)
	if err != nil || s.Row == 0 || s.Col == 0 {
		return 24, 80
	}
	return int(s.Row), int(s.Col)
}
func (t *linuxTerminal) read(timeout int) error {
	fds := []unix.PollFd{{Fd: int32(t.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, timeout)
	if err == unix.EINTR {
		return nil
	}
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if fds[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0 {
		return io.EOF
	}
	b := make([]byte, 1024)
	n, err = unix.Read(t.fd, b)
	if err != nil {
		return err
	}
	if n == 0 {
		return io.EOF
	}
	t.buffer = append(t.buffer, b[:n]...)
	return nil
}
func (t *linuxTerminal) Key(ctx context.Context) (string, error) {
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if len(t.buffer) == 0 {
			if err := t.read(100); err != nil {
				return "", err
			}
			if len(t.buffer) == 0 {
				return "resize", nil
			}
		}
		b := t.buffer[0]
		if b == 27 {
			if len(t.buffer) < 3 {
				if err := t.read(30); err != nil {
					return "", err
				}
			}
			for _, seq := range []string{"\x1b[A", "\x1bOA", "\x1b[B", "\x1bOB"} {
				if strings.HasPrefix(string(t.buffer), seq) {
					t.buffer = t.buffer[len(seq):]
					if seq[len(seq)-1] == 'A' {
						return "up", nil
					}
					return "down", nil
				}
			}
			t.buffer = t.buffer[1:]
			return "esc", nil
		}
		if b == '\n' || b == '\r' {
			t.buffer = t.buffer[1:]
			return "enter", nil
		}
		if b == 127 || b == 8 {
			t.buffer = t.buffer[1:]
			return "backspace", nil
		}
		if b == 4 {
			return "", io.EOF
		}
		if b < 32 {
			t.buffer = t.buffer[1:]
			continue
		}
		if !utf8.FullRune(t.buffer) {
			if err := t.read(100); err != nil {
				return "", err
			}
			continue
		}
		r, n := utf8.DecodeRune(t.buffer)
		t.buffer = t.buffer[n:]
		if r == utf8.RuneError {
			continue
		}
		return string(r), nil
	}
}
