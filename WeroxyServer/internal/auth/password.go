// Package auth hashes administrator passwords and reads them without echoing.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// ArgonMemoryKiB is 64 MiB, the skeleton Argon2id memory cost.
	ArgonMemoryKiB = 64 * 1024
	// ArgonTime is the Argon2id iteration count.
	ArgonTime = 3
	// ArgonThreads is the Argon2id parallelism. One thread keeps the limiter meaningful.
	ArgonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16

	// MinPasswordLen and MaxPasswordLen bound the accepted password in bytes.
	MinPasswordLen = 6
	MaxPasswordLen = 1024

	maxHashInFlight = 2
	maxHashQueued   = 8

	minMemoryKiB = 8 * 1024
	maxMemoryKiB = 256 * 1024
	minTime      = 2
	maxTime      = 5
)

// ErrHashBusy means the in-flight and queued password hashes are already full.
var ErrHashBusy = errors.New("password hash busy")

// ErrPasswordLength means the password is outside the accepted byte length.
var ErrPasswordLength = errors.New("password length out of range")

// ErrPasswordFile means the secret file is missing or readable by group or others.
var ErrPasswordFile = errors.New("password file is not private")

// ErrParams means a stored PHC string asks for a cost outside the allowed range.
var ErrParams = errors.New("argon2 parameters out of range")

// PasswordHasher creates and checks PHC strings.
type PasswordHasher interface {
	Hash(password []byte) (string, error)
	Verify(password []byte, phc string) (bool, error)
}

// Argon is an Argon2id hasher with a bounded concurrency queue.
type Argon struct {
	slots chan struct{}
	queue chan struct{}
	kdf   func(password, salt []byte, time, memory uint32, threads uint8) []byte
}

// NewArgon returns the production hasher.
func NewArgon() *Argon {
	return &Argon{
		slots: make(chan struct{}, maxHashInFlight),
		queue: make(chan struct{}, maxHashQueued),
		kdf: func(password, salt []byte, time, memory uint32, threads uint8) []byte {
			return argon2.IDKey(password, salt, time, memory, threads, argonKeyLen)
		},
	}
}

// Hash returns a PHC string. The password is not retained.
func (a *Argon) Hash(password []byte) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	if err := a.acquire(); err != nil {
		return "", err
	}
	defer a.release()

	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	sum := a.kdf(password, salt, ArgonTime, ArgonMemoryKiB, ArgonThreads)
	return formatPHC(ArgonMemoryKiB, ArgonTime, ArgonThreads, salt, sum), nil
}

// Verify checks a password against a PHC string in constant time for the hash bytes.
func (a *Argon) Verify(password []byte, phc string) (bool, error) {
	mem, timeCost, threads, salt, want, err := parsePHC(phc)
	if err != nil {
		return false, err
	}
	if err := a.acquire(); err != nil {
		return false, err
	}
	defer a.release()
	got := a.kdf(password, salt, timeCost, mem, threads)
	if len(got) != len(want) {
		return false, nil
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func (a *Argon) acquire() error {
	select {
	case a.slots <- struct{}{}:
		return nil
	default:
	}
	select {
	case a.queue <- struct{}{}:
	default:
		return ErrHashBusy
	}
	a.slots <- struct{}{}
	<-a.queue
	return nil
}

func (a *Argon) release() {
	<-a.slots
}

// ValidatePassword checks the configured byte length.
func ValidatePassword(password []byte) error {
	if len(password) < MinPasswordLen || len(password) > MaxPasswordLen {
		return ErrPasswordLength
	}
	return nil
}

// ReadPassword reads a secret from a mode-0600 file, a terminal, or one stdin line.
func ReadPassword(path string, in io.Reader, isTerm bool, termRead func() ([]byte, error)) ([]byte, error) {
	if path != "" {
		info, err := os.Stat(path)
		if err != nil {
			return nil, ErrPasswordFile
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, ErrPasswordFile
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, ErrPasswordFile
		}
		return trimSecret(body)
	}
	if isTerm {
		if termRead == nil {
			return nil, errors.New("terminal password reader is unavailable")
		}
		body, err := termRead()
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}
		return trimSecret(body)
	}
	body, err := readLimited(in, MaxPasswordLen+1)
	if err != nil {
		return nil, err
	}
	return trimSecret(body)
}

func trimSecret(body []byte) ([]byte, error) {
	if len(body) > 0 && body[len(body)-1] == '\n' {
		body = body[:len(body)-1]
		if len(body) > 0 && body[len(body)-1] == '\r' {
			body = body[:len(body)-1]
		}
	}
	if err := ValidatePassword(body); err != nil {
		return nil, err
	}
	out := make([]byte, len(body))
	copy(out, body)
	return out, nil
}

func readLimited(in io.Reader, limit int) ([]byte, error) {
	buf := make([]byte, limit+1)
	n, err := io.ReadFull(in, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read password: %w", err)
	}
	if n > limit {
		return nil, ErrPasswordLength
	}
	return buf[:n], nil
}

func formatPHC(memory, timeCost uint32, threads uint8, salt, sum []byte) string {
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, timeCost, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	)
}

func parsePHC(phc string) (memory, timeCost uint32, threads uint8, salt, sum []byte, err error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return 0, 0, 0, nil, nil, ErrParams
	}
	var m, t, p int
	if _, scanErr := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); scanErr != nil {
		return 0, 0, 0, nil, nil, ErrParams
	}
	if m < minMemoryKiB || m > maxMemoryKiB || t < minTime || t > maxTime || p != ArgonThreads {
		return 0, 0, 0, nil, nil, ErrParams
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return 0, 0, 0, nil, nil, ErrParams
	}
	sum, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(sum) != argonKeyLen {
		return 0, 0, 0, nil, nil, ErrParams
	}
	return uint32(m), uint32(t), uint8(p), salt, sum, nil
}

// QueueDepth reports how many hashes are waiting for a slot. Tests use it.
func (a *Argon) QueueDepth() int {
	return len(a.queue)
}
