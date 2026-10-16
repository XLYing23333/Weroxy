package auth

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestArgonPHCRoundTrip(t *testing.T) {
	h := NewArgon()
	password := []byte("correct-horse-1")
	phc, err := h.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatalf("phc = %s", phc)
	}
	ok, err := h.Verify(password, phc)
	if err != nil || !ok {
		t.Fatalf("verify ok=%v err=%v", ok, err)
	}
	ok, err = h.Verify([]byte("correct-horse-2"), phc)
	if err != nil || ok {
		t.Fatalf("wrong password ok=%v err=%v", ok, err)
	}
	if _, err := h.Verify(password, "$argon2id$v=19$m=99999999,t=3,p=1$aaaaaaaa$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err != ErrParams {
		t.Fatalf("huge memory err=%v", err)
	}
}

func TestSixBytePasswordBoundary(t *testing.T) {
	h := NewArgon()
	for _, password := range []string{"12345", "123456"} {
		got, err := h.Hash([]byte(password))
		if len(password) == 5 {
			if !errors.Is(err, ErrPasswordLength) || got != "" {
				t.Fatalf("five-byte password: hash=%q err=%v", got, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("six-byte password: %v", err)
		}
		ok, err := h.Verify([]byte(password), got)
		if err != nil || !ok {
			t.Fatalf("six-byte verify: ok=%v err=%v", ok, err)
		}
	}
	got, err := ReadPassword("", strings.NewReader("123456\n"), false, nil)
	if err != nil || string(got) != "123456" {
		t.Fatalf("six-byte stdin: %q %v", got, err)
	}
}

func TestHashConcurrencyLimit(t *testing.T) {
	h := NewArgon()
	started := make(chan struct{}, 16)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	h.kdf = func(password, salt []byte, time, memory uint32, threads uint8) []byte {
		started <- struct{}{}
		<-release
		return bytes.Repeat([]byte{1}, 32)
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := h.Hash([]byte("correct-horse-1")); err != nil {
				t.Errorf("in-flight hash: %v", err)
			}
		}()
	}
	for i := 0; i < 2; i++ {
		<-started
	}
	for i := 0; i < maxHashQueued; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.Hash([]byte("correct-horse-1"))
		}()
	}
	deadline := 0
	for h.QueueDepth() < maxHashQueued {
		deadline++
		if deadline > 1000 {
			t.Fatalf("queue depth %d", h.QueueDepth())
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := h.Hash([]byte("correct-horse-1")); !errors.Is(err, ErrHashBusy) {
		t.Fatalf("busy err=%v", err)
	}
	once.Do(func() { close(release) })
	wg.Wait()
}

func TestPasswordFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("correct-horse-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPassword(path, nil, false, nil); !errors.Is(err, ErrPasswordFile) {
		t.Fatalf("mode err=%v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPassword(path, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "correct-horse-1" {
		t.Fatalf("got %q", got)
	}
}

func TestReadStdinAndTerminal(t *testing.T) {
	got, err := ReadPassword("", strings.NewReader("correct-horse-1\n"), false, nil)
	if err != nil || string(got) != "correct-horse-1" {
		t.Fatalf("stdin %q %v", got, err)
	}
	got, err = ReadPassword("", nil, true, func() ([]byte, error) {
		return []byte("correct-horse-1"), nil
	})
	if err != nil || string(got) != "correct-horse-1" {
		t.Fatalf("term %q %v", got, err)
	}
	if _, err := ReadPassword("", strings.NewReader("short\n"), false, nil); !errors.Is(err, ErrPasswordLength) {
		t.Fatalf("short err=%v", err)
	}
}
