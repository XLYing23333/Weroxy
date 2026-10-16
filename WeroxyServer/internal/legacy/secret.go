package legacy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SecretFile is the local HMAC key. It is not the Client Key.
const SecretFile = "legacy-mac.key"

// ErrSecretMode means the HMAC key file is readable by the group or by others.
var ErrSecretMode = errors.New("legacy mac key is readable by group or others")

// LoadSecret reads the data-directory HMAC key. When create is set, a missing file is generated.
func LoadSecret(dir string, create bool) ([]byte, error) {
	path := filepath.Join(dir, SecretFile)
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return nil, err
		}
		body = make([]byte, 32)
		if _, err := rand.Read(body); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
		return body, nil
	}
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, ErrSecretMode
	}
	if len(body) < 32 {
		return nil, fmt.Errorf("legacy mac key is too short")
	}
	return body, nil
}

// MAC returns HMAC-SHA256(secret, clientKey).
func MAC(secret, clientKey []byte) []byte {
	sum := hmac.New(sha256.New, secret)
	_, _ = sum.Write(clientKey)
	return sum.Sum(nil)
}
