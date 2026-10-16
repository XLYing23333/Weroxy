package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

var ErrUsername = errors.New("invalid username")

func ValidUsername(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func SetupPath(dir string) string { return filepath.Join(dir, "setup.secret") }

// SetupToken is persisted across restarts and is never sent by the status API.
func SetupToken(dir string) (string, error) {
	path := SetupPath(dir)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 64 {
			return "", errors.New("invalid setup credential file")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if !ValidSetupToken(string(b)) {
			return "", errors.New("invalid setup credential")
		}
		return string(b), nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		return SetupToken(dir)
	}
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(token)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return token, nil
}
func ValidSetupToken(value string) bool {
	if len(value) != 64 {
		return false
	}
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32
}
func SetupMatches(want, got string) bool {
	return ValidSetupToken(want) && ValidSetupToken(got) && subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}
