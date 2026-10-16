//go:build !windows

package config

import (
	"errors"
	"os"
)

func secureProfile(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("secret file is readable by group or others")
	}
	return nil
}

func restrictProfile(string) error { return nil }

func restrictReplacement(path, existing string) error { return restrictProfile(path) }
