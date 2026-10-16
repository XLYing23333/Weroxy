package harden

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

func lock() (func(), error) {
	if e := regular(base); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(base, 0700); e != nil {
		return nil, e
	}
	if e := trustedDirectory(base); e != nil {
		return nil, e
	}
	p := base + "/operation.lock"
	if e := regular(p); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("Another hardening operation is running")
	}
	return func() { f.Close() }, nil
}

func trustedExecutable(path string) error {
	st, e := os.Stat(path)
	if e != nil {
		return e
	}
	raw, ok := st.Sys().(*syscall.Stat_t)
	if !ok || raw.Uid != 0 || st.Mode().Perm()&0022 != 0 {
		return errors.New("Rollback executable must be root-owned and not writable by others; install the native package first")
	}
	return nil
}

func trustedDirectory(path string) error {
	st, e := os.Stat(path)
	if e != nil {
		return e
	}
	raw, ok := st.Sys().(*syscall.Stat_t)
	if !ok || raw.Uid != 0 || st.Mode().Perm()&0022 != 0 {
		return errors.New("Backup directory must be root-owned and not writable by others")
	}
	return nil
}
