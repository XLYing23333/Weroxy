//go:build !windows

// Package status exposes the running client's connection and byte counters
// on a local socket. A missing socket means the process is not running.
package status

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Snapshot is one reading from the running client.
type Snapshot struct {
	State     string
	Connected bool
	Up        uint64
	Down      uint64
}

const InstalledConfigPath = "/etc/weroxycli/client.conf"
const InstalledStatusPath = "/run/weroxycli/weroxy-client.status"

// Path is next to a foreground profile, or under systemd's RuntimeDirectory
// for the installed service's root-owned profile directory.
func Path(configPath string) string {
	if filepath.Clean(configPath) == InstalledConfigPath {
		return InstalledStatusPath
	}
	return filepath.Join(filepath.Dir(configPath), "weroxy-client.status")
}

// Listen serves snapshots until close is called.
func Listen(path string, current func() Snapshot) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("status path is not a socket")
		}
		probe, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			probe.Close()
			return nil, fmt.Errorf("status socket already in use")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("cannot verify stale status socket")
		}
		again, err := os.Lstat(path)
		if err != nil || !os.SameFile(info, again) {
			return nil, fmt.Errorf("status socket changed")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(false)
	socketInfo, err := os.Lstat(path)
	if err != nil {
		ln.Close()
		return nil, err
	}
	cleanup := func() {
		if info, err := os.Lstat(path); err == nil && os.SameFile(socketInfo, info) {
			_ = os.Remove(path)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		cleanup()
		return nil, err
	}
	var once sync.Once
	var mu sync.Mutex
	stopped := false
	active := make(map[net.Conn]struct{})
	slots := make(chan struct{}, 8)
	closeLn := func() {
		once.Do(func() {
			ln.Close()
			mu.Lock()
			stopped = true
			for conn := range active {
				conn.Close()
			}
			mu.Unlock()
			cleanup()
		})
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				conn.Close()
				continue
			}
			mu.Lock()
			if stopped {
				mu.Unlock()
				conn.Close()
				<-slots
				return
			}
			active[conn] = struct{}{}
			mu.Unlock()
			go func() {
				defer func() {
					conn.Close()
					mu.Lock()
					delete(active, conn)
					mu.Unlock()
					<-slots
				}()
				if conn.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
					return
				}
				snap := current()
				flag := 0
				if snap.Connected {
					flag = 1
				}
				_, _ = fmt.Fprintf(conn, "connected=%d up=%d down=%d state=%s\n", flag, snap.Up, snap.Down, SafeState(snap.State))
			}()
		}
	}()
	return closeLn, nil
}

// Read dials the socket. ok is false when the process is not listening.
func Read(path string) (Snapshot, bool) {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return Snapshot{}, false
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(conn, 256)).ReadString('\n')
	if err != nil {
		return Snapshot{}, false
	}
	var snap Snapshot
	seen := map[string]bool{}
	for _, field := range strings.Fields(line) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch key {
		case "state":
			snap.State = SafeState(value)
		case "connected":
			if value != "0" && value != "1" {
				return Snapshot{}, false
			}
			seen[key] = true
			snap.Connected = value == "1"
		case "up":
			snap.Up, err = strconv.ParseUint(value, 10, 64)
			if err != nil {
				return Snapshot{}, false
			}
			seen[key] = true
		case "down":
			snap.Down, err = strconv.ParseUint(value, 10, 64)
			if err != nil {
				return Snapshot{}, false
			}
			seen[key] = true
		}
	}
	return snap, seen["connected"] && seen["up"] && seen["down"]
}
