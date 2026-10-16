//go:build windows

// Package status exposes bounded snapshots over a local, ACL-restricted pipe.
package status

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Snapshot struct {
	State     string
	Connected bool
	Up        uint64
	Down      uint64
}

var InstalledConfigPath = installedConfigPath()

const InstalledStatusPath = `\\.\pipe\weroxycli-service`

func installedConfigPath() string {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return `C:\ProgramData\WeroxyCli\client.conf`
	}
	return filepath.Join(base, "WeroxyCli", "client.conf")
}

func Path(configPath string) string {
	if strings.EqualFold(filepath.Clean(configPath), filepath.Clean(InstalledConfigPath)) {
		return InstalledStatusPath
	}
	absolute, err := filepath.Abs(configPath)
	if err != nil {
		absolute = configPath
	}
	key := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(absolute))))
	return `\\.\pipe\weroxycli-` + hex.EncodeToString(key[:8])
}

func Listen(path string, current func() Snapshot) (func(), error) {
	if !strings.HasPrefix(path, `\\.\pipe\weroxycli-`) {
		return nil, fmt.Errorf("invalid Weroxy status pipe")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)(A;;GR;;;" + user.User.Sid.String() + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	attributes := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	first, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_OUTBOUND|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1, 512, 0, 5000, attributes)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	active := first
	done := make(chan struct{})
	var once sync.Once
	go func() {
		handle := first
		for {
			if handle == windows.InvalidHandle {
				return
			}
			mu.Lock()
			active = handle
			mu.Unlock()
			err := windows.ConnectNamedPipe(handle, nil)
			select {
			case <-done:
				windows.CloseHandle(handle)
				return
			default:
			}
			if err == nil || err == windows.ERROR_PIPE_CONNECTED {
				snap := current()
				flag := 0
				if snap.Connected {
					flag = 1
				}
				file := os.NewFile(uintptr(handle), path)
				_, _ = fmt.Fprintf(file, "connected=%d up=%d down=%d state=%s\n", flag, snap.Up, snap.Down, SafeState(snap.State))
				_ = file.Close()
			} else {
				windows.CloseHandle(handle)
			}
			mu.Lock()
			if active == handle {
				active = windows.InvalidHandle
			}
			mu.Unlock()
			select {
			case <-done:
				return
			default:
			}
			for {
				handle, err = windows.CreateNamedPipe(name, windows.PIPE_ACCESS_OUTBOUND|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
					windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
					1, 512, 0, 5000, attributes)
				if err == nil {
					break
				}
				select {
				case <-done:
					return
				case <-time.After(100 * time.Millisecond):
				}
			}
		}
	}()
	closePipe := func() {
		once.Do(func() {
			close(done)
			// ConnectNamedPipe is synchronous. A local read opens the pipe and
			// wakes it so the serving goroutine can close its own handle.
			wake, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
			if err == nil {
				windows.CloseHandle(wake)
			} else {
				mu.Lock()
				handle := active
				mu.Unlock()
				if handle != windows.InvalidHandle {
					_ = windows.CancelIoEx(handle, nil)
				}
			}
		})
	}
	return closePipe, nil
}

func Read(path string) (Snapshot, bool) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Snapshot{}, false
	}
	until := time.Now().Add(2 * time.Second)
	var handle windows.Handle
	for {
		handle, err = windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			break
		}
		if time.Now().After(until) || err != windows.ERROR_PIPE_BUSY {
			return Snapshot{}, false
		}
		time.Sleep(25 * time.Millisecond)
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	lineCh := make(chan string, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(file, 256)).ReadString('\n')
		if err == nil {
			lineCh <- line
		} else {
			lineCh <- ""
		}
	}()
	var line string
	select {
	case line = <-lineCh:
	case <-time.After(2 * time.Second):
		_ = windows.CancelIoEx(handle, nil)
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
			snap.Connected = value == "1"
			seen[key] = true
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
