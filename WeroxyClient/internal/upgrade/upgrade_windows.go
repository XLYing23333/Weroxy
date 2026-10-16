//go:build windows

// Package upgrade replaces a stopped Windows service executable with a
// verified offline candidate and restores the old binary on health failure.
package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"weroxy/client/internal/config"
	"weroxy/client/internal/status"
)

const maxBinary = 128 << 20

// Apply upgrades only the installed weroxycli service. The supplied SHA-256
// must come from a trusted channel; this function never downloads code.
func Apply(ctx context.Context, source, expectedHash, expectedVersion, configPath string) error {
	if source == "" || expectedVersion == "" || len(expectedHash) != 64 {
		return errors.New("Candidate file, version and full SHA-256 are required")
	}
	if _, err := hex.DecodeString(expectedHash); err != nil {
		return errors.New("Invalid SHA-256 format")
	}
	if !strings.EqualFold(filepath.Clean(configPath), filepath.Clean(status.InstalledConfigPath)) {
		return errors.New("Upgrade can only inspect the installed service configuration")
	}
	if _, err := config.Load(configPath); err != nil {
		return errors.New("Invalid service configuration permissions or contents")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return errors.New("Upgrade requires service manager administrator privileges")
	}
	defer manager.Disconnect()
	service, err := manager.OpenService("weroxycli")
	if err != nil {
		return errors.New("The weroxycli service is not installed")
	}
	defer service.Close()
	installed, err := service.Config()
	if err != nil {
		return err
	}
	dest := filepath.Join(filepath.Dir(status.InstalledConfigPath), "weroxy-client.exe")
	release, err := acquireLock(dest)
	if err != nil {
		return err
	}
	defer release()
	// Match the exact Service Manager command registered by install. A
	// modified executable path or extra argument must not be upgraded.
	registered := syscall.EscapeArg(dest) + " run --config " + syscall.EscapeArg(status.InstalledConfigPath)
	if !strings.EqualFold(installed.BinaryPathName, registered) {
		return errors.New("Service program path or arguments differ from the installation record")
	}
	runningExe, err := os.Executable()
	if err != nil {
		return err
	}
	old, err := os.Lstat(dest)
	if err != nil || !old.Mode().IsRegular() {
		return errors.New("Installed executable is not a regular file")
	}
	runningInfo, err := os.Stat(runningExe)
	if err != nil {
		return err
	}
	if strings.EqualFold(filepath.Clean(runningExe), filepath.Clean(dest)) || os.SameFile(runningInfo, old) {
		return errors.New("Run upgrade from a verified standalone Client executable")
	}
	rollbackPath := dest + ".rollback"
	if _, err := os.Lstat(rollbackPath); err == nil {
		return errors.New("Unresolved upgrade rollback files exist; inspect them first")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	state, err := service.Query()
	if err != nil || state.State != svc.Running {
		return errors.New("Service is not running; post-upgrade health cannot be verified")
	}
	stage, err := stageCandidate(ctx, source, dest, expectedHash, expectedVersion)
	if err != nil {
		return err
	}
	defer os.Remove(stage)
	// The caller's terminal may go away after the service stops. Continue the
	// replacement or rollback under a separate bounded context.
	critical, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := stopService(critical, service); err != nil {
		_ = service.Start()
		return errors.New("Unable to stop the Client service")
	}
	if err := os.Rename(dest, rollbackPath); err != nil {
		_ = service.Start()
		return err
	}
	if err := os.Rename(stage, dest); err != nil {
		return restoreService(service, dest, rollbackPath, err)
	}
	if err := service.Start(); err != nil {
		return restoreService(service, dest, rollbackPath, errors.New("Unable to start the new version"))
	}
	until := time.NewTimer(30 * time.Second)
	defer until.Stop()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		state, err := service.Query()
		if err == nil && state.State == svc.Running {
			if snap, ok := status.Read(status.Path(configPath)); ok && snap.Connected {
				previous := dest + ".previous"
				if err := os.Remove(previous); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("New version is healthy, but the previous backup could not be updated: %w", err)
				}
				if err := os.Rename(rollbackPath, previous); err != nil {
					return fmt.Errorf("New version is healthy, but the previous backup could not be saved: %w", err)
				}
				return nil
			}
		}
		if err == nil && state.State == svc.Stopped {
			return restoreService(service, dest, rollbackPath, errors.New("New version stopped unexpectedly"))
		}
		select {
		case <-ctx.Done():
			return restoreService(service, dest, rollbackPath, ctx.Err())
		case <-critical.Done():
			return restoreService(service, dest, rollbackPath, errors.New("Upgrade operation timed out"))
		case <-until.C:
			return restoreService(service, dest, rollbackPath, errors.New("New version control connection failed its health check"))
		case <-tick.C:
		}
	}
}

func stageCandidate(ctx context.Context, source, dest, expectedHash, expectedVersion string) (string, error) {
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBinary {
		return "", errors.New("Candidate must be a size-bounded regular file")
	}
	in, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.CreateTemp(filepath.Dir(dest), ".weroxy-client-upgrade-*.exe")
	if err != nil {
		return "", err
	}
	defer func() { _ = out.Close() }()
	defer func() {
		if err != nil {
			_ = os.Remove(out.Name())
		}
	}()
	if err = config.SetServiceBinaryACL(out.Name()); err != nil {
		return "", err
	}
	hash := sha256.New()
	var n int64
	n, err = io.Copy(io.MultiWriter(out, hash), io.LimitReader(in, maxBinary+1))
	if err != nil || n != info.Size() || n > maxBinary {
		err = errors.New("Unable to read candidate file or file changed")
		return "", err
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expectedHash) {
		err = errors.New("Candidate SHA-256 mismatch")
		return "", err
	}
	if err = out.Sync(); err != nil {
		return "", err
	}
	if err = out.Close(); err != nil {
		return "", err
	}
	versionCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	output, runErr := candidateVersion(versionCtx, out.Name())
	cancel()
	if runErr != nil || strings.TrimSpace(string(output)) != "weroxy-client "+expectedVersion {
		err = errors.New("Candidate version check failed")
		return "", err
	}
	return out.Name(), nil
}

func stopService(ctx context.Context, service *mgr.Service) error {
	state, err := service.Query()
	if err != nil {
		return err
	}
	if state.State == svc.Stopped {
		return nil
	}
	if state.State != svc.StopPending {
		if _, err := service.Control(svc.Stop); err != nil {
			return err
		}
	}
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		state, err := service.Query()
		if err != nil {
			return err
		}
		if state.State == svc.Stopped {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func restoreService(service *mgr.Service, dest, rollbackPath string, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := stopService(ctx, service); err != nil {
		return fmt.Errorf("Upgrade failed; unable to stop the new version for rollback: %w", err)
	}
	if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("Upgrade failed; unable to remove the new version for rollback: %w", err)
	}
	if err := os.Rename(rollbackPath, dest); err != nil {
		return fmt.Errorf("Upgrade and automatic rollback failed: %v: %w", cause, err)
	}
	if err := service.Start(); err != nil {
		return fmt.Errorf("Upgrade failed; previous version restored but could not start: %w", err)
	}
	return fmt.Errorf("Upgrade failed; previous version restored: %w", cause)
}
