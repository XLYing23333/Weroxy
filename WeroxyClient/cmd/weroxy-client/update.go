package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"weroxy/client/internal/buildinfo"
	"weroxy/client/internal/release"
)

func installedPackage(ctx context.Context) (string, string, error) {
	checks := []struct {
		cmd  string
		args []string
		ext  string
	}{
		{"dpkg-query", []string{"-W", "-f=${Version}", "weroxy-client"}, ".deb"},
		{"rpm", []string{"-q", "--qf", "%{VERSION}", "weroxy-client"}, ".rpm"},
		{"pacman", []string{"-Q", "weroxy-client"}, ".pkg.tar.zst"},
	}
	for _, c := range checks {
		b, e := exec.CommandContext(ctx, c.cmd, c.args...).Output()
		if e != nil {
			continue
		}
		v := strings.TrimSpace(string(b))
		if c.cmd == "pacman" {
			fields := strings.Fields(v)
			if len(fields) != 2 {
				continue
			}
			v = strings.TrimSuffix(fields[1], "-1")
		}
		v = strings.TrimSuffix(v, "-1")
		if _, e = release.Version(v); e == nil {
			return c.ext, v, nil
		}
	}
	return "", "", errors.New("No supported installed Client package found")
}
func clientAsset(version, format string) string {
	arch := runtime.GOARCH
	if format == ".deb" {
		return "weroxy-client_" + version + "_" + arch + format
	}
	if arch == "amd64" {
		arch = "x86_64"
	} else if arch == "arm64" {
		arch = "aarch64"
	}
	if format == ".rpm" {
		return "weroxy-client-" + version + "-1." + arch + format
	}
	return "weroxy-client-" + version + "-1-" + arch + format
}
func runUpdate() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := updateClient(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
func updateClient(ctx context.Context) error {
	fmt.Println("Checking GitHub releases...")
	r, e := release.Check(ctx, "")
	if e != nil {
		return e
	}
	fmt.Printf("Current: %s\nLatest: %s\n%s\n", buildinfo.Version, r.Tag, r.URL)
	if !release.Newer(r.Tag, buildinfo.Version) {
		fmt.Println("No newer stable release available.")
		return nil
	}
	if runtime.GOOS != "linux" {
		return errors.New("No automatic update package is published for this platform")
	}
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	format, old, e := installedPackage(probe)
	if e != nil {
		return e
	}
	version := strings.TrimPrefix(r.Tag, "v")
	name := clientAsset(version, format)
	if _, e = r.Asset(name); e != nil {
		return e
	}
	fmt.Println("Update restarts the installed Client and interrupts its connections. Continue? [y/N]")
	answer, e := bufio.NewReader(commandStdin).ReadString('\n')
	if e != nil {
		return e
	}
	if !strings.EqualFold(strings.TrimSpace(answer), "y") {
		fmt.Println("Cancelled.")
		return nil
	}
	dir, e := os.MkdirTemp("", "weroxy-update-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	path, hash, e := r.Download(ctx, name, dir, 128<<20)
	if e != nil {
		return e
	}
	candidate := filepath.Join(dir, name)
	if e = os.Rename(path, candidate); e != nil {
		return e
	}
	previous, e := release.Check(ctx, old)
	if e != nil {
		return e
	}
	oldName := clientAsset(old, format)
	oldPath, oldHash, e := previous.Download(ctx, oldName, dir, 128<<20)
	if e != nil {
		return e
	}
	rollback := filepath.Join(dir, oldName)
	if e = os.Rename(oldPath, rollback); e != nil {
		return e
	}
	// The existing privilege handoff cannot read a user-owned temporary directory
	// after a different identity substitutes it. Copy/verification and locking are
	// performed by ApplyPackage before invoking the package manager.
	if code := runUpgrade([]string{"--package", candidate, "--sha256", hash, "--version", version, "--previous-package", rollback, "--previous-sha256", oldHash}); code != 0 {
		return errors.New("Client update failed; review upgrade diagnostics")
	}
	fmt.Println("Client updated successfully.")
	return nil
}
