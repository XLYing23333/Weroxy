package config

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// InitialProfile is a recognizable, secret-free profile awaiting TUI setup.
const InitialProfile = "# WeroxyClient: configure Host, Port and Key in the TUI.\n"

var ErrUnconfigured = errors.New("客户端尚未配置，请先在菜单中配置连接")

// DefaultUserPath never probes the private system service profile.
func DefaultUserPath() (string, error) {
	if runtime.GOOS == "windows" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "weroxy_client", "client.conf"), nil
	}
	if os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" && os.Getenv("SUDO_USER") != "root" {
		account, err := user.Lookup(os.Getenv("SUDO_USER"))
		if err != nil || !filepath.IsAbs(account.HomeDir) {
			return "", fmt.Errorf("无法确定 sudo 调用用户的主目录")
		}
		return filepath.Join(account.HomeDir, ".config", "weroxy_client", "client.conf"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		account, lookupErr := user.Current()
		if lookupErr != nil || !filepath.IsAbs(account.HomeDir) {
			return "", fmt.Errorf("无法确定当前用户的主目录")
		}
		home = account.HomeDir
	}
	return filepath.Join(home, ".config", "weroxy_client", "client.conf"), nil
}

// EnsureUserProfile creates only a new private profile; existing content stays intact.
func EnsureUserProfile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("配置目录必须是普通目录")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return statErr
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("已有配置必须是权限 0600 的普通文件")
		}
		return EnsureProfileOwner(path)
	}
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(InitialProfile)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return EnsureProfileOwner(path)
}

// EnsureProfileOwner restores the invoking user's ownership after sudo setup.
func EnsureProfileOwner(path string) error {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 || os.Getenv("SUDO_USER") == "" || os.Getenv("SUDO_USER") == "root" {
		return nil
	}
	account, err := user.Lookup(os.Getenv("SUDO_USER"))
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	cfg, err := Load(path)
	if err != nil && !errors.Is(err, ErrUnconfigured) {
		return err
	}
	for _, item := range []string{filepath.Dir(path), path, cfg.KeyPath} {
		if item == "" {
			continue
		}
		if item == cfg.KeyPath && filepath.Dir(item) != filepath.Dir(path) {
			continue
		}
		info, e := os.Lstat(item)
		if e != nil {
			return e
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("配置不能使用符号链接")
		}
		if e = os.Chown(item, uid, gid); e != nil {
			return e
		}
	}
	return nil
}

// Purge removes only a named profile and its own generated files, never other profiles.
func Purge(path string) error {
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("配置必须是普通文件")
	}
	dir := filepath.Dir(path)
	dirInfo, err := os.Lstat(dir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("配置目录必须是普通目录")
	}
	cfg, _ := Load(path)
	files := []string{path, filepath.Join(dir, "weroxy-client.status")}
	if filepath.Base(dir) == "weroxy_client" || dir == "/etc/weroxycli" {
		files = append(files, filepath.Join(dir, "weroxy-tls.crt"), filepath.Join(dir, "client.key"))
	}
	if cfg.KeyPath != "" && filepath.Clean(filepath.Dir(cfg.KeyPath)) == dir {
		files = append(files, cfg.KeyPath)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if (filepath.Base(dir) == "weroxy_client" || dir == "/etc/weroxycli") && strings.HasPrefix(name, ".weroxy-key-") || strings.HasPrefix(name, filepath.Base(path)+".repair-") {
			files = append(files, filepath.Join(dir, name))
		}
	}
	for _, item := range files {
		if err := os.Remove(item); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	// Remove the directory only if it is now empty.
	_ = os.Remove(dir)
	return nil
}
