//go:build linux

package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"weroxy/client/internal/config"
	"weroxy/client/internal/menu"
	"weroxy/client/internal/status"
)

const maxPackage = 128 << 20
const packageCache = "/var/cache/weroxy-client"

type packageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Format  string `json:"format"`
	Hash    string `json:"sha256"`
}

func packageFormat(path string) string {
	for _, ext := range []string{".pkg.tar.zst", ".deb", ".rpm"} {
		if strings.HasSuffix(path, ext) {
			return ext
		}
	}
	return ""
}
func packageCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out := &versionOutput{}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	e := cmd.Run()
	if out.exceeded {
		return "", errors.New("包信息超出上限")
	}
	return string(out.body), e
}
func readPackageInfo(ctx context.Context, path, format string, installed bool) (packageInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var text string
	var e error
	info := packageInfo{Format: format}
	switch format {
	case ".deb":
		if installed {
			text, e = packageCommand(ctx, "dpkg-query", "--show", "--showformat=${Package}\n${Version}\n${Architecture}\n", "weroxy-client")
		} else {
			text, e = packageCommand(ctx, "dpkg-deb", "--show", "--showformat=${Package}\n${Version}\n${Architecture}\n", path)
		}
	case ".rpm":
		if installed {
			text, e = packageCommand(ctx, "rpm", "-q", "--qf", "%{NAME}\n%{VERSION}-%{RELEASE}\n%{ARCH}\n", "weroxy-client")
		} else {
			text, e = packageCommand(ctx, "rpm", "-qp", "--qf", "%{NAME}\n%{VERSION}-%{RELEASE}\n%{ARCH}\n", path)
		}
	case ".pkg.tar.zst":
		if installed {
			text, e = packageCommand(ctx, "pacman", "-Qi", "weroxy-client")
			for _, line := range strings.Split(text, "\n") {
				k, v, ok := strings.Cut(line, ":")
				if !ok {
					continue
				}
				switch strings.TrimSpace(k) {
				case "Name":
					info.Name = strings.TrimSpace(v)
				case "Version":
					info.Version = strings.TrimSpace(v)
				case "Architecture":
					info.Arch = strings.TrimSpace(v)
				}
			}
		} else {
			text, e = packageCommand(ctx, "bsdtar", "-xOf", path, ".PKGINFO")
			for _, line := range strings.Split(text, "\n") {
				k, v, ok := strings.Cut(line, " = ")
				if !ok {
					continue
				}
				switch k {
				case "pkgname":
					info.Name = v
				case "pkgver":
					info.Version = v
				case "arch":
					info.Arch = v
				}
			}
		}
	default:
		return info, errors.New("只支持 deb/RPM/pacman 安装包")
	}
	if e != nil {
		return info, errors.New("不能读取本机包管理器中的安装包信息")
	}
	if format != ".pkg.tar.zst" {
		parts := strings.Split(strings.TrimSpace(text), "\n")
		if len(parts) != 3 {
			return info, errors.New("安装包元数据无效")
		}
		info.Name, info.Version, info.Arch = parts[0], parts[1], parts[2]
	}
	arch := runtime.GOARCH
	if format != ".deb" {
		if arch == "amd64" {
			arch = "x86_64"
		} else if arch == "arm64" {
			arch = "aarch64"
		}
	}
	if info.Name != "weroxy-client" || info.Arch != arch || info.Version == "" {
		return info, errors.New("包名、版本或架构不匹配")
	}
	return info, nil
}
func verifyPackage(ctx context.Context, source, hash, dest, format string) (packageInfo, error) {
	info := packageInfo{}
	if len(hash) != 64 {
		return info, errors.New("需要可信的完整 SHA-256")
	}
	if _, e := hex.DecodeString(hash); e != nil {
		return info, errors.New("SHA-256 格式无效")
	}
	// O_NOFOLLOW prevents a symlink from substituting the trusted candidate.
	fd, e := syscall.Open(source, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return info, errors.New("安装包不是可读取的普通文件")
	}
	f := os.NewFile(uintptr(fd), source)
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > maxPackage {
		return info, errors.New("安装包大小或类型无效")
	}
	out, e := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return info, e
	}
	defer out.Close()
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(out, h), io.LimitReader(f, maxPackage+1))
	if e != nil || n != st.Size() || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), hash) {
		return info, errors.New("安装包 SHA-256 不匹配或文件已改变")
	}
	if e = out.Sync(); e != nil {
		return info, e
	}
	if e = out.Close(); e != nil {
		return info, e
	}
	info, e = readPackageInfo(ctx, dest, format, false)
	info.Hash = strings.ToLower(hash)
	return info, e
}
func installPackage(ctx context.Context, path, format string) error {
	var cmd *exec.Cmd
	switch format {
	case ".deb":
		cmd = exec.CommandContext(ctx, "dpkg", "-i", path)
	case ".rpm":
		cmd = exec.CommandContext(ctx, "rpm", "-U", "--oldpackage", "--replacepkgs", path)
	case ".pkg.tar.zst":
		cmd = exec.CommandContext(ctx, "pacman", "-U", "--noconfirm", path)
	default:
		return errors.New("包格式无效")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = time.Second
	return cmd.Run()
}
func systemctl(ctx context.Context, args ...string) error {
	_, e := packageCommand(ctx, "systemctl", args...)
	return e
}
func waitConnected(ctx context.Context, configPath string) error {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		if snap, ok := status.Read(status.Path(configPath)); ok && snap.Connected {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("控制连接未恢复")
		case <-tick.C:
		}
	}
}
func ownedCache() error {
	if e := os.MkdirAll(packageCache, 0700); e != nil {
		return e
	}
	st, e := os.Lstat(packageCache)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("安装包缓存权限无效")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return errors.New("安装包缓存须由 root 拥有")
	}
	return nil
}

// ApplyPackage uses the native package database for both install and rollback.
func ApplyPackage(ctx context.Context, source, hash, version, configPath, previous, previousHash string) error {
	if os.Geteuid() != 0 {
		return errors.New("安装包升级需要 root 权限")
	}
	if filepath.Clean(configPath) != status.InstalledConfigPath {
		return errors.New("只能验证已安装服务配置")
	}
	if _, e := config.Load(configPath); e != nil {
		return errors.New("服务配置或凭据无效")
	}
	format := packageFormat(source)
	if format == "" {
		return errors.New("需要原生安装包")
	}
	if e := ownedCache(); e != nil {
		return e
	}
	release, e := acquireLock(packageCache + "/package")
	if e != nil {
		return e
	}
	defer release()
	work, e := os.MkdirTemp(packageCache, "upgrade-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	candidatePath := work + "/candidate" + format
	candidate, e := verifyPackage(ctx, source, hash, candidatePath, format)
	if e != nil {
		return e
	}
	expected := version
	if format != ".deb" {
		expected = strings.ReplaceAll(version, "-", ".") + "-1"
	}
	if candidate.Version != expected {
		return errors.New("候选安装包版本不匹配")
	}
	current, e := readPackageInfo(ctx, "", format, true)
	if e != nil {
		return e
	}
	if previous == "" {
		previous = packageCache + "/current" + format
		var record packageInfo
		b, e := os.ReadFile(packageCache + "/current.json")
		if e != nil || json.Unmarshal(b, &record) != nil {
			return errors.New("缺少可验证的上一版安装包；请提供上一版包与可信 SHA-256")
		}
		previousHash = record.Hash
	}
	oldPath := work + "/rollback" + format
	old, e := verifyPackage(ctx, previous, previousHash, oldPath, format)
	if e != nil {
		return fmt.Errorf("上一版包验证失败: %w", e)
	}
	if old.Version != current.Version {
		return errors.New("回滚包必须匹配当前已安装版本")
	}
	wasActive := systemctl(ctx, "is-active", "--quiet", menu.UnitName) == nil
	// No cancellation can strand a stopped service. Native package managers retain their own locks.
	critical, stop := context.WithTimeout(context.Background(), 3*time.Minute)
	defer stop()
	if wasActive {
		if e = systemctl(critical, "stop", menu.UnitName); e != nil {
			return errors.New("停止服务失败")
		}
	}
	rollback := func(cause error) error {
		critical, cancelRollback := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancelRollback()
		_ = systemctl(critical, "stop", menu.UnitName)
		if e := installPackage(critical, oldPath, format); e != nil {
			return fmt.Errorf("升级失败，旧安装包恢复失败: %w", cause)
		}
		_ = systemctl(critical, "daemon-reload")
		if wasActive {
			_ = systemctl(critical, "reset-failed", menu.UnitName)
			if e := systemctl(critical, "start", menu.UnitName); e != nil {
				return fmt.Errorf("旧服务启动失败: %w", cause)
			}
			health, cancel := context.WithTimeout(critical, 35*time.Second)
			e := waitConnected(health, configPath)
			cancel()
			if e != nil {
				return fmt.Errorf("旧包已恢复，控制连接未恢复: %w", cause)
			}
		}
		return fmt.Errorf("升级失败，已恢复旧安装包与服务状态: %w", cause)
	}
	if e = installPackage(critical, candidatePath, format); e != nil {
		return rollback(errors.New("安装候选包失败"))
	}
	_ = systemctl(critical, "daemon-reload")
	versionCtx, stopVersion := context.WithTimeout(critical, 3*time.Second)
	out, e := candidateVersion(versionCtx, menu.ServiceBinaryPath)
	stopVersion()
	if e != nil || strings.TrimSpace(string(out)) != "weroxy-client "+version {
		return rollback(errors.New("安装后程序版本检查失败"))
	}
	if wasActive {
		if e = systemctl(critical, "start", menu.UnitName); e != nil {
			return rollback(e)
		}
		health, cancel := context.WithTimeout(critical, 30*time.Second)
		e = waitConnected(health, configPath)
		cancel()
		if e != nil {
			return rollback(e)
		}
	}
	// The cache is bounded to current and previous packages; update records only after health succeeds.
	if e = os.Rename(oldPath, packageCache+"/previous"+format); e != nil {
		return e
	}
	if e = os.Rename(candidatePath, packageCache+"/current"+format); e != nil {
		return e
	}
	b, _ := json.Marshal(candidate)
	temp := packageCache + "/current.json.new"
	if e = os.WriteFile(temp, b, 0600); e != nil {
		return e
	}
	return os.Rename(temp, packageCache+"/current.json")
}

// Portable binary upgrades are no longer a Linux distribution interface.
func Apply(context.Context, string, string, string, string) error {
	return errors.New("Linux 升级请使用原生安装包 --package")
}
