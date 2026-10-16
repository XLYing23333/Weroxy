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
		return errors.New("缺少候选文件、版本或完整 SHA-256")
	}
	if _, err := hex.DecodeString(expectedHash); err != nil {
		return errors.New("SHA-256 格式无效")
	}
	if !strings.EqualFold(filepath.Clean(configPath), filepath.Clean(status.InstalledConfigPath)) {
		return errors.New("升级只能检查已安装服务的配置")
	}
	if _, err := config.Load(configPath); err != nil {
		return errors.New("服务配置权限或内容无效")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return errors.New("升级需要 Service Manager 管理员权限")
	}
	defer manager.Disconnect()
	service, err := manager.OpenService("weroxycli")
	if err != nil {
		return errors.New("weroxycli 服务未安装")
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
		return errors.New("服务程序路径或参数与安装记录不符")
	}
	runningExe, err := os.Executable()
	if err != nil {
		return err
	}
	old, err := os.Lstat(dest)
	if err != nil || !old.Mode().IsRegular() {
		return errors.New("已安装程序不是普通文件")
	}
	runningInfo, err := os.Stat(runningExe)
	if err != nil {
		return err
	}
	if strings.EqualFold(filepath.Clean(runningExe), filepath.Clean(dest)) || os.SameFile(runningInfo, old) {
		return errors.New("请从已验证的独立客户端程序运行升级命令")
	}
	rollbackPath := dest + ".rollback"
	if _, err := os.Lstat(rollbackPath); err == nil {
		return errors.New("存在未处理的升级回滚文件；请先人工检查")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	state, err := service.Query()
	if err != nil || state.State != svc.Running {
		return errors.New("服务未运行，无法做升级后健康验证")
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
		return errors.New("停止客户端服务失败")
	}
	if err := os.Rename(dest, rollbackPath); err != nil {
		_ = service.Start()
		return err
	}
	if err := os.Rename(stage, dest); err != nil {
		return restoreService(service, dest, rollbackPath, err)
	}
	if err := service.Start(); err != nil {
		return restoreService(service, dest, rollbackPath, errors.New("新版本启动失败"))
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
					return fmt.Errorf("新版本运行正常，但无法更新上一版备份: %w", err)
				}
				if err := os.Rename(rollbackPath, previous); err != nil {
					return fmt.Errorf("新版本运行正常，但无法保存上一版备份: %w", err)
				}
				return nil
			}
		}
		if err == nil && state.State == svc.Stopped {
			return restoreService(service, dest, rollbackPath, errors.New("新版本意外停止"))
		}
		select {
		case <-ctx.Done():
			return restoreService(service, dest, rollbackPath, ctx.Err())
		case <-critical.Done():
			return restoreService(service, dest, rollbackPath, errors.New("升级操作超时"))
		case <-until.C:
			return restoreService(service, dest, rollbackPath, errors.New("新版本控制连接未通过健康检查"))
		case <-tick.C:
		}
	}
}

func stageCandidate(ctx context.Context, source, dest, expectedHash, expectedVersion string) (string, error) {
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBinary {
		return "", errors.New("候选文件必须是大小有界的普通文件")
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
		err = errors.New("读取候选文件失败或文件已改变")
		return "", err
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expectedHash) {
		err = errors.New("候选文件 SHA-256 不匹配")
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
		err = errors.New("候选文件版本检查失败")
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
		return fmt.Errorf("升级失败且无法停止新版本以回滚: %w", err)
	}
	if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("升级失败且无法移除新版本以回滚: %w", err)
	}
	if err := os.Rename(rollbackPath, dest); err != nil {
		return fmt.Errorf("升级失败且自动回滚失败: %v: %w", cause, err)
	}
	if err := service.Start(); err != nil {
		return fmt.Errorf("升级失败，旧版本已恢复但启动失败: %w", err)
	}
	return fmt.Errorf("升级失败，已恢复上一版: %w", cause)
}
