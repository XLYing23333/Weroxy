// Package cli implements the weroxy-Server command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	notices "weroxy/server"

	"weroxy/server/internal/auth"
	"weroxy/server/internal/buildinfo"
	"weroxy/server/internal/firewallagent"
	"weroxy/server/internal/logging"
	"weroxy/server/internal/server"
	"weroxy/server/internal/storage/sqlite"
)

// Option carries process inputs so tests can avoid the real terminal.
type Option struct {
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	IsTerminal bool
	TermRead   func() ([]byte, error)
}

// Run executes one invocation and returns the process status.
func Run(args []string, opt Option) int {
	if opt.Stdout == nil {
		opt.Stdout = os.Stdout
	}
	if opt.Stderr == nil {
		opt.Stderr = os.Stderr
	}
	if opt.Stdin == nil {
		opt.Stdin = os.Stdin
	}
	for _, arg := range args {
		if arg == "--password" || strings.HasPrefix(arg, "--password=") {
			fmt.Fprintln(opt.Stderr, "已拒绝 --password。请使用终端输入、--password-file 或标准输入。")
			return 2
		}
		if arg == "--key" || strings.HasPrefix(arg, "--key=") || arg == "--token" || strings.HasPrefix(arg, "--token=") {
			fmt.Fprintln(opt.Stderr, "已拒绝在命令参数中提供 Key 或 Token。")
			return 2
		}
	}
	for _, arg := range args {
		for _, removed := range []string{"--legacy-tls-listen", "--legacy-tls-cert", "--legacy-tls-key", "--web-cert", "--web-key", "--tls-ca", "--tls-name"} {
			if arg == removed || strings.HasPrefix(arg, removed+"=") {
				fmt.Fprintln(opt.Stderr, "TLS/HTTPS options are not supported. Weroxy v2 uses Noise for Control and Data binding; Web remains HTTP. Upgrade both components together.")
				return 2
			}
		}
	}
	if len(args) == 0 {
		args = []string{"run"}
	}
	switch args[0] {
	case "notices":
		if len(args) != 1 {
			return 2
		}
		fmt.Fprint(opt.Stdout, notices.Text())
		return 0
	case "version":
		sqliteVersion, driverVersion, err := sqlite.Probe()
		if err != nil {
			fmt.Fprintf(opt.Stderr, "sqlite: %v\n", err)
			return 1
		}
		fmt.Fprintf(opt.Stdout, "weroxy-Server %s\ngo %s\nsqlite %s\nmodernc.org/sqlite %s\n",
			buildinfo.Version, runtime.Version(), sqliteVersion, driverVersion)
		return 0
	case "health":
		return healthCommand(args[1:], opt)
	case "run":
		data, err := flagValue(args[1:], "data", "/data")
		if err != nil {
			fmt.Fprintln(opt.Stderr, err)
			return 2
		}
		legacyListen, err := flagValue(args[1:], "legacy-listen", "")
		if err != nil {
			fmt.Fprintln(opt.Stderr, err)
			return 2
		}
		weroxyControl, err := flagValue(args[1:], "weroxy-control", "")
		if err != nil {
			fmt.Fprintln(opt.Stderr, err)
			return 2
		}
		weroxyData, err := flagValue(args[1:], "weroxy-data", "")
		if err != nil {
			fmt.Fprintln(opt.Stderr, err)
			return 2
		}
		quickList, err := flagValue(args[1:], "quick-list", "")
		if err != nil {
			fmt.Fprintln(opt.Stderr, err)
			return 2
		}
		quickAllow, err := flagValue(args[1:], "quick-allow", "")
		if err != nil {
			fmt.Fprintln(opt.Stderr, err)
			return 2
		}
		web, err := flagValue(args[1:], "web", "")
		if err != nil {
			fmt.Fprintln(opt.Stderr, err)
			return 2
		}
		drainRaw, err := flagValue(args[1:], "drain-timeout", "20s")
		if err != nil {
			fmt.Fprintln(opt.Stderr, err)
			return 2
		}
		drain, err := time.ParseDuration(drainRaw)
		if err != nil || drain < time.Second || drain > 5*time.Minute {
			fmt.Fprintln(opt.Stderr, "drain-timeout must be between 1s and 5m")
			return 2
		}
		var allow []string
		if quickAllow != "" {
			allow = strings.Split(quickAllow, ",")
		}
		return runServe(data, legacyListen, weroxyControl, weroxyData, quickList, allow, web, drain, opt)
	case "legacy":
		return legacyCommand(args[1:], opt)
	case "migrate":
		return migrateCommand(args[1:], opt)
	case "firewall-plan":
		return firewallPlanCommand(args[1:], opt)
	case "firewall-agent":
		configPath, err := flagValue(args[1:], "config", "/etc/weroxy/firewall-agent.json")
		if err != nil {
			fmt.Fprintln(opt.Stderr, err)
			return 2
		}
		cfg, err := firewallagent.LoadConfig(configPath)
		if err != nil {
			fmt.Fprintln(opt.Stderr, err)
			return 1
		}
		if flagPresent(args[1:], "check") {
			fmt.Fprintln(opt.Stdout, "firewall-agent config valid")
			return 0
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := firewallagent.Run(ctx, cfg); err != nil {
			fmt.Fprintln(opt.Stderr, err)
			return 1
		}
		return 0
	case "weroxy":
		return weroxyCommand(args[1:], opt)
	case "admin":
		if len(args) < 2 {
			fmt.Fprintln(opt.Stderr, "usage: weroxy-Server admin bootstrap|reset-password")
			return 2
		}
		switch args[1] {
		case "bootstrap":
			return admin(args[2:], opt, true)
		case "reset-password":
			return admin(args[2:], opt, false)
		default:
			fmt.Fprintln(opt.Stderr, "usage: weroxy-Server admin bootstrap|reset-password")
			return 2
		}
	default:
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server run|version|notices|admin bootstrap|admin reset-password|legacy device add|legacy forward add|weroxy device add|weroxy forward add|weroxy device revoke|weroxy pool set|weroxy policy set|weroxy capacity")
		return 2
	}
}

func runServe(data, legacyListen, weroxyControl, weroxyData, quickList string, quickAllow []string, web string, drain time.Duration, opt Option) int {
	log := logging.New(logging.Options{Dir: filepath.Join(data, "logs"), Err: opt.Stderr})
	defer log.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := server.Start(ctx, server.Config{
		DataDir: data, Log: log, LegacyListen: legacyListen,
		WeroxyControl: weroxyControl, WeroxyData: weroxyData,
		QuickList: quickList, QuickAllow: quickAllow, Web: web, DrainTimeout: drain,
	}); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 1
	}
	return 0
}

func admin(args []string, opt Option, bootstrap bool) int {
	data, err := flagValue(args, "data", "/data")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err)
		return 2
	}
	username, err := flagValue(args, "username", "admin")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err)
		return 2
	}
	file, err := flagValue(args, "password-file", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err)
		return 2
	}
	if err := server.Writable(data); err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 1
	}
	log := logging.New(logging.Options{Dir: filepath.Join(data, "logs"), Err: opt.Stderr})
	defer log.Close()
	db, err := sqlite.Open(filepath.Join(data, "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 1
	}
	defer db.Close()
	ctx := context.Background()
	password, err := auth.ReadPassword(file, opt.Stdin, opt.IsTerminal, opt.TermRead)
	if err != nil {
		_ = db.RecordAudit(ctx, action(bootstrap), "failure", "password input rejected")
		fmt.Fprintln(opt.Stderr, passwordError(err))
		return 1
	}
	hasher := auth.NewArgon()
	if bootstrap {
		err = db.Bootstrap(ctx, hasher, username, password)
	} else {
		err = db.ResetPassword(ctx, hasher, username, password)
	}
	zero(password)
	if err != nil {
		log.Error("administrator update failed", map[string]string{"action": action(bootstrap)})
		fmt.Fprintln(opt.Stderr, adminError(err))
		return 1
	}
	log.Info("administrator updated", map[string]string{"action": action(bootstrap), "username": username})
	if bootstrap {
		fmt.Fprintln(opt.Stdout, "管理员已创建。")
	} else {
		fmt.Fprintln(opt.Stdout, "密码已更新。")
	}
	return 0
}

func passwordError(err error) string {
	switch {
	case errors.Is(err, auth.ErrPasswordFile):
		return "密码文件不存在，或可被同组及其他用户读取。"
	case errors.Is(err, auth.ErrPasswordLength):
		return "密码长度必须在 6 到 1024 字节之间。"
	case errors.Is(err, auth.ErrHashBusy):
		return "密码哈希繁忙，请稍后重试。"
	default:
		return "未能读取密码。"
	}
}

func adminError(err error) string {
	switch {
	case errors.Is(err, sqlite.ErrAdminExists):
		return "管理员已存在。"
	case errors.Is(err, sqlite.ErrNoAdmin):
		return "管理员不存在。"
	case errors.Is(err, sqlite.ErrQueueFull), errors.Is(err, sqlite.ErrDatabaseBusy):
		return "数据库繁忙或写入队列已满，未修改管理员。"
	case errors.Is(err, auth.ErrPasswordLength):
		return "密码长度必须在 6 到 1024 字节之间。"
	case errors.Is(err, auth.ErrHashBusy):
		return "密码哈希繁忙，请稍后重试。"
	default:
		return "未能更新管理员。"
	}
}

func action(bootstrap bool) string {
	if bootstrap {
		return "bootstrap"
	}
	return "reset_password"
}

func zero(password []byte) {
	for i := range password {
		password[i] = 0
	}
}

func flagValue(args []string, name, fallback string) (string, error) {
	prefix := "--" + name
	found := false
	value := fallback
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == prefix {
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", prefix)
			}
			found = true
			value = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(arg, prefix+"=") {
			found = true
			value = strings.TrimPrefix(arg, prefix+"=")
			continue
		}
		if strings.HasPrefix(arg, "--") && arg != prefix {
			known := map[string]bool{
				"--data": true, "--config": true, "--username": true, "--password-file": true,
				"--legacy-listen": true, "--name": true, "--key-file": true,
				"--ttl": true, "--device": true, "--listen": true, "--target": true,
				"--weroxy-control": true, "--weroxy-data": true,
				"--quick-list": true, "--quick-allow": true,
				"--mode": true, "--min": true, "--preferred": true, "--max": true,
				"--scope": true, "--max-pending": true,
				"--max-per-ip": true, "--rate": true, "--burst": true, "--cidr": true,
				"--forward-pool": true, "--data-pool": true, "--reserved": true,
				"--bind-host": true, "--use-reserved": true, "--import": true,
				"--max-data-ports": true, "--web": true,
				"--file": true, "--dry-run": true, "--apply": true,
				"--url": true, "--check": true,
				"--web-cert": true, "--web-key": true, "--allow-ports": true, "--drain-timeout": true,
			}
			key := arg
			if eq := strings.IndexByte(arg, '='); eq >= 0 {
				key = arg[:eq]
			}
			if !known[key] {
				return "", fmt.Errorf("unknown flag %s", key)
			}
		}
	}
	_ = found
	if name == "username" && !validUsername(value) {
		return "", fmt.Errorf("invalid username")
	}
	return value, nil
}

func validUsername(name string) bool { return auth.ValidUsername(name) }
