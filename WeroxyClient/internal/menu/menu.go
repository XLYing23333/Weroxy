// Package menu provides the native Linux Client terminal menu.
package menu

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"weroxy/client/internal/config"
	"weroxy/client/internal/status"
)

const UnitName = "weroxycli.service"
const UnitPath = "/usr/lib/systemd/system/weroxycli.service"
const ServiceBinaryPath = "/usr/bin/weroxy-client"

var ServiceConfigPath = status.InstalledConfigPath

type System interface {
	HasSudo(context.Context) bool
	Active(context.Context) (string, error)
	Enabled(context.Context) (string, error)
	EnsureUser(context.Context) error
	Install(context.Context, string, string, string) error
	DaemonReload(context.Context) error
	Enable(context.Context) error
	Disable(context.Context) error
	Start(context.Context) error
	Stop(context.Context) error
	Restart(context.Context) error
	Installed(context.Context) bool
	Remove(context.Context) error
	Uninstall(context.Context, string) error
}

type Terminal interface {
	Key(context.Context) (string, error)
	Size() (int, int)
	Pause() error
	Resume() error
	Close() error
}
type Option struct {
	Action     func(string, []string) int
	ConfigPath string
	Binary     string
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	System     System
	Terminal   Terminal
}

func UnitText(binary, path string) string {
	return "[Unit]\nDescription=Weroxy client\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nUser=weroxy\nGroup=weroxy\nRuntimeDirectory=weroxycli\nRuntimeDirectoryMode=0700\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nExecStart=" + strconv.Quote(binary) + " run --config " + strconv.Quote(path) + "\nRestart=on-failure\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n"
}

var entries = []string{"profile", "start/restart", "stop", "status", "开机自启", "doctor", "主机加固", "uninstall"}

func Run(ctx context.Context, opt Option) int {
	if opt.Stdin == nil {
		opt.Stdin = os.Stdin
	}
	if opt.Stdout == nil {
		opt.Stdout = os.Stdout
	}
	if opt.Stderr == nil {
		opt.Stderr = os.Stderr
	}
	if opt.System == nil {
		opt.System = realSystem{}
	}
	if opt.Binary == "" {
		opt.Binary, _ = os.Executable()
	}
	term := opt.Terminal
	if term == nil {
		var err error
		term, err = openTerminal(opt.Stdin, opt.Stdout)
		if err != nil {
			fmt.Fprintln(opt.Stdout, "weroxy-client: interactive terminal required. Use: menu | init | run | status | doctor | service <start|restart|stop|enable|disable|status> --config <path>")
			return 0
		}
	}
	defer term.Close()
	selected := 0
	submenu := false
	message := "选择 profile 配置 Host、Port、Key，然后 start/restart。"
	success := true
	for ctx.Err() == nil {
		options := entries
		if submenu {
			options = []string{"enable", "disable"}
		}
		draw(opt.Stdout, term, opt, options, selected, message, success)
		key, err := term.Key(ctx)
		if err != nil {
			break
		}
		switch key {
		case "up":
			selected = (selected + len(options) - 1) % len(options)
		case "down":
			selected = (selected + 1) % len(options)
		case "esc", "q":
			if submenu {
				submenu = false
				selected = 4
			} else {
				return 0
			}
		case "enter":
			rows, cols := term.Size()
			if rows < 12 || cols < 32 {
				continue
			}
			action := options[selected]
			if action == "开机自启" {
				submenu = true
				selected = 0
				continue
			}
			if action == "profile" {
				message, err = editProfile(ctx, term, opt)
				success = err == nil
				if err != nil {
					message = err.Error()
				}
				continue
			}
			if action == "status" {
				message = strings.Join(statusLines(ctx, opt), "\n")
				success = true
				continue
			}
			if err = term.Pause(); err != nil {
				return 1
			}
			if action == "主机加固" {
				if opt.Action != nil {
					reader := bufio.NewReader(opt.Stdin)
					fmt.Fprintln(opt.Stdout, "1 风险检测  2 SSH 加固  3 登录防护安装/配置  4 dry-run  5 回滚")
					choice, _ := reader.ReadString('\n')
					choice = strings.TrimSpace(choice)
					values := []string{"status"}
					switch choice {
					case "2":
						values = []string{"ssh"}
					case "3":
						values = []string{"fail2ban"}
					case "4":
						values = []string{"ssh", "--dry-run"}
					case "5":
						fmt.Fprintln(opt.Stdout, "操作编号（Enter 使用最近一次）：")
						id, _ := reader.ReadString('\n')
						values = []string{"rollback"}
						if strings.TrimSpace(id) != "" {
							values = append(values, strings.TrimSpace(id))
						}
					}
					success = opt.Action("harden", values) == 0
					message = "主机助手结束。"
				}
			} else if action == "doctor" {
				if opt.Action != nil {
					code := opt.Action("doctor", nil)
					success = code == 0
					message = "诊断完成。"
					if !success {
						message = "诊断未通过，请查看上述原因。"
					}
				}
			} else {
				message, err = apply(ctx, opt, action)
				success = err == nil
				if err != nil {
					message = "失败：" + err.Error()
				}
			}
			if action == "uninstall" && success {
				fmt.Fprintln(opt.Stdout, message)
				return 0
			}
			fmt.Fprintln(opt.Stdout, message, "\n按 Enter 返回菜单。")
			// Resume before waiting so cancellation and resize remain available.
			if err = term.Resume(); err != nil {
				return 1
			}
			for {
				key, err = term.Key(ctx)
				if err != nil || key == "enter" || key == "esc" {
					break
				}
			}
		}
	}
	return 0
}

func draw(out io.Writer, t Terminal, opt Option, options []string, selected int, message string, success bool) {
	rows, cols := t.Size()
	fmt.Fprint(out, "\x1b[H\x1b[2J")
	if rows < 12 || cols < 32 {
		fmt.Fprintln(out, "请放大终端；q 退出。 ")
		return
	}
	fmt.Fprintln(out, clip("WeroxyClient · TCP · "+runtime.GOARCH, cols-1))
	fmt.Fprintln(out, clip("配置："+opt.ConfigPath, cols-1))
	fmt.Fprintln(out)
	for i, item := range options {
		prefix := "  "
		if i == selected {
			prefix = "› "
		}
		fmt.Fprintln(out, clip(prefix+item, cols-1))
	}
	fmt.Fprintln(out)
	color := "\x1b[32m"
	if !success {
		color = "\x1b[31m"
	}
	fmt.Fprint(out, color)
	for i, line := range strings.Split(message, "\n") {
		if i >= rows-len(options)-7 {
			break
		}
		fmt.Fprintln(out, clip(line, cols-1))
	}
	fmt.Fprint(out, "\x1b[0m")
	fmt.Fprintf(out, "\x1b[%d;1H↑↓ 选择 · Enter 执行 · Esc 返回 · q 退出", rows)
}
func clip(s string, columns int) string {
	var out strings.Builder
	used := 0
	for _, r := range s {
		if r < 32 || r == 127 {
			continue
		}
		w := 1
		if r >= 0x1100 {
			w = 2
		}
		if used+w > columns {
			break
		}
		out.WriteRune(r)
		used += w
	}
	return out.String()
}
func input(ctx context.Context, t Terminal, out io.Writer, label, current string) (string, bool, error) {
	value := ""
	for {
		rows, cols := t.Size()
		fmt.Fprint(out, "\x1b[H\x1b[2J")
		fmt.Fprintln(out, clip(label, cols-1))
		fmt.Fprintln(out, clip("当前值："+current, cols-1))
		fmt.Fprintln(out, "Enter 保留当前值 · Esc 取消")
		fmt.Fprintln(out, clip("> "+value, cols-1))
		_ = rows
		k, err := t.Key(ctx)
		if err != nil {
			return "", false, err
		}
		switch k {
		case "esc":
			return "", false, nil
		case "enter":
			if value == "" {
				return current, true, nil
			}
			return strings.TrimSpace(value), true, nil
		case "backspace":
			r := []rune(value)
			if len(r) > 0 {
				value = string(r[:len(r)-1])
			}
		case "up", "down", "resize":
		default:
			if len(value)+len(k) <= 1024 {
				value += k
			}
		}
	}
}
func editProfile(ctx context.Context, t Terminal, opt Option) (string, error) {
	current, loadErr := config.Load(opt.ConfigPath)
	host, port := "", config.ControlPort
	if loadErr == nil {
		host, port, _ = net.SplitHostPort(current.Server)
	}
	prompts := []string{"Host（Server IP 或域名）", "Port（Control 默认 29999；没改过直接 Enter）", "Key（Web 设备连接密钥，明文输入）"}
	values := []string{host, port, current.Key}
	for i, prompt := range prompts {
		for {
			v, ok, err := input(ctx, t, opt.Stdout, prompt, values[i])
			if err != nil {
				return "", err
			}
			if !ok {
				return "已取消；配置未保存。", nil
			}
			valid := v != ""
			if i == 0 {
				valid = valid && !strings.ContainsAny(v, " \t\r\n/=")
			}
			if i == 1 {
				n, e := strconv.Atoi(v)
				valid = e == nil && n > 0 && n <= 65535
			}
			if i == 2 {
				_, e := config.ReadToken(strings.NewReader(v))
				valid = e == nil
			}
			if valid {
				values[i] = v
				break
			}
			prompt = "输入无效，请重试：" + prompts[i]
		}
	}
	if err := config.Save(opt.ConfigPath, values[0], values[2], values[1]); err != nil {
		return "", fmt.Errorf("配置未保存：%w", err)
	}
	if err := config.EnsureProfileOwner(opt.ConfigPath); err != nil {
		return "", err
	}
	return "配置已保存；选择 start/restart 应用并连接 Server。", nil
}
func statusLines(ctx context.Context, opt Option) []string {
	active, e := opt.System.Active(ctx)
	if e != nil || active == "" {
		active = "unknown"
	}
	enabled, e := opt.System.Enabled(ctx)
	if e != nil || enabled == "" {
		enabled = "unknown"
	}
	system := runtime.GOOS
	if data, e := os.ReadFile("/etc/os-release"); e == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				system = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			}
		}
	}
	lines := []string{"系统：" + system + " / " + runtime.GOARCH, "服务：" + active, "开机自启：" + enabled, "传输模式：控制与握手已保护；业务流沿用原协议"}
	snap, ok := status.Read(status.Path(ServiceConfigPath))
	if !ok && os.Geteuid() != 0 {
		child, cancel := context.WithTimeout(ctx, 2*time.Second)
		cmd := exec.CommandContext(child, "sudo", "-n", ServiceBinaryPath, "status", "--config", ServiceConfigPath, "--json")
		if body, err := cmd.Output(); err == nil {
			var result struct {
				State     string `json:"state"`
				Running   bool   `json:"running"`
				Connected bool   `json:"connected"`
				Up        uint64 `json:"up_bytes"`
				Down      uint64 `json:"down_bytes"`
			}
			if json.Unmarshal(body, &result) == nil && result.Running {
				snap = status.Snapshot{State: result.State, Connected: result.Connected, Up: result.Up, Down: result.Down}
				ok = true
			}
		}
		cancel()
	}
	if !ok {
		lines = append(lines, "控制连接：未知（暂无运行状态读数）")
		return lines
	}
	return append(lines, "控制连接："+status.StateText(snap.State), fmt.Sprintf("上行：%d B · 下行：%d B", snap.Up, snap.Down))
}
func apply(ctx context.Context, opt Option, action string) (string, error) {
	if !opt.System.HasSudo(ctx) {
		return "", errors.New("需要 root 或 sudo 权限")
	}
	switch action {
	case "start/restart", "start", "restart":
		if err := installService(ctx, opt); err != nil {
			return "", fmt.Errorf("配置同步失败：%w", err)
		}
		active, _ := opt.System.Active(ctx)
		if action == "restart" || active == "active" {
			return "已重启。", opt.System.Restart(ctx)
		}
		return "已启动。", opt.System.Start(ctx)
	case "stop":
		return "已停止。", opt.System.Stop(ctx)
	case "enable":
		return "已开启开机自启；当前运行状态不变。", opt.System.Enable(ctx)
	case "disable":
		return "已关闭开机自启；当前运行状态不变。", opt.System.Disable(ctx)
	case "install":
		return "已同步配置。", installService(ctx, opt)
	case "uninstall":
		if err := opt.System.Stop(ctx); err != nil {
			return "", err
		}
		if err := opt.System.Disable(ctx); err != nil {
			return "", err
		}
		if err := opt.System.Uninstall(ctx, opt.ConfigPath); err != nil {
			return "", err
		}
		return "已卸载软件并删除当前用户及服务配置。", nil
	case "remove-service":
		return "已停用服务。", opt.System.Remove(ctx)
	default:
		return "", errors.New("未知操作")
	}
}
func installService(ctx context.Context, opt Option) error {
	if _, err := config.Load(opt.ConfigPath); err != nil {
		return fmt.Errorf("请先配置 profile：%w", err)
	}
	if err := opt.System.EnsureUser(ctx); err != nil {
		return err
	}
	if err := opt.System.Install(ctx, UnitText(ServiceBinaryPath, ServiceConfigPath), opt.Binary, opt.ConfigPath); err != nil {
		return err
	}
	return opt.System.DaemonReload(ctx)
}
func Service(ctx context.Context, action string, opt Option) int {
	if opt.Stdout == nil {
		opt.Stdout = os.Stdout
	}
	if opt.Stderr == nil {
		opt.Stderr = os.Stderr
	}
	if opt.System == nil {
		opt.System = realSystem{}
	}
	if opt.Binary == "" {
		opt.Binary, _ = os.Executable()
	}
	if action == "status" {
		for _, line := range statusLines(ctx, opt) {
			fmt.Fprintln(opt.Stdout, line)
		}
		return 0
	}
	message, err := apply(ctx, opt, action)
	if err != nil {
		fmt.Fprintln(opt.Stderr, err)
		return 1
	}
	fmt.Fprintln(opt.Stdout, message)
	return 0
}

type realSystem struct{}

func (realSystem) HasSudo(ctx context.Context) bool {
	if os.Geteuid() == 0 {
		return true
	}
	_, err := exec.LookPath("sudo")
	return err == nil
}

func (realSystem) Active(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", UnitName)
	out, err := cmd.Output()
	text := strings.TrimSpace(string(out))
	if text == "" && err != nil {
		return "unknown", nil
	}
	return text, nil
}

func privileged(ctx context.Context, input io.Reader, command string, args ...string) error {
	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		cmd = exec.CommandContext(ctx, command, args...)
	} else {
		cmd = exec.CommandContext(ctx, "sudo", append([]string{command}, args...)...)
	}
	cmd.Stdin = input
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (realSystem) EnsureUser(ctx context.Context) error {
	if exec.CommandContext(ctx, "id", "weroxy").Run() == nil {
		return nil
	}
	return privileged(ctx, nil, "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "weroxy")
}

func (realSystem) Install(ctx context.Context, unit, binary, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(cfg.Server)
	if err != nil {
		return err
	}
	var profileText strings.Builder
	profileText.WriteString("server.host=" + host + "\nclient.key_file=client.key\nserver.port=" + port + "\n")
	profile := []byte(profileText.String())
	defer func() {
		for i := range profile {
			profile[i] = 0
		}
	}()
	// The package owns the program and unit. Configuration sync cannot replace them.
	if filepath.Clean(binary) != ServiceBinaryPath {
		return fmt.Errorf("请先通过原生安装包安装 /usr/bin/weroxy-client")
	}
	if _, err := os.Stat(UnitPath); err != nil {
		return fmt.Errorf("原生安装包的服务单元不存在")
	}
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("service binary is not a regular file")
	}
	if err := privileged(ctx, nil, "install", "-d", "-o", "root", "-g", "weroxy", "-m", "0750", filepath.Dir(ServiceConfigPath)); err != nil {
		return err
	}
	// Stage files under root-owned directories before replacing the live names.
	// The program and unit remain owned by the package manager.
	for _, item := range []struct {
		body                     []byte
		owner, group, mode, dest string
	}{
		{[]byte(cfg.Key + "\n"), "weroxy", "weroxy", "0600", filepath.Join(filepath.Dir(ServiceConfigPath), "client.key")},
		{profile, "weroxy", "weroxy", "0600", ServiceConfigPath},
	} {
		staged := item.dest + ".new"
		if err := privileged(ctx, bytes.NewReader(item.body), "install", "-o", item.owner, "-g", item.group, "-m", item.mode, "/dev/stdin", staged); err != nil {
			return err
		}
		if err := privileged(ctx, nil, "mv", "-f", staged, item.dest); err != nil {
			return err
		}
	}
	return privileged(ctx, nil, "systemctl", "unmask", UnitName)
}

func (realSystem) DaemonReload(ctx context.Context) error {
	return privileged(ctx, nil, "systemctl", "daemon-reload")
}

func (realSystem) Enable(ctx context.Context) error {
	return privileged(ctx, nil, "systemctl", "enable", UnitName)
}

func (realSystem) Disable(ctx context.Context) error {
	return privileged(ctx, nil, "systemctl", "disable", UnitName)
}

func (realSystem) Start(ctx context.Context) error {
	return privileged(ctx, nil, "systemctl", "start", UnitName)
}

func (realSystem) Stop(ctx context.Context) error {
	return privileged(ctx, nil, "systemctl", "stop", UnitName)
}

func (realSystem) Restart(ctx context.Context) error {
	return privileged(ctx, nil, "systemctl", "restart", UnitName)
}

func (realSystem) Installed(context.Context) bool {
	if target, e := os.Readlink("/etc/systemd/system/" + UnitName); e == nil && target == "/dev/null" {
		return false
	}
	_, err := os.Stat(ServiceConfigPath)
	return err == nil
}

func (realSystem) Remove(ctx context.Context) error {
	return privileged(ctx, nil, "systemctl", "mask", UnitName)
}

func (realSystem) Enabled(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "is-enabled", UnitName).Output()
	value := strings.TrimSpace(string(out))
	if value != "" {
		return value, nil
	}
	return "unknown", err
}
func (realSystem) Uninstall(ctx context.Context, path string) error {
	// Detect package ownership before deleting configuration; no shell interpolation.
	var manager string
	for _, candidate := range []string{"dpkg-query", "rpm", "pacman"} {
		var args []string
		switch candidate {
		case "dpkg-query":
			args = []string{"-S", ServiceBinaryPath}
		case "rpm":
			args = []string{"-qf", ServiceBinaryPath, "--qf", "%{NAME}"}
		case "pacman":
			args = []string{"-Qqo", ServiceBinaryPath}
		}
		out, err := exec.CommandContext(ctx, candidate, args...).Output()
		owner := strings.TrimSpace(string(out))
		if candidate == "dpkg-query" {
			owner, _, _ = strings.Cut(owner, ":")
		}
		if err == nil && owner == "weroxy-client" {
			manager = candidate
			break
		}
	}
	if manager == "" {
		return errors.New("无法核实安装包归属；未删除配置")
	}
	// The private helper uses a fixed subcommand and bounded paths, not rm -rf from Web input.
	if err := privileged(ctx, nil, ServiceBinaryPath, "purge-profile", "--config", path); err != nil {
		return err
	}
	switch manager {
	case "dpkg-query":
		return privileged(ctx, nil, "dpkg", "--remove", "weroxy-client")
	case "rpm":
		return privileged(ctx, nil, "rpm", "-e", "weroxy-client")
	case "pacman":
		return privileged(ctx, nil, "pacman", "-R", "--noconfirm", "weroxy-client")
	}
	return nil
}
