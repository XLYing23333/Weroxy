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

var entries = []string{"profile", "start/restart", "stop", "status", "autostart", "doctor", "host hardening", "uninstall"}

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
	message := "Configure Host, Port and Key in profile, then choose start/restart."
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
			if action == "autostart" {
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
			if action == "host hardening" {
				if opt.Action != nil {
					reader := bufio.NewReader(opt.Stdin)
					fmt.Fprintln(opt.Stdout, "1 Inspect risks  2 Harden SSH  3 Install/configure login protection  4 Dry run  5 Roll back")
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
						fmt.Fprintln(opt.Stdout, "Operation ID (Enter for latest):")
						id, _ := reader.ReadString('\n')
						values = []string{"rollback"}
						if strings.TrimSpace(id) != "" {
							values = append(values, strings.TrimSpace(id))
						}
					}
					success = opt.Action("harden", values) == 0
					message = "Host assistant finished."
				}
			} else if action == "doctor" {
				if opt.Action != nil {
					code := opt.Action("doctor", nil)
					success = code == 0
					message = "Diagnostics completed."
					if !success {
						message = "Diagnostics failed; review the reasons above."
					}
				}
			} else {
				message, err = apply(ctx, opt, action)
				success = err == nil
				if err != nil {
					message = "Failed: " + err.Error()
				}
			}
			if action == "uninstall" && success {
				fmt.Fprintln(opt.Stdout, message)
				return 0
			}
			fmt.Fprintln(opt.Stdout, message, "\nPress Enter to return to the menu.")
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
		fmt.Fprintln(out, "Enlarge the terminal; q to quit. ")
		return
	}
	fmt.Fprintln(out, clip("WeroxyClient · TCP · "+runtime.GOARCH, cols-1))
	fmt.Fprintln(out, clip("Profile: "+opt.ConfigPath, cols-1))
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
	fmt.Fprintf(out, "\u001b[%d;1HUp/Down select | Enter execute | Esc back | q quit", rows)
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
		fmt.Fprintln(out, clip("Current: "+current, cols-1))
		fmt.Fprintln(out, "Enter keeps the current value | Esc cancels")
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
	prompts := []string{"Host (Server IP or domain)", "Port (Control default: 29999; Enter to keep)", "Key (device connection key from Web; visible input)"}
	values := []string{host, port, current.Key}
	for i, prompt := range prompts {
		for {
			v, ok, err := input(ctx, t, opt.Stdout, prompt, values[i])
			if err != nil {
				return "", err
			}
			if !ok {
				return "Cancelled; profile not saved.", nil
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
			prompt = "Invalid input; try again: " + prompts[i]
		}
	}
	if err := config.Save(opt.ConfigPath, values[0], values[2], values[1]); err != nil {
		return "", fmt.Errorf("Profile not saved: %w", err)
	}
	if err := config.EnsureProfileOwner(opt.ConfigPath); err != nil {
		return "", err
	}
	return "Profile saved; choose start/restart to apply and connect to Server.", nil
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
	lines := []string{"System: " + system + " / " + runtime.GOARCH, "Service: " + active, "Autostart: " + enabled, "Transport: control and binding protected; business traffic retains its original protocol"}
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
		lines = append(lines, "Control: unknown (no runtime status available)")
		return lines
	}
	return append(lines, "Control: "+status.StateText(snap.State), fmt.Sprintf("Upload: %d B | Download: %d B", snap.Up, snap.Down))
}
func apply(ctx context.Context, opt Option, action string) (string, error) {
	if !opt.System.HasSudo(ctx) {
		return "", errors.New("Root or sudo privileges required")
	}
	switch action {
	case "start/restart", "start", "restart":
		if err := installService(ctx, opt); err != nil {
			return "", fmt.Errorf("Profile synchronization failed: %w", err)
		}
		active, _ := opt.System.Active(ctx)
		if action == "restart" || active == "active" {
			return "Restarted.", opt.System.Restart(ctx)
		}
		return "Started.", opt.System.Start(ctx)
	case "stop":
		return "Stopped.", opt.System.Stop(ctx)
	case "enable":
		return "Autostart enabled; current running state unchanged.", opt.System.Enable(ctx)
	case "disable":
		return "Autostart disabled; current running state unchanged.", opt.System.Disable(ctx)
	case "install":
		return "Profile synchronized.", installService(ctx, opt)
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
		return "Package removed; current user and service profiles deleted.", nil
	case "remove-service":
		return "Service disabled.", opt.System.Remove(ctx)
	default:
		return "", errors.New("Unknown action")
	}
}
func installService(ctx context.Context, opt Option) error {
	if _, err := config.Load(opt.ConfigPath); err != nil {
		return fmt.Errorf("Configure profile first: %w", err)
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
		return fmt.Errorf("Install /usr/bin/weroxy-client using a native package first")
	}
	if _, err := os.Stat(UnitPath); err != nil {
		return fmt.Errorf("The native package service unit is missing")
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
		return errors.New("Package ownership could not be verified; configuration was not deleted")
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
