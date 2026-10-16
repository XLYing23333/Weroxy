// Package harden provides explicit, optional host configuration, never a service dependency.
package harden

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const base = "/var/lib/weroxy-client/harden-backup"
const sshFile = "/etc/ssh/sshd_config.d/60-weroxy-hardening.conf"
const jailFile = "/etc/fail2ban/jail.d/weroxy.local"

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func command(ctx context.Context, name string, args ...string) (string, error) {
	child, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	b, e := exec.CommandContext(child, name, args...).CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("%s 执行失败", name)
	}
	return string(b), nil
}
func sshd() string {
	if p, e := exec.LookPath("sshd"); e == nil {
		return p
	}
	return "/usr/sbin/sshd"
}
func source() string {
	f := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(f) == 4 && net.ParseIP(f[0]) != nil {
		return f[0]
	}
	return ""
}
func settings(ctx context.Context) (map[string]string, error) {
	args := []string{"-T"}
	f := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(f) == 4 {
		args = append(args, "-C", "user="+managementUser()+",addr="+f[0]+",host="+f[0]+",laddr="+f[2]+",lport="+f[3])
	}
	text, e := command(ctx, sshd(), args...)
	m := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		p := strings.SplitN(line, " ", 2)
		if len(p) == 2 {
			m[p[0]] = strings.TrimSpace(p[1])
		}
	}
	return m, e
}
func Inspect(ctx context.Context) []Check {
	if runtime.GOOS != "linux" {
		return []Check{{"platform", "skip", "主机加固仅支持 Linux"}}
	}
	m, e := settings(ctx)
	out := []Check{}
	if e != nil {
		out = append(out, Check{"sshd", "skip", "无法检测：需要足够权限及 OpenSSH"})
	} else {
		for _, k := range []string{"permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "persourcemaxstartups", "logingracetime"} {
			value, ok := m[k]
			state := "pass"
			if !ok {
				state = "skip"
				value = "不支持"
			} else if value == "yes" || value == "none" {
				state = "warn"
			} else if k == "logingracetime" {
				n, _ := strconv.Atoi(value)
				if n > 60 {
					state = "warn"
				}
			}
			out = append(out, Check{k, state, value})
		}
	}
	if _, e = command(ctx, "systemctl", "is-active", "--quiet", "fail2ban"); e != nil {
		out = append(out, Check{"fail2ban", "warn", "未运行或无法检测"})
	} else if _, e = command(ctx, "fail2ban-client", "status", "sshd"); e != nil {
		out = append(out, Check{"fail2ban", "warn", "服务运行但 sshd jail 无法确认"})
	} else {
		out = append(out, Check{"fail2ban", "pass", "sshd jail 运行"})
	}
	port := m["port"]
	if port == "" {
		port = "22"
	}
	if text, err := command(ctx, "ss", "-ltnH"); err == nil {
		broad := false
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 3 {
				addr := fields[3]
				if strings.HasSuffix(addr, ":"+port) && (strings.HasPrefix(addr, "0.0.0.0:") || strings.HasPrefix(addr, "[::]:") || strings.HasPrefix(addr, "*:")) {
					broad = true
				}
			}
		}
		if broad {
			out = append(out, Check{"sshd_listener", "warn", "SSH 在通配地址监听；公网可达还取决于防火墙"})
		} else {
			out = append(out, Check{"sshd_listener", "info", "未发现所选端口通配监听；不等于公网不可达"})
		}
	} else {
		out = append(out, Check{"sshd_listener", "skip", "无法检查监听"})
	}
	if text, err := command(ctx, "ufw", "status"); err == nil {
		found := false
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, port+"/tcp") && strings.Contains(line, "LIMIT") {
				found = true
			}
		}
		if found {
			out = append(out, Check{"firewall", "info", "发现所选端口限速规则，未验证实际防护"})
		} else {
			out = append(out, Check{"firewall", "warn", "未发现所选端口 UFW 限速规则；仅检测，不自动修改"})
		}
	} else {
		out = append(out, Check{"firewall", "skip", "UFW 不可用或权限不足；不自动修改防火墙"})
	}
	return out
}

type Plan struct {
	Kind, Port, PerSource, Grace, Root, MaxRetry, FindTime, BanTime, Ignore string
	DisablePassword                                                         bool
	Files                                                                   map[string]string
}

func prompt(r *bufio.Reader, w io.Writer, label, value string) (string, error) {
	fmt.Fprintf(w, "%s [%s]（Enter 默认，输入 cancel 取消）: ", label, value)
	s, e := r.ReadString('\n')
	if e != nil {
		return "", errors.New("输入取消，未应用配置")
	}
	s = strings.TrimSpace(s)
	if s == "cancel" {
		return "", errors.New("已取消")
	}
	if s == "" {
		s = value
	}
	return s, nil
}
func positive(s string, max int) bool { n, e := strconv.Atoi(s); return e == nil && n > 0 && n <= max }
func collect(r *bufio.Reader, w io.Writer, kind string, m map[string]string, ip string) (Plan, error) {
	p := Plan{Kind: kind, Files: map[string]string{}}
	var e error
	port := m["port"]
	if port == "" {
		port = "22"
	}
	p.Port, e = prompt(r, w, "SSH 保护端口（不改变监听）", port)
	if e != nil {
		return p, e
	}
	if !positive(p.Port, 65535) {
		return p, errors.New("SSH 端口无效")
	}
	if kind == "ssh" {
		p.PerSource, e = prompt(r, w, "PerSourceMaxStartups（隧道可能共用本地来源）", "3")
		if e != nil {
			return p, e
		}
		p.Grace, e = prompt(r, w, "LoginGraceTime 秒", "30")
		if e != nil {
			return p, e
		}
		if !positive(p.PerSource, 10000) || !positive(p.Grace, 3600) {
			return p, errors.New("SSH 参数无效")
		}
		keep, e := prompt(r, w, "保留当前密码认证？Y/n", "Y")
		if e != nil {
			return p, e
		}
		if !strings.EqualFold(keep, "y") && !strings.EqualFold(keep, "n") {
			return p, errors.New("请选择 Y/n")
		}
		p.DisablePassword = strings.EqualFold(keep, "n")
		p.Root, e = prompt(r, w, "root 登录方式 keep/prohibit-password/no", "keep")
		if e != nil {
			return p, e
		}
		if p.Root != "keep" && p.Root != "prohibit-password" && p.Root != "no" {
			return p, errors.New("root 模式无效")
		}
		text := "# Managed by Weroxy; optional host hardening\nPerSourceMaxStartups " + p.PerSource + "\nLoginGraceTime " + p.Grace + "\n"
		if p.DisablePassword {
			text += "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
		}
		if p.Root != "keep" {
			text += "PermitRootLogin " + p.Root + "\n"
		}
		p.Files[sshFile] = text
	}
	install, e := prompt(r, w, "安装并配置 fail2ban？Y/n", "Y")
	if e != nil {
		return p, e
	}
	if !strings.EqualFold(install, "y") && !strings.EqualFold(install, "n") {
		return p, errors.New("请选择 Y/n")
	}
	if strings.EqualFold(install, "y") {
		p.MaxRetry, e = prompt(r, w, "maxretry", "3")
		if e != nil {
			return p, e
		}
		p.FindTime, e = prompt(r, w, "findtime", "10m")
		if e != nil {
			return p, e
		}
		p.BanTime, e = prompt(r, w, "bantime", "1h")
		if e != nil {
			return p, e
		}
		if !positive(p.MaxRetry, 100) {
			return p, errors.New("maxretry 无效")
		}
		for _, s := range []string{p.FindTime, p.BanTime} {
			d, e := time.ParseDuration(s)
			if e != nil || d < time.Second || d > 30*24*time.Hour {
				return p, errors.New("时间参数无效")
			}
		}
		ignore := "127.0.0.1/8,::1"
		if m["_ignoreip"] != "" {
			ignore += "," + strings.ReplaceAll(m["_ignoreip"], " ", ",")
		}
		if ip != "" {
			ignore += "," + ip
		}
		p.Ignore, e = prompt(r, w, "ignoreip（必须包含当前管理来源及回环）", ignore)
		if e != nil {
			return p, e
		}
		if ip == "" {
			ip, e = prompt(r, w, "无法识别来源：填写可信管理 IP", "")
			if e != nil {
				return p, e
			}
			if net.ParseIP(ip) == nil {
				return p, errors.New("管理 IP 无效")
			}
		}
		covered := false
		loop4, loop6 := false, false
		for _, s := range strings.Split(p.Ignore, ",") {
			s = strings.TrimSpace(s)
			v := net.ParseIP(s)
			_, network, nerr := net.ParseCIDR(s)
			if v == nil && nerr != nil {
				return p, errors.New("ignoreip 必须为合法 IP/CIDR")
			}
			contains := func(x string) bool {
				a := net.ParseIP(x)
				return v != nil && v.Equal(a) || network != nil && network.Contains(a)
			}
			covered = covered || contains(ip)
			loop4 = loop4 || contains("127.0.0.1")
			loop6 = loop6 || contains("::1")
			if network != nil {
				ones, _ := network.Mask.Size()
				if ones == 0 {
					return p, errors.New("禁止白名单放行全部来源")
				}
			}
		}
		if !covered || !loop4 || !loop6 {
			return p, errors.New("白名单必须包含管理来源和双栈回环")
		}
		p.Files[jailFile] = "# Managed by Weroxy; direct SSH only, not original tunnel visitor IPs\n[sshd]\nenabled = true\nbackend = systemd\nport = " + p.Port + "\nmaxretry = " + p.MaxRetry + "\nfindtime = " + p.FindTime + "\nbantime = " + p.BanTime + "\nignoreip = " + strings.ReplaceAll(p.Ignore, ",", " ") + "\n"
	}
	return p, nil
}

type FileBackup struct {
	Path   string
	Exists bool
	Body   []byte
	Mode   uint32
}
type Operation struct {
	ID          string
	Source      string
	Files       []FileBackup
	SSHUnit     string
	FailActive  bool
	FailEnabled bool
	Confirmed   bool
	RolledBack  bool
	Started     string
}

func regular(path string) error {
	for p := path; p != "/"; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("拒绝符号链接路径")
		}
	}
	return nil
}
func saveOperation(op Operation) error {
	b, e := json.Marshal(op)
	if e != nil {
		return e
	}
	dir := filepath.Join(base, op.ID)
	if e = regular(dir); e != nil {
		return e
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	tmp := filepath.Join(dir, "manifest.tmp")
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, filepath.Join(dir, "manifest.json"))
}
func loadOperation(id string) (Operation, error) {
	var op Operation
	if len(id) != 32 {
		return op, errors.New("操作编号无效")
	}
	if _, e := hex.DecodeString(id); e != nil {
		return op, e
	}
	p := filepath.Join(base, id, "manifest.json")
	if e := regular(p); e != nil {
		return op, e
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return op, e
	}
	e = json.Unmarshal(b, &op)
	if op.ID != id {
		return op, errors.New("操作记录无效")
	}
	return op, e
}
func timerUnit(id string) string { return "weroxy-harden-rollback-" + id }
func rollback(ctx context.Context, id string, automatic bool) error {
	op, e := loadOperation(id)
	if e != nil {
		return e
	}
	if (automatic && op.Confirmed) || op.RolledBack {
		return nil
	}
	for _, f := range op.Files {
		if f.Path != sshFile && f.Path != jailFile {
			return errors.New("备份路径不允许")
		}
		if e = regular(f.Path); e != nil {
			return e
		}
		if f.Exists {
			e = os.WriteFile(f.Path, f.Body, os.FileMode(f.Mode))
			if e == nil {
				e = os.Chmod(f.Path, os.FileMode(f.Mode))
			}
		} else {
			e = os.Remove(f.Path)
			if os.IsNotExist(e) {
				e = nil
			}
		}
		if e != nil {
			return e
		}
	}
	for _, f := range op.Files {
		if f.Path == sshFile {
			if _, e = command(ctx, sshd(), "-t"); e != nil {
				return e
			}
			if _, e = command(ctx, "systemctl", "reload", op.SSHUnit); e != nil {
				return e
			}
		}
	}
	hasJail := false
	for _, f := range op.Files {
		if f.Path == jailFile {
			hasJail = true
		}
	}
	if hasJail && op.FailActive {
		if _, e = command(ctx, "systemctl", "restart", "fail2ban"); e != nil {
			return e
		}
	} else if hasJail {
		if _, e = command(ctx, "systemctl", "stop", "fail2ban"); e != nil {
			if _, look := exec.LookPath("fail2ban-client"); look == nil {
				return e
			}
		}
	}
	if hasJail && !op.FailEnabled {
		_, _ = command(ctx, "systemctl", "disable", "fail2ban")
	}
	op.RolledBack = true
	if e = saveOperation(op); e != nil {
		return e
	}
	_, _ = command(ctx, "systemctl", "stop", timerUnit(id)+".timer")
	return nil
}
func apply(ctx context.Context, p Plan, m map[string]string, w io.Writer) (err error) {
	if os.Geteuid() != 0 {
		return errors.New("必须通过 sudo 运行")
	}
	release, e := os.ReadFile("/etc/os-release")
	if e != nil || !strings.Contains(string(release), "ID=debian") || !strings.Contains(string(release), "VERSION_ID=\"12\"") {
		return errors.New("目前仅验证 Debian 12")
	}
	if _, ok := p.Files[sshFile]; ok {
		if m["persourcemaxstartups"] == "" {
			return errors.New("当前 OpenSSH 不支持 PerSourceMaxStartups")
		}
		if _, e = command(ctx, sshd(), "-t"); e != nil {
			return e
		}
	}
	if len(p.Files) == 0 {
		return nil
	}
	op := Operation{Source: os.Getenv("SSH_CONNECTION"), SSHUnit: "ssh", Started: time.Now().UTC().Format(time.RFC3339)}
	raw := make([]byte, 16)
	if _, e = rand.Read(raw); e != nil {
		return e
	}
	op.ID = hex.EncodeToString(raw)
	if _, e = command(ctx, "systemctl", "is-active", "--quiet", "ssh"); e != nil {
		return errors.New("ssh 服务不可验证")
	}
	_, e = command(ctx, "systemctl", "is-active", "--quiet", "fail2ban")
	op.FailActive = e == nil
	_, e = command(ctx, "systemctl", "is-enabled", "--quiet", "fail2ban")
	op.FailEnabled = e == nil
	for path := range p.Files {
		if e = regular(path); e != nil {
			return e
		}
		f := FileBackup{Path: path}
		if st, e := os.Stat(path); e == nil {
			if !st.Mode().IsRegular() {
				return errors.New("配置不是普通文件")
			}
			f.Exists = true
			f.Mode = uint32(st.Mode().Perm())
			f.Body, e = os.ReadFile(path)
			if e != nil {
				return e
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		op.Files = append(op.Files, f)
	}
	if e = saveOperation(op); e != nil {
		return e
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	if e = regular(exe); e != nil {
		return e
	}
	if e = trustedExecutable(exe); e != nil {
		return e
	}
	if _, e = command(ctx, "systemd-run", "--unit="+timerUnit(op.ID), "--on-active=5m", "--timer-property=AccuracySec=1s", "--property=Restart=on-failure", "--property=RestartSec=5s", exe, "harden", "rollback", op.ID, "--automatic"); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			re := rollback(context.Background(), op.ID, true)
			if re != nil {
				err = fmt.Errorf("%v；自动回滚失败，请通过带外渠道处理", err)
			}
		}
	}()
	if _, ok := p.Files[jailFile]; ok {
		if _, e = exec.LookPath("fail2ban-client"); e != nil {
			child, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			for _, argv := range [][]string{{"update"}, {"install", "-y", "fail2ban"}} {
				cmd := exec.CommandContext(child, "apt-get", argv...)
				cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
				cmd.Stdout = w
				cmd.Stderr = w
				if e = cmd.Run(); e != nil {
					return errors.New("fail2ban 包索引更新或安装失败")
				}
			}
		}
	}
	for path, text := range p.Files {
		if e = regular(path); e != nil {
			return e
		}
		if e = os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			return e
		}
		if e = os.WriteFile(path, []byte(text), 0600); e != nil {
			return e
		}
	}
	if _, ok := p.Files[sshFile]; ok {
		if _, e = command(ctx, sshd(), "-t"); e != nil {
			return e
		}
		actual, e := settings(ctx)
		if e != nil {
			return e
		}
		if actual["persourcemaxstartups"] != p.PerSource || actual["logingracetime"] != p.Grace || p.DisablePassword && (actual["passwordauthentication"] != "no" || actual["kbdinteractiveauthentication"] != "no") || p.Root != "keep" && actual["permitrootlogin"] != p.Root {
			return errors.New("配置未实际生效，可能存在 Include/Match 优先级冲突")
		}
		if _, e = command(ctx, "systemctl", "reload", "ssh"); e != nil {
			return e
		}
	}
	if _, ok := p.Files[jailFile]; ok {
		if _, e = command(ctx, "fail2ban-client", "-t"); e != nil {
			return e
		}
		if _, e = command(ctx, "systemctl", "enable", "fail2ban"); e != nil {
			return e
		}
		if _, e = command(ctx, "systemctl", "restart", "fail2ban"); e != nil {
			return e
		}
		ready, cancel := context.WithTimeout(ctx, 20*time.Second)
		for {
			if _, e = command(ready, "fail2ban-client", "status", "sshd"); e == nil {
				break
			}
			select {
			case <-ready.Done():
				cancel()
				return errors.New("fail2ban jail 未在预算内就绪")
			case <-time.After(200 * time.Millisecond):
			}
		}
		cancel()
		expected := map[string]string{"maxretry": p.MaxRetry}
		for key, value := range map[string]string{"findtime": p.FindTime, "bantime": p.BanTime} {
			d, _ := time.ParseDuration(value)
			expected[key] = strconv.FormatInt(int64(d/time.Second), 10)
		}
		for key, value := range expected {
			actual, e := command(ctx, "fail2ban-client", "get", "sshd", key)
			if e != nil || strings.TrimSpace(actual) != value {
				return errors.New("fail2ban 参数未实际生效")
			}
		}
	}
	started, _ := time.Parse(time.RFC3339, op.Started)
	if time.Since(started) >= 5*time.Minute {
		return errors.New("操作超过确认期限，正在回滚")
	}
	fmt.Fprintf(w, "已应用。请在第二个 SSH 会话执行：sudo %s harden confirm %s\n五分钟内未确认将自动回滚。\n", exe, op.ID)
	return nil
}

// Run is shared by CLI and TUI. All system-changing operations are explicit.
func Run(args []string, in io.Reader, out io.Writer) int {
	ctx := context.Background()
	if runtime.GOOS != "linux" {
		fmt.Fprintln(out, "主机加固目前仅支持 Debian 12 Linux")
		return 2
	}
	if len(args) == 0 {
		fmt.Fprintln(out, "harden ssh|fail2ban [--dry-run]|status [--json]|rollback <id>|confirm <id>")
		return 2
	}
	if args[0] == "status" {
		checks := Inspect(ctx)
		if len(args) == 2 && args[1] == "--json" {
			_ = json.NewEncoder(out).Encode(checks)
		} else {
			for _, c := range checks {
				fmt.Fprintf(out, "%s: %s — %s\n", c.Name, c.Status, c.Detail)
			}
		}
		return 0
	}
	if args[0] == "rollback" || args[0] == "confirm" {
		if args[0] == "rollback" && len(args) == 1 {
			id, e := latestOperation()
			if e != nil {
				fmt.Fprintln(out, e)
				return 1
			}
			args = append(args, id)
		}
		automatic := len(args) == 3 && args[0] == "rollback" && args[2] == "--automatic"
		if os.Geteuid() != 0 || (len(args) != 2 && !automatic) {
			fmt.Fprintln(out, "需要 root 与操作编号")
			return 2
		}
		release, e := lock()
		if e != nil {
			fmt.Fprintln(out, e)
			return 1
		}
		defer release()
		if args[0] == "rollback" {
			if !automatic {
				latest, e := latestOperation()
				if e != nil || latest != args[1] {
					fmt.Fprintln(out, "请先回滚最近的未回滚操作")
					return 1
				}
			}
			if e := rollback(ctx, args[1], automatic); e != nil {
				fmt.Fprintln(out, e)
				return 1
			}
			fmt.Fprintln(out, "已回滚")
			return 0
		}
		op, e := loadOperation(args[1])
		if e != nil {
			fmt.Fprintln(out, e)
			return 1
		}
		if op.RolledBack {
			fmt.Fprintln(out, "已回滚，不能确认")
			return 1
		}
		if source() == "" || os.Getenv("SSH_CONNECTION") == op.Source {
			fmt.Fprintln(out, "请通过第二个 SSH 管理会话确认")
			return 1
		}
		started, e := time.Parse(time.RFC3339, op.Started)
		if e != nil || time.Since(started) >= 5*time.Minute {
			fmt.Fprintln(out, "确认已超时")
			return 1
		}
		op.Confirmed = true
		if e = saveOperation(op); e != nil {
			fmt.Fprintln(out, e)
			return 1
		}
		_, _ = command(ctx, "systemctl", "stop", timerUnit(op.ID)+".timer")
		fmt.Fprintln(out, "已确认")
		return 0
	}
	if args[0] != "ssh" && args[0] != "fail2ban" {
		return 2
	}
	dry := len(args) == 2 && args[1] == "--dry-run"
	if len(args) > 1 && !dry {
		return 2
	}
	if !dry && os.Geteuid() != 0 {
		fmt.Fprintln(out, "请使用 sudo；只读预览可用 --dry-run")
		return 1
	}
	m, e := settings(ctx)
	if e != nil && !dry {
		fmt.Fprintln(out, "无法验证 sshd 配置")
		return 1
	}
	if text, err := command(ctx, "fail2ban-client", "get", "sshd", "ignoreip"); err == nil {
		// Output contains a tree header followed by IP/CIDR lines; accept only literal networks.
		ips := []string{}
		for _, field := range strings.Fields(text) {
			v := strings.Trim(field, "|-`+")
			_, _, e := net.ParseCIDR(v)
			if net.ParseIP(v) != nil || e == nil {
				ips = append(ips, v)
			}
		}
		m["_ignoreip"] = strings.Join(ips, " ")
	}
	r := bufio.NewReader(in)
	p, e := collect(r, out, args[0], m, source())
	if e != nil {
		fmt.Fprintln(out, e)
		return 1
	}
	for path, text := range p.Files {
		fmt.Fprintf(out, "\n%s\n%s", path, text)
	}
	fmt.Fprintln(out, "不会修改 UFW。fail2ban 不会识别隧道背后的原始公网来源。")
	if dry {
		fmt.Fprintln(out, "dry-run：未应用任何变更")
		return 0
	}
	for path := range p.Files {
		if _, e := os.Stat(path); e == nil {
			fmt.Fprintf(out, "将替换已有专属配置：%s（变更前备份）\n", path)
		}
	}
	yes, e := prompt(r, out, "确认有第二 SSH/带外管理渠道，输入 YES 执行", "NO")
	if e != nil || yes != "YES" {
		fmt.Fprintln(out, "已取消，未应用配置")
		return 0
	}
	release, e := lock()
	if e != nil {
		fmt.Fprintln(out, e)
		return 1
	}
	defer release()
	if id, err := latestOperation(); err == nil {
		op, e := loadOperation(id)
		if e != nil {
			fmt.Fprintln(out, e)
			return 1
		}
		if !op.Confirmed && !op.RolledBack {
			fmt.Fprintln(out, "请先确认或回滚上一次操作")
			return 1
		}
	}
	if e = apply(ctx, p, m, out); e != nil {
		fmt.Fprintln(out, e)
		return 1
	}
	return 0
}

func managementUser() string {
	if s := os.Getenv("SUDO_USER"); s != "" {
		return s
	}
	return os.Getenv("USER")
}

func latestOperation() (string, error) {
	entries, e := os.ReadDir(base)
	if e != nil {
		return "", errors.New("没有可回滚的操作")
	}
	type item struct {
		id      string
		started string
	}
	items := []item{}
	for _, entry := range entries {
		if !entry.IsDir() || len(entry.Name()) != 32 {
			continue
		}
		op, e := loadOperation(entry.Name())
		if e == nil && !op.RolledBack {
			items = append(items, item{op.ID, op.Started})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].started > items[j].started })
	if len(items) == 0 {
		return "", errors.New("没有可回滚的操作")
	}
	return items[0].id, nil
}
