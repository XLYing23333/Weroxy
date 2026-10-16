//go:build linux

package firewallagent

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
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const maxRequest = 32 << 10

type agent struct {
	cfg              Config
	nft              string
	generation       uint64
	digest           [32]byte
	rules            []Rule
	appliedActive    int
	applied          bool
	kernelDigest     string
	intentGeneration uint64
	intentDigest     [32]byte
}

// LoadConfig only accepts a small root-owned regular file. The unprivileged
// Web process cannot change the agent's network scope or enable writes.
func LoadConfig(path string) (Config, error) {
	if !filepath.IsAbs(path) {
		return Config{}, errors.New("agent 配置路径必须为绝对路径")
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		parent, err := os.Lstat(dir)
		if err != nil {
			return Config{}, err
		}
		owner, ok := parent.Sys().(*syscall.Stat_t)
		if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o022 != 0 || !ok || owner.Uid != 0 {
			return Config{}, errors.New("agent 配置路径的目录必须由 root 拥有且不可由其他账户写入")
		}
		if dir == string(filepath.Separator) {
			break
		}
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Config{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Config{}, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Size() > 256<<10 || info.Mode().Perm()&0o077 != 0 || !ok || owner.Uid != 0 {
		return Config{}, errors.New("agent 配置必须是 root 拥有的受限普通文件")
	}
	body, err := io.ReadAll(io.LimitReader(file, (256<<10)+1))
	if err != nil || len(body) > 256<<10 {
		return Config{}, errors.New("agent 配置读取失败或超限")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, errors.New("agent 配置 JSON 无效")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("agent 配置包含多余内容")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Run serves only a local UNIX socket. It never listens on a network address.
func Run(ctx context.Context, cfg Config) error {
	if os.Geteuid() != 0 {
		return errors.New("firewall-agent 需要 root 权限")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	binary := ""
	var err error
	if cfg.Backend == "nft" {
		binary, err = findNFT()
	} else {
		_, err = findIPTables("iptables")
	}
	if err != nil {
		return err
	}
	directory := filepath.Dir(SocketPath)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || !ok || owner.Uid != 0 {
		return errors.New("agent socket directory must be root-owned and protected")
	}
	if err := removeStaleSocket(cfg.ClientUID); err != nil {
		return err
	}
	previousMask := unix.Umask(0o077)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: SocketPath, Net: "unix"})
	unix.Umask(previousMask)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(SocketPath)
	if err := os.Chown(SocketPath, cfg.ClientUID, -1); err != nil {
		return err
	}
	if err := os.Chmod(SocketPath, 0o600); err != nil {
		return err
	}
	go func() { <-ctx.Done(); _ = listener.Close() }()
	a := &agent{cfg: cfg, nft: binary}
	if err := a.recoverState(ctx); err != nil {
		return err
	}
	// Requests and expiry both mutate a under the same gate.
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	expiry := time.NewTicker(time.Minute)
	defer expiry.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-expiry.C:
				select {
				case <-gate:
				case <-ctx.Done():
					return
				}
				a.expire(ctx)
				gate <- struct{}{}
			}
		}
	}()
	clients := make(chan struct{}, 16)
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case clients <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { <-clients }()
			defer conn.Close()
			if uid := peerUID(conn); uid != cfg.ClientUID && uid != 0 {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
			select {
			case <-gate:
			case <-ctx.Done():
				return
			}
			defer func() { gate <- struct{}{} }()
			_ = json.NewEncoder(conn).Encode(a.serve(ctx, conn))
		}()
	}
}

func peerUID(conn *net.UnixConn) int {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1
	}
	uid := -1
	_ = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err == nil {
			uid = int(cred.Uid)
		}
	})
	return uid
}

func (a *agent) serve(ctx context.Context, reader io.Reader) Response {
	body, err := bufio.NewReader(io.LimitReader(reader, maxRequest+1)).ReadBytes('\n')
	if err != nil || len(body) > maxRequest {
		return Response{Status: "invalid", Reason: "request_size", KernelStatus: "unknown"}
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return Response{Status: "invalid", Reason: "json", KernelStatus: "unknown"}
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Response{Status: "invalid", Reason: "trailing_data", KernelStatus: "unknown"}
	}
	response := Response{Generation: a.generation, PendingGeneration: a.intentGeneration, Rules: a.appliedActive, KernelStatus: "unverified"}
	if a.applied {
		response.Digest = fmt.Sprintf("%x", a.digest)
	}
	switch req.Operation {
	case "query":
		response.Endpoints = append([]Endpoint(nil), a.cfg.Endpoints...)
		if a.applied {
			fingerprint, err := a.kernelFingerprint(ctx)
			if err != nil || fingerprint != a.kernelDigest {
				response.KernelStatus = "drift"
				response.Reason = "kernel_integrity"
			} else {
				response.KernelStatus = "agent_applied_unverified"
			}
		}
		response.Status = "ok"
		return response
	case "plan", "apply", "revoke":
		if req.Operation == "revoke" && len(req.Rules) != 0 {
			response.Status = "invalid"
			response.Reason = "revoke_rules"
			return response
		}
		if err := ValidateRules(a.cfg, req.Rules, time.Now().UTC()); err != nil {
			response.Status = "invalid"
			response.Reason = "rule_validation"
			return response
		}
		active := liveRules(req.Rules, time.Now().UTC())
		response.Script = Script(a.cfg, active)
		if req.Operation == "plan" {
			response.Status = "planned"
			return response
		}
		if !a.cfg.AllowApply {
			response.Status = "unsupported"
			response.Reason = "apply_disabled"
			response.Script = ""
			return response
		}
		if req.Generation == 0 || req.Generation < a.generation {
			response.Status = "conflict"
			response.Reason = "generation"
			response.Script = ""
			return response
		}
		digest := digestRules(req.Rules)
		if req.Generation < a.intentGeneration || req.Generation == a.intentGeneration && digest != a.intentDigest {
			response.Status = "conflict"
			response.Reason = "pending_generation"
			response.Script = ""
			return response
		}
		if req.Generation == a.generation {
			if a.applied && digest == a.digest {
				fingerprint, err := a.kernelFingerprint(ctx)
				if err != nil || fingerprint != a.kernelDigest {
					response.Status = "failed"
					response.Reason = "kernel_integrity"
					response.KernelStatus = "drift"
					response.Script = ""
					return response
				}
				response.Status = "applied"
				response.KernelStatus = "agent_applied_unverified"
				response.Script = ""
				return response
			}
			response.Status = "conflict"
			response.Reason = "generation_content"
			response.Script = ""
			return response
		}
		if err := a.saveIntent(req.Generation, req.Rules); err != nil {
			response.Status = "failed"
			response.Reason = "state_persist"
			response.Script = ""
			return response
		}
		if err := a.apply(ctx, active); err != nil {
			response.Status = "failed"
			response.Reason = "kernel_apply"
			response.Script = ""
			return response
		}
		a.generation, a.digest, a.rules, a.appliedActive, a.applied = req.Generation, digest, append([]Rule(nil), req.Rules...), len(active), true
		fmt.Fprintf(os.Stderr, "firewall-agent generation=%d rules=%d operation=%s result=applied\n", a.generation, len(active), req.Operation)
		response.Status, response.Generation, response.Rules, response.KernelStatus, response.Script = "applied", a.generation, len(active), "agent_applied_unverified", ""
		return response
	default:
		response.Status, response.Reason = "invalid", "operation"
		return response
	}
}

func liveRules(rules []Rule, now time.Time) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if rule.ExpiresAt.After(now) {
			out = append(out, rule)
		}
	}
	return out
}

func (a *agent) expire(ctx context.Context) {
	if !a.applied {
		return
	}
	now := time.Now().UTC()
	active := liveRules(a.rules, now)
	if len(active) == a.appliedActive {
		return
	}
	if err := a.apply(ctx, active); err != nil {
		fmt.Fprintf(os.Stderr, "firewall-agent generation=%d operation=expire result=failed\n", a.generation)
		return
	}
	a.appliedActive = len(active)
	fmt.Fprintf(os.Stderr, "firewall-agent generation=%d rules=%d operation=expire result=applied\n", a.generation, len(active))
}

func (a *agent) apply(parent context.Context, rules []Rule) error {
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	if a.cfg.Backend == "iptables" {
		if err := a.applyIPTables(ctx, rules); err != nil {
			return err
		}
		fingerprint, err := a.kernelFingerprint(ctx)
		if err != nil {
			return err
		}
		a.kernelDigest = fingerprint
		return nil
	}
	if err := a.ensureTable(ctx); err != nil {
		return err
	}
	script := Script(a.cfg, rules)
	if _, err := nft(ctx, a.nft, script, "-c", "-f", "-"); err != nil {
		return err
	}
	if _, err := nft(ctx, a.nft, script, "-f", "-"); err != nil {
		return err
	}
	fingerprint, err := a.kernelFingerprint(ctx)
	if err != nil {
		return err
	}
	a.kernelDigest = fingerprint
	return nil
}

func (a *agent) ensureTable(ctx context.Context) error {
	out, err := nft(ctx, a.nft, "", "-j", "list", "tables")
	if err != nil {
		return err
	}
	var tables struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &tables); err != nil {
		return err
	}
	exists := false
	for _, entry := range tables.NFTables {
		if raw := entry["table"]; raw != nil {
			var item struct{ Family, Name string }
			if json.Unmarshal(raw, &item) == nil && item.Family == "inet" && item.Name == "weroxy" {
				exists = true
			}
		}
	}
	if !exists {
		if _, err := nft(ctx, a.nft,
			"add table inet weroxy\nadd chain inet weroxy input { type filter hook input priority -145; policy accept; }\nadd chain inet weroxy forward { type filter hook forward priority -145; policy accept; }\n",
			"-f", "-"); err != nil {
			return err
		}
	}
	out, err = nft(ctx, a.nft, "", "-j", "list", "table", "inet", "weroxy")
	if err != nil {
		return err
	}
	var current struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &current); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, entry := range current.NFTables {
		if raw := entry["chain"]; raw != nil {
			var chain struct {
				Family   string `json:"family"`
				Table    string `json:"table"`
				Name     string `json:"name"`
				Type     string `json:"type"`
				Hook     string `json:"hook"`
				Priority int    `json:"prio"`
				Policy   string `json:"policy"`
			}
			if json.Unmarshal(raw, &chain) != nil || chain.Family != "inet" || chain.Table != "weroxy" ||
				(chain.Name != "input" && chain.Name != "forward") || chain.Type != "filter" ||
				chain.Hook != chain.Name || chain.Priority != -145 || chain.Policy != "accept" || seen[chain.Name] {
				return errors.New("Weroxy nft base chain 已被外部修改")
			}
			seen[chain.Name] = true
		} else if entry["set"] != nil || entry["map"] != nil || entry["flowtable"] != nil {
			return errors.New("Weroxy nft 表含未知对象")
		}
	}
	if !seen["input"] || !seen["forward"] {
		return errors.New("Weroxy nft base chain 不完整")
	}
	return nil
}

func nft(ctx context.Context, binary, script string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LANG=C"}
	if script != "" {
		cmd.Stdin = strings.NewReader(script)
	}
	var out boundedOutput
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if out.over {
		return nil, errors.New("nft 输出超限")
	}
	if err != nil {
		return nil, errors.New("nft 命令失败")
	}
	return out.Bytes(), nil
}

type boundedOutput struct {
	bytes.Buffer
	over bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1<<20 {
		b.over = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

func findNFT() (string, error) {
	for _, path := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"} {
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if info.Mode().IsRegular() && info.Mode().Perm()&0o022 == 0 && ok && owner.Uid == 0 {
			return path, nil
		}
	}
	return "", errors.New("未找到 root 拥有且不可由其他账户修改的 nft")
}

func removeStaleSocket(clientUID int) error {
	info, err := os.Lstat(SocketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("agent socket 路径已被非 socket 文件占用")
	}
	conn, dialErr := net.DialTimeout("unix", SocketPath, 200*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return errors.New("firewall-agent 已运行")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (owner.Uid != 0 && owner.Uid != uint32(clientUID)) {
		return errors.New("无法安全清理未知 socket")
	}
	return os.Remove(SocketPath)
}
