// Package firewallagent accepts bounded Weroxy-only host firewall requests.
// It is deliberately independent from the unprivileged Web server process.
package firewallagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const SocketPath = "/run/weroxy-firewall/agent.sock"

// Endpoint is one operator-approved published TCP entrance. For a Docker
// bridge, DestinationIP/TargetPort are the post-DNAT container tuple.
type Endpoint struct {
	Mode          string `json:"mode"`
	Bridge        string `json:"bridge,omitempty"`
	HostIP        string `json:"host_ip"`
	ListenHost    string `json:"listen_host"`
	DestinationIP string `json:"destination_ip"`
	PublicPort    int    `json:"public_port"`
	TargetPort    int    `json:"target_port"`
}

type Config struct {
	Backend           string     `json:"backend"`
	ClientUID         int        `json:"client_uid"`
	AllowApply        bool       `json:"allow_apply"`
	ManagementPort    int        `json:"management_port"`
	ManagementSources []string   `json:"management_sources"`
	Endpoints         []Endpoint `json:"endpoints"`
}

type Rule struct {
	Source     string    `json:"source"`
	ListenHost string    `json:"listen_host"`
	Port       int       `json:"target_port"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type Request struct {
	Operation  string `json:"operation"`
	Generation uint64 `json:"generation"`
	Rules      []Rule `json:"rules,omitempty"`
}

type Response struct {
	Status            string     `json:"status"`
	Reason            string     `json:"reason,omitempty"`
	Generation        uint64     `json:"generation"`
	PendingGeneration uint64     `json:"pending_generation"`
	Rules             int        `json:"rules"`
	Script            string     `json:"script,omitempty"`
	KernelStatus      string     `json:"kernel_status"`
	Digest            string     `json:"digest,omitempty"`
	Endpoints         []Endpoint `json:"endpoints,omitempty"`
}

func (cfg Config) Validate() error {
	if cfg.Backend != "nft" && cfg.Backend != "iptables" {
		return errors.New("backend 必须明确选择 nft 或 iptables")
	}
	if cfg.ClientUID < 1 || cfg.ClientUID > 1<<31-1 {
		return errors.New("client_uid 必须是非 root 的本机 UID")
	}
	if len(cfg.Endpoints) == 0 || len(cfg.Endpoints) > 512 {
		return errors.New("endpoint 数量必须在 1 到 512 之间")
	}
	if cfg.ManagementPort < 1 || cfg.ManagementPort > 65535 {
		return errors.New("management_port 无效")
	}
	if len(cfg.ManagementSources) == 0 || len(cfg.ManagementSources) > 16 {
		return errors.New("management_sources 数量必须在 1 到 16 之间")
	}
	management := map[bool]bool{}
	for _, source := range cfg.ManagementSources {
		address, err := netip.ParseAddr(source)
		if err != nil || !address.IsValid() || address.IsUnspecified() || address.Zone() != "" || address.Is4In6() {
			return errors.New("management_sources 必须是明确 IP")
		}
		management[address.Is4()] = true
	}
	seen := map[string]bool{}
	for _, item := range cfg.Endpoints {
		host, err := netip.ParseAddr(item.HostIP)
		if err != nil || !host.IsValid() || host.IsUnspecified() || host.Zone() != "" || host.Is4In6() {
			return errors.New("endpoint host_ip 无效")
		}
		dest, err := netip.ParseAddr(item.DestinationIP)
		if err != nil || !dest.IsValid() || dest.IsUnspecified() || dest.Zone() != "" || dest.Is4() != host.Is4() || dest.Is4In6() {
			return errors.New("endpoint destination_ip 无效或地址族不匹配")
		}
		listen, err := netip.ParseAddr(item.ListenHost)
		if err != nil || !listen.IsValid() || listen.Zone() != "" || listen.Is4In6() || listen.String() != item.ListenHost {
			return errors.New("endpoint listen_host 无效")
		}
		if item.PublicPort < 1 || item.PublicPort > 65535 || item.TargetPort < 1 || item.TargetPort > 65535 {
			return errors.New("endpoint 端口无效")
		}
		if item.PublicPort == cfg.ManagementPort && !management[host.Is4()] {
			return errors.New("管理入口的地址族缺少可信管理来源")
		}
		if item.Mode == "host" {
			if item.Bridge != "" || dest != host || item.TargetPort != item.PublicPort {
				return errors.New("host endpoint 必须使用相同地址和端口")
			}
		} else if item.Mode == "bridge" {
			if !validInterface(item.Bridge) {
				return errors.New("bridge 接口名称无效")
			}
		} else {
			return errors.New("endpoint mode 必须是 host 或 bridge")
		}
		key := item.HostIP + ":" + strconv.Itoa(item.PublicPort)
		if seen[key] {
			return errors.New("重复发布入口")
		}
		seen[key] = true
	}
	return nil
}

func validInterface(name string) bool {
	if len(name) < 1 || len(name) > 15 {
		return false
	}
	for _, char := range name {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_' || char == '-' || char == '.') {
			return false
		}
	}
	return true
}

func ValidateRules(cfg Config, rules []Rule, now time.Time) error {
	if len(rules) > 128 {
		return errors.New("规则超过 128 条上限")
	}
	management := make([]netip.Addr, 0, len(cfg.ManagementSources))
	for _, source := range cfg.ManagementSources {
		address, _ := netip.ParseAddr(source)
		management = append(management, address)
	}
	seen := map[string]bool{}
	expanded := 0
	for _, rule := range rules {
		prefix, err := netip.ParsePrefix(rule.Source)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() || prefix.Masked().String() != rule.Source {
			return errors.New("source 必须是规范 CIDR")
		}
		if !rule.ExpiresAt.After(now) || rule.ExpiresAt.After(now.Add(24*time.Hour)) {
			return errors.New("规则 TTL 必须在未来 24 小时内")
		}
		listen, err := netip.ParseAddr(rule.ListenHost)
		if err != nil || !listen.IsValid() || listen.Zone() != "" || listen.Is4In6() || listen.String() != rule.ListenHost {
			return errors.New("rule listen_host 无效")
		}
		matched := false
		for _, endpoint := range cfg.Endpoints {
			host, _ := netip.ParseAddr(endpoint.HostIP)
			if endpoint.TargetPort == rule.Port && endpoint.ListenHost == rule.ListenHost && prefix.Addr().Is4() == host.Is4() {
				expanded++
				if expanded > 1024 {
					return errors.New("expanded kernel rules exceed budget")
				}
				matched = true
				if endpoint.PublicPort == cfg.ManagementPort {
					for _, source := range management {
						if host.Is4() == source.Is4() && prefix.Contains(source) {
							return errors.New("规则会封锁配置的管理来源")
						}
					}
				}
			}
		}
		if !matched {
			return errors.New("规则端口未获授权或地址族不匹配")
		}
		key := rule.Source + ":" + rule.ListenHost + ":" + strconv.Itoa(rule.Port)
		if seen[key] {
			return errors.New("重复规则")
		}
		seen[key] = true
	}
	return nil
}

// Script returns only commands in Weroxy's own nft table and chains. The
// table and base chains must have been initialized and verified by the agent.
func Script(cfg Config, rules []Rule) string {
	if cfg.Backend == "iptables" {
		return "# IPv4 iptables-restore --noflush\n" + IPTablesScript(cfg, rules, false) + "# IPv6 ip6tables-restore --noflush\n" + IPTablesScript(cfg, rules, true)
	}
	ordered := append([]Rule(nil), rules...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Port != ordered[j].Port {
			return ordered[i].Port < ordered[j].Port
		}
		if ordered[i].ListenHost != ordered[j].ListenHost {
			return ordered[i].ListenHost < ordered[j].ListenHost
		}
		return ordered[i].Source < ordered[j].Source
	})
	var b strings.Builder
	b.WriteString("flush chain inet weroxy input\nflush chain inet weroxy forward\n")
	for _, rule := range ordered {
		prefix, _ := netip.ParsePrefix(rule.Source)
		family := "ip"
		if prefix.Addr().Is6() {
			family = "ip6"
		}
		for _, ep := range cfg.Endpoints {
			host, _ := netip.ParseAddr(ep.HostIP)
			if ep.TargetPort != rule.Port || ep.ListenHost != rule.ListenHost || host.Is4() != prefix.Addr().Is4() {
				continue
			}
			if ep.Mode == "host" {
				fmt.Fprintf(&b, "add rule inet weroxy input %s saddr %s %s daddr %s tcp dport %d drop\n",
					family, rule.Source, family, host.String(), ep.PublicPort)
			} else {
				fmt.Fprintf(&b, "add rule inet weroxy forward oifname %q %s saddr %s %s daddr %s tcp dport %d ct original daddr %s ct original proto-dst %d drop\n",
					ep.Bridge, family, rule.Source, family, ep.DestinationIP, ep.TargetPort, host.String(), ep.PublicPort)
			}
		}
	}
	return b.String()
}

// DigestRules is stable across caller order and matches the agent's
// idempotency digest. It contains no secret material.
func DigestRules(rules []Rule) string {
	sum := digestRules(rules)
	return hex.EncodeToString(sum[:])
}

func digestRules(rules []Rule) [32]byte {
	ordered := append([]Rule(nil), rules...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Port != ordered[j].Port {
			return ordered[i].Port < ordered[j].Port
		}
		if ordered[i].Source != ordered[j].Source {
			return ordered[i].Source < ordered[j].Source
		}
		return ordered[i].ExpiresAt.Before(ordered[j].ExpiresAt)
	})
	body, _ := json.Marshal(ordered)
	return sha256.Sum256(body)
}
