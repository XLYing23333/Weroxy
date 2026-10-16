//go:build linux

package firewallagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// kernelFingerprint checks only Weroxy objects and required hook placement.
// It is evidence of installed rules, never evidence of public connectivity.
func (a *agent) kernelFingerprint(parent context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	var body []byte
	if a.cfg.Backend == "nft" {
		raw, err := nft(ctx, a.nft, "", "-j", "list", "table", "inet", "weroxy")
		if err != nil {
			return "", err
		}
		var value any
		if json.Unmarshal(raw, &value) != nil {
			return "", errors.New("nft integrity JSON invalid")
		}
		stripKernelMetadata(value)
		body, err = json.Marshal(value)
		if err != nil {
			return "", err
		}
	} else {
		seen := map[bool]bool{}
		var b strings.Builder
		for _, ep := range a.cfg.Endpoints {
			v6 := strings.Contains(ep.HostIP, ":")
			if seen[v6] {
				continue
			}
			seen[v6] = true
			name := "iptables"
			if v6 {
				name = "ip6tables"
			}
			tool, err := findIPTables(name)
			if err != nil {
				return "", err
			}
			b.WriteString(name + "\n")
			for _, chain := range []string{"WEROXY-IN", "WEROXY-FWD"} {
				if err := verifyOwned(ctx, tool, chain); err != nil {
					return "", err
				}
				raw, err := ipt(ctx, tool, "", "-w", "2", "-S", chain)
				if err != nil {
					return "", err
				}
				b.Write(raw)
			}
			bridge := false
			for _, endpoint := range a.cfg.Endpoints {
				if endpoint.Mode == "bridge" && strings.Contains(endpoint.HostIP, ":") == v6 {
					bridge = true
				}
			}
			hooks := [][2]string{{"INPUT", "WEROXY-IN"}}
			if bridge {
				hooks = append(hooks, [2]string{"DOCKER-USER", "WEROXY-FWD"})
			}
			for _, hook := range hooks {
				raw, err := ipt(ctx, tool, "", "-w", "2", "-S", hook[0])
				if err != nil {
					return "", err
				}
				first := ""
				count := 0
				wanted := "-A " + hook[0] + " -m comment --comment weroxy-agent -j " + hook[1]
				for _, line := range strings.Split(strings.ReplaceAll(string(raw), `"weroxy-agent"`, "weroxy-agent"), "\n") {
					if strings.HasPrefix(line, "-A ") && first == "" {
						first = line
					}
					if strings.Contains(line, "-j "+hook[1]) {
						count++
					}
				}
				if first != wanted || count != 1 {
					return "", errors.New("Weroxy hook placement changed")
				}
				b.WriteString(wanted + "\n")
			}
		}
		body = []byte(b.String())
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func stripKernelMetadata(value any) {
	switch item := value.(type) {
	case map[string]any:
		delete(item, "handle")
		delete(item, "metainfo")
		for _, child := range item {
			stripKernelMetadata(child)
		}
	case []any:
		for _, child := range item {
			stripKernelMetadata(child)
		}
	}
}
