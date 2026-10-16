//go:build linux

package firewallagent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func findIPTables(name string) (string, error) {
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin"} {
		candidate := filepath.Join(dir, name)
		path, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if info.Mode().IsRegular() && info.Mode().Perm()&0o022 == 0 && ok && owner.Uid == 0 {
			return candidate, nil
		}
	}
	return "", errors.New("root-owned iptables executable missing")
}
func ipt(ctx context.Context, binary, script string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LANG=C"}
	if script != "" {
		cmd.Stdin = strings.NewReader(script)
	}
	var out boundedOutput
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil || out.over {
		return nil, errors.New("iptables command failed")
	}
	return out.Bytes(), nil
}

// verifyOwned rejects pre-existing chains unless their terminal ownership
// marker and every rule match the previously generated, restricted grammar.
func verifyOwned(ctx context.Context, binary, chain string) error {
	out, err := ipt(ctx, binary, "", "-w", "2", "-S", chain)
	if err != nil {
		return nil
	} // restore creates a missing chain; failures still fail apply.
	lines := strings.Split(strings.ReplaceAll(strings.TrimSpace(string(out)), `"weroxy-owned"`, "weroxy-owned"), "\n")
	marker := "-A " + chain + " -m comment --comment weroxy-owned -j RETURN"
	if len(lines) < 2 || lines[len(lines)-1] != marker {
		return errors.New("Weroxy chain ownership missing")
	}
	for _, line := range lines[1 : len(lines)-1] {
		if !strings.HasPrefix(line, "-A "+chain+" ") || !strings.HasSuffix(line, " -j DROP") {
			return errors.New("Weroxy chain externally modified")
		}
	}
	return nil
}
func (a *agent) applyIPTables(ctx context.Context, rules []Rule) (applyErr error) {
	type family struct {
		tool, restore string
		ipv6          bool
	}
	families := []family{}
	seen := map[bool]bool{}
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
			return err
		}
		restore, err := findIPTables(name + "-restore")
		if err != nil {
			return err
		}
		families = append(families, family{tool, restore, v6})
	}
	changed := false
	defer func() {
		if applyErr == nil || !changed {
			return
		}
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
		defer cancel()
		for _, f := range families {
			if _, err := ipt(recovery, f.restore, IPTablesScript(a.cfg, liveRules(a.rules, time.Now().UTC()), f.ipv6), "--wait", "2", "--noflush"); err != nil {
				applyErr = errors.Join(applyErr, errors.New("iptables rollback failed"))
			}
		}
	}()
	for _, f := range families {
		for _, ep := range a.cfg.Endpoints {
			if ep.Mode == "bridge" && strings.Contains(ep.HostIP, ":") == f.ipv6 {
				if _, err := ipt(ctx, f.tool, "", "-w", "2", "-S", "DOCKER-USER"); err != nil {
					return errors.New("Docker iptables DOCKER-USER path unavailable")
				}
				break
			}
		}
		for _, chain := range []string{"WEROXY-IN", "WEROXY-FWD"} {
			if err := verifyOwned(ctx, f.tool, chain); err != nil {
				return err
			}
		}
		script := IPTablesScript(a.cfg, rules, f.ipv6)
		if _, err := ipt(ctx, f.restore, script, "--wait", "2", "--noflush", "--test"); err != nil {
			return err
		}
	}
	for _, f := range families {
		if _, err := ipt(ctx, f.restore, IPTablesScript(a.cfg, rules, f.ipv6), "--wait", "2", "--noflush"); err != nil {

			return err
		}
		changed = true
		for _, hook := range [][2]string{{"INPUT", "WEROXY-IN"}, {"DOCKER-USER", "WEROXY-FWD"}} {
			if hook[0] == "DOCKER-USER" {
				bridge := false
				for _, ep := range a.cfg.Endpoints {
					if ep.Mode == "bridge" && strings.Contains(ep.HostIP, ":") == f.ipv6 {
						bridge = true
					}
				}
				if !bridge {
					continue
				}
				if _, err := ipt(ctx, f.tool, "", "-w", "2", "-S", "DOCKER-USER"); err != nil {
					return errors.New("Docker iptables DOCKER-USER path unavailable")
				}
			}
			args := []string{"-w", "2", "-C", hook[0], "-m", "comment", "--comment", "weroxy-agent", "-j", hook[1]}
			if _, err := ipt(ctx, f.tool, "", args...); err != nil {
				args = []string{"-w", "2", "-I", hook[0], "1", "-m", "comment", "--comment", "weroxy-agent", "-j", hook[1]}
				if _, err := ipt(ctx, f.tool, "", args...); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
