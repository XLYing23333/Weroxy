package firewallsync

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"weroxy/server/internal/firewallagent"
	"weroxy/server/internal/storage/sqlite"
)

// compileFirewallRules maps application Ban scopes to visitor listener ports.
// Shared Data Ports are never used to approximate one device/Forward's scope.
func CompileRules(bans []sqlite.FirewallBan, forwards []sqlite.FirewallForward, endpoints []firewallagent.Endpoint, now time.Time) ([]firewallagent.Rule, []int64, []int64, error) {
	approved := map[string]bool{}
	for _, endpoint := range endpoints {
		address, err := netip.ParseAddr(endpoint.HostIP)
		if err != nil {
			return nil, nil, nil, errors.New("invalid agent endpoint")
		}
		key := firewallPortKey(endpoint.ListenHost, endpoint.TargetPort, address.Is4())
		approved[key] = true
	}
	type listener struct {
		device, listenHost, listen string
		port                       int
	}
	active := make([]listener, 0, len(forwards))
	for _, f := range forwards {
		host, portText, err := net.SplitHostPort(f.Listen)
		if err != nil {
			return nil, nil, nil, errors.New("invalid stored forward listen")
		}
		address, err := netip.ParseAddr(host)
		if err != nil {
			return nil, nil, nil, errors.New("invalid stored forward host")
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, nil, nil, errors.New("invalid stored forward port")
		}
		active = append(active, listener{device: f.Device, listenHost: address.String(), listen: f.Listen, port: port})
	}
	projected := now.UTC().Truncate(12 * time.Hour).Add(24 * time.Hour)
	byKey := map[string]firewallagent.Rule{}
	var matched, unmatched []int64
	for _, ban := range bans {
		prefix, err := netip.ParsePrefix(ban.CIDR)
		if err != nil {
			return nil, nil, nil, errors.New("invalid stored ban CIDR")
		}
		prefix = prefix.Masked()
		until := projected
		if ban.ExpiresAt != nil {
			if ban.ExpiresAt.Before(until) {
				until = ban.ExpiresAt.UTC()
			}
		}
		found := false
		uncovered := false
		for _, f := range active {
			switch ban.Scope {
			case "global":
			case "device":
				if ban.Key != f.device {
					continue
				}
			case "forward":
				device, listen, ok := strings.Cut(ban.Key, "|")
				if !ok || device != f.device || listen != f.listen {
					continue
				}
			default:
				return nil, nil, nil, errors.New("invalid stored ban scope")
			}
			if !approved[firewallPortKey(f.listenHost, f.port, prefix.Addr().Is4())] {
				uncovered = true
				continue
			}
			found = true
			rule := firewallagent.Rule{Source: prefix.String(), ListenHost: f.listenHost, Port: f.port, ExpiresAt: until}
			key := rule.Source + "|" + rule.ListenHost + "|" + strconv.Itoa(rule.Port)
			if prior, ok := byKey[key]; !ok || rule.ExpiresAt.After(prior.ExpiresAt) {
				byKey[key] = rule
			}
		}
		if found && !uncovered {
			matched = append(matched, ban.ID)
		} else {
			unmatched = append(unmatched, ban.ID)
		}
	}
	if len(byKey) > 128 {
		return nil, matched, unmatched, errors.New("host rule budget exceeded")
	}
	out := make([]firewallagent.Rule, 0, len(byKey))
	for _, rule := range byKey {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].ListenHost != out[j].ListenHost {
			return out[i].ListenHost < out[j].ListenHost
		}
		return out[i].Source < out[j].Source
	})
	return out, matched, unmatched, nil
}

func firewallPortKey(host string, port int, ipv4 bool) string {
	return host + "|" + strconv.Itoa(port) + "|" + strconv.FormatBool(ipv4)
}

// FirewallPlan is a read-only candidate. It does not call agent apply/revoke
// or change the database, kernel, Docker, or active policy.
type FirewallPlan struct {
	PolicyRevision int64
	Rules          []firewallagent.Rule
	MatchedBans    int
	UnmatchedBans  int
}

func PlanFirewall(ctx context.Context, db *sqlite.DB, endpoints []firewallagent.Endpoint) (FirewallPlan, error) {
	revision, bans, forwards, err := db.FirewallSnapshot(ctx)
	if err != nil {
		return FirewallPlan{}, err
	}
	rules, matched, unmatched, err := CompileRules(bans, forwards, endpoints, time.Now().UTC())
	if err != nil {
		return FirewallPlan{}, err
	}
	return FirewallPlan{PolicyRevision: revision, Rules: rules, MatchedBans: len(matched), UnmatchedBans: len(unmatched)}, nil
}
