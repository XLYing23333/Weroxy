package firewallagent

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// IPTablesScript changes only the two Weroxy-owned filter chains. Hook jumps
// are installed separately; --noflush preserves Docker and operator chains.
func IPTablesScript(cfg Config, rules []Rule, ipv6 bool) string {
	ordered := append([]Rule(nil), rules...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Source+ordered[i].ListenHost+fmt.Sprint(ordered[i].Port) < ordered[j].Source+ordered[j].ListenHost+fmt.Sprint(ordered[j].Port)
	})
	var b strings.Builder
	b.WriteString("*filter\n:WEROXY-IN - [0:0]\n:WEROXY-FWD - [0:0]\n-F WEROXY-IN\n-F WEROXY-FWD\n")
	for _, rule := range ordered {
		prefix, err := netip.ParsePrefix(rule.Source)
		if err != nil || prefix.Addr().Is6() != ipv6 {
			continue
		}
		for _, ep := range cfg.Endpoints {
			host, _ := netip.ParseAddr(ep.HostIP)
			if ep.TargetPort != rule.Port || ep.ListenHost != rule.ListenHost || host.Is6() != ipv6 {
				continue
			}
			if ep.Mode == "host" {
				fmt.Fprintf(&b, "-A WEROXY-IN -p tcp -s %s -d %s --dport %d -j DROP\n", rule.Source, ep.HostIP, ep.PublicPort)
			} else {
				fmt.Fprintf(&b, "-A WEROXY-FWD -o %s -p tcp -s %s -d %s --dport %d -m conntrack --ctdir ORIGINAL --ctorigdst %s --ctorigdstport %d -j DROP\n", ep.Bridge, rule.Source, ep.DestinationIP, ep.TargetPort, ep.HostIP, ep.PublicPort)
			}
		}
	}
	b.WriteString("-A WEROXY-IN -m comment --comment weroxy-owned -j RETURN\n-A WEROXY-FWD -m comment --comment weroxy-owned -j RETURN\nCOMMIT\n")
	return b.String()
}
