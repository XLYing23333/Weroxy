// Package ports checks listen conflicts and assigns data-port pools.
package ports

import (
	"net"
	"strconv"
)

const (
	LegacyPlainPort = 4900
	ControlPort     = 29999
	WebPort         = 9415
)

// Endpoint is one claimed TCP address.
type Endpoint struct {
	Host string
	Port int
	Role string
}

// Reserved are the documented default process entrances. Quick List shares
// WebPort at /list; it has no independently reserved TCP port.
func Reserved() []Endpoint {
	var claimed []Endpoint
	for _, entry := range []struct {
		port int
		role string
	}{
		{LegacyPlainPort, "legacy"},
		{ControlPort, "weroxy-control"}, {WebPort, "web"},
	} {
		claimed = append(claimed,
			Endpoint{Host: "0.0.0.0", Port: entry.port, Role: entry.role},
			Endpoint{Host: "::", Port: entry.port, Role: entry.role})
	}
	return claimed
}

// Conflicts reports whether two listeners on the same port would overlap.
// The IPv6 wildcard conflicts with every address. The IPv4 wildcard conflicts
// with every IPv4 address, including IPv4-mapped IPv6.
func Conflicts(a, b Endpoint) bool {
	if a.Port == 0 || a.Port != b.Port {
		return false
	}
	left, right := classify(a.Host), classify(b.Host)
	if left.all || right.all {
		return true
	}
	if left.v4any && (right.v4 || right.mapped) || right.v4any && (left.v4 || left.mapped) {
		return true
	}
	if left.v6any && right.v6 || right.v6any && left.v6 {
		return true
	}
	if left.mapped && right.v4 && left.ip.To4().Equal(right.ip.To4()) {
		return true
	}
	if right.mapped && left.v4 && right.ip.To4().Equal(left.ip.To4()) {
		return true
	}
	if left.ip != nil && right.ip != nil && left.ip.Equal(right.ip) {
		return true
	}
	return false
}

// FirstConflict returns the claimed endpoint that overlaps next, if any.
func FirstConflict(claimed []Endpoint, next Endpoint) (Endpoint, bool) {
	for _, item := range claimed {
		if Conflicts(item, next) {
			return item, true
		}
	}
	return Endpoint{}, false
}

// ParseHostPort splits a canonical host:port.
func ParseHostPort(value string) (string, int, bool) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

type kind struct {
	ip     net.IP
	v4     bool
	v6     bool
	mapped bool
	v4any  bool
	v6any  bool
	all    bool
}

func classify(host string) kind {
	if host == "" || host == "::" || host == "[::]" {
		return kind{all: true}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return kind{all: true}
	}
	if ip.IsUnspecified() {
		if ip.To4() != nil {
			return kind{ip: ip, v4any: true, v4: true}
		}
		return kind{all: true}
	}
	if v4 := ip.To4(); v4 != nil {
		if ip.To16() != nil && ip.To4() != nil && len(ip) == net.IPv6len {
			return kind{ip: ip, v4: true, mapped: true}
		}
		return kind{ip: v4, v4: true}
	}
	return kind{ip: ip, v6: true}
}
