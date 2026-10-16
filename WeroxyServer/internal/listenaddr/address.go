// Package listenaddr compares configured TCP binds with their runtime addresses.
package listenaddr

import (
	"net"
	"strconv"
)

// Matches accounts for Go's tcp wildcard binding: 0.0.0.0, :: and an
// empty host may all produce a dual-stack [::] listener. A concrete bind
// must still match its concrete IP, so loopback is never a wildcard.
func Matches(actual net.Addr, configured string) bool {
	if actual == nil {
		return false
	}
	if actual.String() == configured {
		return true
	}
	tcp, ok := actual.(*net.TCPAddr)
	if !ok {
		return false
	}
	host, port, err := net.SplitHostPort(configured)
	if err != nil {
		return false
	}
	number, err := strconv.Atoi(port)
	if err != nil || number != tcp.Port {
		return false
	}
	ip := net.ParseIP(host)
	if host == "" {
		ip = net.IPv6zero
	}
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() && tcp.IP.IsUnspecified() {
		return true
	}
	return ip.Equal(tcp.IP) && tcp.Zone == ""
}
