// Package targetguard resolves Server-selected targets before any target dial.
package targetguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"weroxy/client/internal/config"
)

var ErrDenied = errors.New("invalid Server-selected target")
var ErrResolve = errors.New("target resolution failed")

// ValidTarget validates endpoint syntax. Authorization is Server-owned.
func ValidTarget(target string) bool {
	_, err := config.NormalizeTarget(target)
	return err == nil
}

// Resolve pins one bounded DNS answer set. Address format is validated;
// dialing uses these IPs without another lookup.
func Resolve(parent context.Context, target string, timeout time.Duration) ([]string, error) {
	if !ValidTarget(target) {
		return nil, ErrDenied
	}
	host, port, _ := net.SplitHostPort(target)
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(resolved) == 0 || len(resolved) > 16 {
			return nil, ErrResolve
		}
		addresses = resolved
	}
	out := make([]string, 0, len(addresses))
	seen := map[netip.Addr]bool{}
	for _, original := range addresses {
		ip := original.Unmap()
		if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, ErrDenied
		}
		if !seen[ip] {
			out = append(out, net.JoinHostPort(ip.String(), port))
			seen[ip] = true
		}
	}
	if len(out) == 0 {
		return nil, ErrResolve
	}
	return out, nil
}

// DialResolved tries only the validated snapshot under a single deadline.
func DialResolved(parent context.Context, addresses []string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if len(addresses) == 0 || len(addresses) > 16 {
		return nil, ErrResolve
	}
	var last error
	for index, address := range addresses {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Share the remaining budget so a blackholed first address does not
		// prevent an authorized IPv4/IPv6 fallback from being attempted.
		deadline, _ := ctx.Deadline()
		attempt, stop := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(addresses)-index))
		conn, err := (&net.Dialer{}).DialContext(attempt, "tcp", address)
		stop()
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}
