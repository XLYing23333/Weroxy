package sqlite

import (
	"errors"
	"net/netip"
	"strings"
)

var ErrAccessRuleExists = errors.New("equivalent access rule already exists")

// Preserve an IPv4-mapped prefix's meaning when representing it as IPv4.
func canonicalAccessCIDR(value string) (string, error) {
	if len(value) > 128 {
		return "", ErrPortRange
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return "", ErrPortRange
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return "", ErrPortRange
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked().String(), nil
}
