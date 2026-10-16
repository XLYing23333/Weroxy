package listenaddr

import (
	"net"
	"testing"
)

func TestTCPBindIdentity(t *testing.T) {
	for _, tc := range []struct {
		actual, configured string
		match              bool
	}{
		{"[::]:29000", "0.0.0.0:29000", true},
		{"[::]:29100", ":29100", true},
		{"0.0.0.0:29000", "[::]:29000", true},
		{"[::]:29000", "0.0.0.0:29001", false},
		{"[::]:29000", "127.0.0.1:29000", false},
		{"127.0.0.1:29000", "0.0.0.0:29000", false},
		{"127.0.0.1:29000", "127.0.0.2:29000", false},
		{"127.0.0.1:29000", "127.0.0.1:29000", true},
		{"[::1]:29000", "[::1]:29000", true},
	} {
		addr, err := net.ResolveTCPAddr("tcp", tc.actual)
		if err != nil {
			t.Fatal(err)
		}
		if got := Matches(addr, tc.configured); got != tc.match {
			t.Errorf("%s vs %s: got %v", tc.actual, tc.configured, got)
		}
	}
}
