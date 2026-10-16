package harden

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestDefaultsPreserveAuthentication(t *testing.T) {
	var out bytes.Buffer
	p, e := collect(bufio.NewReader(strings.NewReader("\n\n\n\n\n\n\n\n\n\n")), &out, "ssh", map[string]string{"port": "22"}, "192.0.2.1")
	if e != nil {
		t.Fatal(e)
	}
	if p.DisablePassword || p.Root != "keep" || p.MaxRetry != "3" || p.FindTime != "10m" || p.BanTime != "1h" {
		t.Fatalf("unexpected defaults: %+v", p)
	}
	if strings.Contains(p.Files[sshFile], "Authentication") || !strings.Contains(p.Files[jailFile], "192.0.2.1") {
		t.Fatal("unsafe defaults")
	}
}
func TestCancelAndUnsafeWhitelist(t *testing.T) {
	for _, input := range []string{"cancel\n", "22\nY\n3\n10m\n1h\n0.0.0.0/0,::/0\n"} {
		_, e := collect(bufio.NewReader(strings.NewReader(input)), &bytes.Buffer{}, "fail2ban", nil, "192.0.2.1")
		if e == nil {
			t.Fatal("accepted unsafe/cancelled plan")
		}
	}
}
func TestPasswordOptIn(t *testing.T) {
	p, e := collect(bufio.NewReader(strings.NewReader("22\n3\n30\nn\nno\nn\n")), &bytes.Buffer{}, "ssh", nil, "192.0.2.1")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(p.Files[sshFile], "KbdInteractiveAuthentication no") {
		t.Fatal("interactive password still allowed")
	}
}
