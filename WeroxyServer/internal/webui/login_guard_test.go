package webui

import (
	"testing"
	"time"
)

func TestLoginGuardBoundsFailuresWithoutGlobalAdminLockout(t *testing.T) {
	now := time.Now()
	g := newLoginGuard()
	g.now = func() time.Time { return now }
	for i := 0; i < loginFailures; i++ {
		g.fail("admin", "192.0.2.1:80")
	}
	if g.allow("admin", "192.0.2.1:80") {
		t.Fatal("source still allowed")
	}
	if !g.allow("admin", "192.0.2.2:80") {
		t.Fatal("different source locked out")
	}
	now = now.Add(loginBan + time.Second)
	if !g.allow("admin", "192.0.2.1:80") {
		t.Fatal("ban did not expire")
	}
	for i := 0; i < loginCacheMax+100; i++ {
		g.fail("admin", "192.0.2.3:80")
		g.success("admin", "192.0.2.3:80")
	}
	if len(g.attempts) > loginCacheMax {
		t.Fatal("cache unbounded")
	}
}
