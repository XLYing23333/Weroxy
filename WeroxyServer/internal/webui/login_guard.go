package webui

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	loginWindow   = 10 * time.Minute
	loginBan      = 30 * time.Minute
	loginFailures = 5
	loginCacheMax = 2048
)

type loginAttempt struct {
	first        time.Time
	last         time.Time
	blockedUntil time.Time
	failures     int
}

type loginGuard struct {
	mu       sync.Mutex
	attempts map[string]loginAttempt
	now      func() time.Time
	window   time.Duration
	ban      time.Duration
	failures int
}

func newLoginGuard() *loginGuard {
	return &loginGuard{attempts: make(map[string]loginAttempt), now: time.Now,
		window: loginWindow, ban: loginBan, failures: loginFailures}
}

// configure replaces the login limits without dropping existing attempts.
// Disabling the optional guard leaves the baseline login protection active.
func (g *loginGuard) configure(enabled bool, windowSec, failures, banSec int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !enabled {
		g.window, g.ban, g.failures = loginWindow, loginBan, loginFailures
		return
	}
	if windowSec < 30 || windowSec > 86400 || failures < 1 || failures > 100 || banSec < 60 || banSec > 30*86400 {
		return
	}
	g.window = time.Duration(windowSec) * time.Second
	g.ban = time.Duration(banSec) * time.Second
	g.failures = failures
}

func loginSource(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return "unknown"
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	return ip.Unmap().String()
}

func (g *loginGuard) key(username, remote string) string {
	return username + "\x00" + loginSource(remote)
}

func (g *loginGuard) allow(username, remote string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	at, ok := g.attempts[g.key(username, remote)]
	if !ok {
		return true
	}
	now := g.now()
	if !now.Before(at.blockedUntil) && now.Sub(at.first) >= g.window {
		delete(g.attempts, g.key(username, remote))
		return true
	}
	return !now.Before(at.blockedUntil)
}

func (g *loginGuard) fail(username, remote string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	key, now := g.key(username, remote), g.now()
	at, ok := g.attempts[key]
	if !ok || now.Sub(at.first) >= g.window {
		at = loginAttempt{first: now}
	}
	at.failures++
	at.last = now
	if at.failures >= g.failures {
		at.blockedUntil = now.Add(g.ban)
	}
	if !ok && len(g.attempts) >= loginCacheMax {
		oldest := key
		earliest := now
		for item, state := range g.attempts {
			if !state.last.After(earliest) {
				oldest, earliest = item, state.last
			}
		}
		delete(g.attempts, oldest)
	}
	g.attempts[key] = at
}

func (g *loginGuard) success(username, remote string) {
	g.mu.Lock()
	delete(g.attempts, g.key(username, remote))
	g.mu.Unlock()
}
