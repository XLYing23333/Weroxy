// Package policy merges connection limits and admits visitors before OPEN.
package policy

import (
	"net"
	"sync"
	"time"
)

const (
	// ReasonBanned means a ban matched the visitor and no tighter allow can override it.
	ReasonBanned = "banned"
	// ReasonPending means a pending-session limit is already full.
	ReasonPending = "pending_limit"
	// ReasonIP means one visitor address already holds its concurrency limit.
	ReasonIP = "ip_limit"
	// ReasonRate means the visitor exceeded its connection rate.
	ReasonRate = "rate_limit"
	// ReasonAllow means an allow list is present and the visitor is outside it.
	ReasonAllow = "allow_list"
)

// Limit is one numeric policy. Nil means inherit. Zero means disallow.
type Limit struct {
	Set   bool
	Value int
}

// Rule is the policy stored at one scope.
type Rule struct {
	MaxPending Limit
	MaxPerIP   Limit
	RatePerSec Limit
	Burst      Limit
	IdleSec    Limit
	ConnectSec Limit
	WaitSec    Limit
	Bandwidth  Limit
}

// Ban is a CIDR that rejects business visitors. It does not apply to control connections.
type Ban struct {
	Scope string
	Key   string
	Net   *net.IPNet
}

// Allow is a CIDR that can pass a scope only when that scope also has an allow list.
type Allow struct {
	Scope string
	Key   string
	Net   *net.IPNet
}

// Effective keeps the tighter of each level. A child cannot loosen a parent.
func Effective(global, device, forward Rule) Rule {
	return Rule{
		MaxPending: tighten(tighten(Limit{}, global.MaxPending), device.MaxPending, forward.MaxPending),
		MaxPerIP:   tighten(tighten(Limit{}, global.MaxPerIP), device.MaxPerIP, forward.MaxPerIP),
		RatePerSec: tighten(tighten(Limit{}, global.RatePerSec), device.RatePerSec, forward.RatePerSec),
		Burst:      tighten(tighten(Limit{}, global.Burst), device.Burst, forward.Burst),
		IdleSec:    tighten(tighten(Limit{}, global.IdleSec), device.IdleSec, forward.IdleSec),
		ConnectSec: tighten(tighten(Limit{}, global.ConnectSec), device.ConnectSec, forward.ConnectSec),
		WaitSec:    tighten(tighten(Limit{}, global.WaitSec), device.WaitSec, forward.WaitSec),
		Bandwidth:  tighten(tighten(Limit{}, global.Bandwidth), device.Bandwidth, forward.Bandwidth),
	}
}

// Looser reports whether child would permit more than the parent effective rule.
func Looser(parent, child Rule) bool {
	return looser(parent.MaxPending, child.MaxPending) ||
		looser(parent.MaxPerIP, child.MaxPerIP) ||
		looser(parent.RatePerSec, child.RatePerSec) ||
		looser(parent.Burst, child.Burst) ||
		looser(parent.IdleSec, child.IdleSec) ||
		looser(parent.ConnectSec, child.ConnectSec) ||
		looser(parent.WaitSec, child.WaitSec) ||
		looser(parent.Bandwidth, child.Bandwidth)
}

func tighten(base Limit, parts ...Limit) Limit {
	current := base
	for _, part := range parts {
		if !part.Set {
			continue
		}
		if !current.Set || part.Value < current.Value {
			current = part
		}
	}
	return current
}

func looser(parent, child Limit) bool {
	if !child.Set {
		return false
	}
	if !parent.Set {
		return false
	}
	return child.Value > parent.Value
}

// Admission counts sessions and visitor rates. Release is idempotent.
type Admission struct {
	mu      sync.Mutex
	now     func() time.Time
	active  map[string]int
	pending map[string]int
	perIP   map[string]int
	buckets map[string]*bucket
	order   []string
	maxIPs  int
	bans    []Ban
	allows  []Allow
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Grant is one accepted visitor. Activate moves it from pending to active.
type Grant struct {
	adm      *Admission
	keys     []string
	ip       string
	once     sync.Once
	active   bool
	released bool
}

// NewAdmission builds an empty limiter. maxIPs bounds the rate-limit cache.
func NewAdmission(maxIPs int) *Admission {
	if maxIPs <= 0 {
		maxIPs = 1024
	}
	return &Admission{
		now:     time.Now,
		active:  map[string]int{},
		pending: map[string]int{},
		perIP:   map[string]int{},
		buckets: map[string]*bucket{},
		maxIPs:  maxIPs,
	}
}

// SetLimits replaces the ban and allow tables. Existing session counts stay.
func (a *Admission) SetLimits(bans []Ban, allows []Allow) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bans = append([]Ban(nil), bans...)
	a.allows = append([]Allow(nil), allows...)
}

// Acquire checks bans, allow lists, and limits before a session is opened.
func (a *Admission) Acquire(ip net.IP, deviceKey, forwardKey string, rule Rule) (*Grant, string) {
	if ip == nil {
		return nil, ReasonAllow
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.banned(ip, deviceKey, forwardKey) {
		return nil, ReasonBanned
	}
	if !a.allowed(ip, deviceKey, forwardKey) {
		return nil, ReasonAllow
	}
	keys := []string{"global", "device:" + deviceKey, "forward:" + forwardKey}
	if reason := a.room(keys, ip.String(), rule); reason != "" {
		return nil, reason
	}
	for _, key := range keys {
		a.pending[key]++
	}
	a.perIP[ip.String()]++
	return &Grant{adm: a, keys: keys, ip: ip.String()}, ""
}

// Activate counts the session as active. It runs once.
func (g *Grant) Activate() {
	if g == nil {
		return
	}
	g.adm.mu.Lock()
	defer g.adm.mu.Unlock()
	if g.active || g.released {
		return
	}
	g.active = true
	for _, key := range g.keys {
		if g.adm.pending[key] > 0 {
			g.adm.pending[key]--
			if g.adm.pending[key] == 0 {
				delete(g.adm.pending, key)
			}
		}
		g.adm.active[key]++
	}
}

// Release drops the grant once, from whichever state it is in.
func (g *Grant) Release() {
	if g == nil {
		return
	}
	g.once.Do(func() {
		g.adm.mu.Lock()
		defer g.adm.mu.Unlock()
		g.released = true
		table := g.adm.pending
		if g.active {
			table = g.adm.active
		}
		for _, key := range g.keys {
			if table[key] > 0 {
				table[key]--
				if table[key] == 0 {
					delete(table, key)
				}
			}
		}
		if g.adm.perIP[g.ip] > 0 {
			g.adm.perIP[g.ip]--
			if g.adm.perIP[g.ip] == 0 {
				delete(g.adm.perIP, g.ip)
			}
		}
	})
}

func (a *Admission) banned(ip net.IP, deviceKey, forwardKey string) bool {
	for _, ban := range a.bans {
		if !matchScope(ban.Scope, ban.Key, deviceKey, forwardKey) || !ban.Net.Contains(ip) {
			continue
		}
		return true
	}
	return false
}

func (a *Admission) allowed(ip net.IP, deviceKey, forwardKey string) bool {
	for _, scope := range []struct{ name, key string }{{"global", ""}, {"device", deviceKey}, {"forward", forwardKey}} {
		var rules []Allow
		for _, allow := range a.allows {
			if allow.Scope == scope.name && allow.Key == scope.key {
				rules = append(rules, allow)
			}
		}
		if len(rules) == 0 {
			continue
		}
		matched := false
		for _, allow := range rules {
			if allow.Net.Contains(ip) {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func matchScope(scope, key, deviceKey, forwardKey string) bool {
	switch scope {
	case "global":
		return true
	case "device":
		return key == deviceKey
	case "forward":
		return key == forwardKey
	default:
		return false
	}
}

func (a *Admission) room(keys []string, ip string, rule Rule) string {
	if rule.MaxPending.Set {
		for _, key := range keys {
			if a.pending[key] >= rule.MaxPending.Value {
				return ReasonPending
			}
		}
	}
	if rule.MaxPerIP.Set && a.perIP[ip] >= rule.MaxPerIP.Value {
		return ReasonIP
	}
	if rule.RatePerSec.Set {
		if !a.takeRate(ip, rule.RatePerSec.Value, burstOf(rule)) {
			return ReasonRate
		}
	}
	return ""
}

func burstOf(rule Rule) int {
	if rule.Burst.Set {
		return rule.Burst.Value
	}
	if rule.RatePerSec.Value < 1 {
		return 1
	}
	return rule.RatePerSec.Value
}

func (a *Admission) takeRate(ip string, rate, burst int) bool {
	a.evict()
	now := a.now()
	item := a.buckets[ip]
	if item == nil {
		item = &bucket{tokens: float64(burst), last: now}
		a.buckets[ip] = item
		a.order = append(a.order, ip)
	}
	elapsed := now.Sub(item.last).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	item.tokens += elapsed * float64(rate)
	if item.tokens > float64(burst) {
		item.tokens = float64(burst)
	}
	item.last = now
	if item.tokens < 1 {
		return false
	}
	item.tokens--
	return true
}

func (a *Admission) evict() {
	if len(a.buckets) < a.maxIPs {
		return
	}
	cut := len(a.order) / 2
	if cut < 1 {
		cut = 1
	}
	for _, ip := range a.order[:cut] {
		delete(a.buckets, ip)
	}
	a.order = append([]string(nil), a.order[cut:]...)
}

// Table holds the three policy levels. A nil table means unlimited.
type Table struct {
	mu      sync.RWMutex
	global  Rule
	device  map[string]Rule
	forward map[string]Rule
}

// Replace swaps the stored rules. Existing admissions keep their grants.
func (t *Table) Replace(global Rule, device, forward map[string]Rule) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.global = global
	t.device = device
	t.forward = forward
}

// Effective returns the tightened rule for one forward.
func (t *Table) Effective(device, forward string) Rule {
	if t == nil {
		return Rule{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return Effective(t.global, t.device[device], t.forward[forward])
}

// SetClock replaces the monotonic-enough clock used by tests.
func (a *Admission) SetClock(now func() time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.now = now
}
