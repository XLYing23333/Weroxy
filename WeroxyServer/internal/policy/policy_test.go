package policy

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestTightenAndRejectLooserChild(t *testing.T) {
	global := Rule{MaxPerIP: Limit{Set: true, Value: 2}}
	device := Rule{}
	forward := Rule{MaxPerIP: Limit{Set: true, Value: 2}}
	got := Effective(global, device, forward)
	if !got.MaxPerIP.Set || got.MaxPerIP.Value != 2 {
		t.Fatalf("effective=%+v", got.MaxPerIP)
	}
	if !Looser(got, Rule{MaxPerIP: Limit{Set: true, Value: 3}}) {
		t.Fatal("child must not raise the parent limit")
	}
	denied := Effective(global, Rule{}, Rule{MaxPerIP: Limit{Set: true, Value: 0}})
	if denied.MaxPerIP.Value != 0 {
		t.Fatalf("zero should disallow, got %d", denied.MaxPerIP.Value)
	}
	parent := Effective(Rule{}, Rule{}, Rule{})
	if Looser(parent, Rule{MaxPerIP: Limit{Set: true, Value: 1}}) {
		t.Fatal("an unlimited parent can be tightened")
	}
	globalIdle := Rule{IdleSec: Limit{Set: true, Value: 86400}}
	inherited := Effective(globalIdle, Rule{}, Rule{})
	if !inherited.IdleSec.Set || inherited.IdleSec.Value != 86400 {
		t.Fatalf("idle=%+v", inherited.IdleSec)
	}
	if !Looser(inherited, Rule{IdleSec: Limit{Set: true, Value: 90000}}) {
		t.Fatal("child idle must not exceed the parent")
	}
}

func TestBanDoesNotUseAllowToBypassParent(t *testing.T) {
	adm := NewAdmission(8)
	_, banNet, _ := net.ParseCIDR("127.0.0.1/32")
	_, allowNet, _ := net.ParseCIDR("127.0.0.1/32")
	adm.SetLimits(
		[]Ban{{Scope: "global", Net: banNet}},
		[]Allow{{Scope: "forward", Key: "a/1", Net: allowNet}},
	)
	_, reason := adm.Acquire(net.ParseIP("127.0.0.1"), "box", "a/1", Rule{})
	if reason != ReasonBanned {
		t.Fatalf("reason=%s", reason)
	}
}

func TestPendingReleasedOnceAndRateIsBounded(t *testing.T) {
	adm := NewAdmission(4)
	rule := Rule{MaxPending: Limit{Set: true, Value: 1}, RatePerSec: Limit{Set: true, Value: 1}, Burst: Limit{Set: true, Value: 1}}
	grant, reason := adm.Acquire(net.ParseIP("192.0.2.1"), "box", "f", rule)
	if reason != "" || grant == nil {
		t.Fatal(reason)
	}
	if _, reason := adm.Acquire(net.ParseIP("192.0.2.2"), "box", "f", rule); reason != ReasonPending {
		t.Fatalf("second=%s", reason)
	}
	grant.Release()
	grant.Release()
	clock := time.Unix(0, 0)
	adm.SetClock(func() time.Time { return clock })
	first, reason := adm.Acquire(net.ParseIP("192.0.2.9"), "other", "g", Rule{RatePerSec: Limit{Set: true, Value: 1}, Burst: Limit{Set: true, Value: 1}})
	if reason != "" {
		t.Fatal(reason)
	}
	first.Release()
	if _, reason := adm.Acquire(net.ParseIP("192.0.2.9"), "other", "g", Rule{RatePerSec: Limit{Set: true, Value: 1}, Burst: Limit{Set: true, Value: 1}}); reason != ReasonRate {
		t.Fatalf("rate=%s", reason)
	}
	for i := 0; i < 10; i++ {
		ip := net.IPv4(198, 51, 100, byte(i+1))
		grant, _ := adm.Acquire(ip, "d", "f", Rule{RatePerSec: Limit{Set: true, Value: 1}, Burst: Limit{Set: true, Value: 1}})
		if grant != nil {
			grant.Release()
		}
	}
	if len(adm.buckets) > adm.maxIPs {
		t.Fatalf("buckets=%d", len(adm.buckets))
	}
}

func TestPerIPLimitDoesNotBlockAnotherAddress(t *testing.T) {
	adm := NewAdmission(4)
	rule := Rule{MaxPerIP: Limit{Set: true, Value: 1}}
	grant, reason := adm.Acquire(net.ParseIP("192.0.2.8"), "box", "f", rule)
	if reason != "" || grant == nil {
		t.Fatal(reason)
	}
	if _, reason := adm.Acquire(net.ParseIP("192.0.2.8"), "box", "f", rule); reason != ReasonIP {
		t.Fatalf("same=%s", reason)
	}
	other, reason := adm.Acquire(net.ParseIP("192.0.2.9"), "box", "f", rule)
	if reason != "" || other == nil {
		t.Fatalf("other=%s", reason)
	}
}

func TestLimitChangeDoesNotDropExistingGrant(t *testing.T) {
	adm := NewAdmission(4)
	grant, reason := adm.Acquire(net.ParseIP("192.0.2.4"), "box", "f", Rule{})
	if reason != "" {
		t.Fatal(reason)
	}
	grant.Activate()
	if _, reason := adm.Acquire(net.ParseIP("192.0.2.5"), "box", "f", Rule{MaxPerIP: Limit{Set: true, Value: 0}}); reason != ReasonIP {
		t.Fatalf("new session reason=%s", reason)
	}
	if adm.active["global"] != 1 {
		t.Fatalf("existing grant was dropped: %+v", adm.active)
	}
}

func TestReleasedGrantsDoNotRetainChurnedIdentities(t *testing.T) {
	adm := NewAdmission(32)
	held, _ := adm.Acquire(net.ParseIP("192.0.2.1"), "held", "held/1", Rule{})
	held.Activate()
	for i := 0; i < 10000; i++ {
		ip := net.IPv4(198, byte(i>>16), byte(i>>8), byte(i))
		grant, reason := adm.Acquire(ip, fmt.Sprint(i), fmt.Sprint(i, "/1"), Rule{})
		if reason != "" {
			t.Fatal(reason)
		}
		if i%2 == 0 {
			grant.Activate()
		}
		grant.Release()
		grant.Release()
	}
	if len(adm.perIP) != 1 || len(adm.active) != 3 || len(adm.pending) != 0 {
		t.Fatalf("retained identities: ip=%d active=%d pending=%d", len(adm.perIP), len(adm.active), len(adm.pending))
	}
	held.Release()
	if len(adm.perIP)+len(adm.active)+len(adm.pending) != 0 {
		t.Fatal("released grants retained")
	}
}
