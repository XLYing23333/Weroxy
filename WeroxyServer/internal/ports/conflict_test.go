package ports

import "testing"

func TestWildcardConflicts(t *testing.T) {
	v4 := Endpoint{Host: "0.0.0.0", Port: 20000}
	local := Endpoint{Host: "127.0.0.1", Port: 20000}
	if !Conflicts(v4, local) {
		t.Fatal("ipv4 wildcard should overlap a specific ipv4 listener")
	}
	other := Endpoint{Host: "192.0.2.10", Port: 20001}
	if Conflicts(v4, other) {
		t.Fatal("different ports do not overlap")
	}
	all := Endpoint{Host: "::", Port: 20000}
	if !Conflicts(all, local) || !Conflicts(all, Endpoint{Host: "2001:db8::1", Port: 20000}) {
		t.Fatal("ipv6 wildcard should overlap both families")
	}
	mapped := Endpoint{Host: "::ffff:127.0.0.1", Port: 20000}
	if !Conflicts(mapped, local) || !Conflicts(v4, mapped) {
		t.Fatal("ipv4-mapped address should overlap ipv4")
	}
	web := Endpoint{Host: "127.0.0.1", Port: WebPort}
	hit, ok := FirstConflict(Reserved(), web)
	if !ok || hit.Port != WebPort {
		t.Fatal("web port must stay reserved")
	}
	for _, port := range []int{LegacyPlainPort, ControlPort} {
		if _, ok := FirstConflict(Reserved(), Endpoint{Host: "127.0.0.1", Port: port}); !ok {
			t.Fatalf("entry port %d must stay reserved", port)
		}
	}
	for _, port := range []int{8090, 8091, 4993} {
		if _, ok := FirstConflict(Reserved(), Endpoint{Host: "127.0.0.1", Port: port}); ok {
			t.Fatalf("obsolete port %d was reserved", port)
		}
	}
}

func TestSharedExclusiveAndReserved(t *testing.T) {
	pool := Pool{First: 21000, Last: 21019, Reserved: 10}
	usable := pool.Usable()
	if len(usable) != 10 || usable[0] != 21000 || usable[len(usable)-1] != 21009 {
		t.Fatalf("usable=%v", usable)
	}
	shared := []Spec{
		{ID: 1, DeviceID: 1, Mode: Shared, Min: 1, Preferred: 1, Max: 4, Enabled: true},
		{ID: 2, DeviceID: 2, Mode: Shared, Min: 1, Preferred: 1, Max: 4, Enabled: true},
		{ID: 3, DeviceID: 3, Mode: Shared, Min: 1, Preferred: 1, Max: 4, Enabled: true},
	}
	out := Allocate(pool, shared)
	ports := map[int]int{}
	for _, item := range out.Assignments {
		if item.Port > 21009 {
			t.Fatalf("reserved port assigned: %d", item.Port)
		}
		ports[item.Port]++
	}
	if len(ports) != 1 || len(out.Rejected) != 0 {
		t.Fatalf("shared ports=%v rejected=%v", ports, out.Rejected)
	}

	wide := Allocate(pool, []Spec{{ID: 7, DeviceID: 7, Mode: Shared, Min: 1, Preferred: 2, Max: 4, Enabled: true}})
	if len(wide.Assignments) != 2 {
		t.Fatalf("preferred assignments=%d", len(wide.Assignments))
	}

	exclusive := []Spec{
		{ID: 1, DeviceID: 1, Mode: Exclusive, Min: 1, Preferred: 1, Max: 1, Enabled: true},
		{ID: 2, DeviceID: 2, Mode: Exclusive, Min: 1, Preferred: 1, Max: 1, Enabled: true},
	}
	small := Pool{First: 1, Last: 1, Reserved: 0}
	got := Allocate(small, exclusive)
	if _, ok := got.Rejected[2]; !ok || len(got.Assignments) != 1 {
		t.Fatalf("assignments=%v rejected=%v", got.Assignments, got.Rejected)
	}
	if got.Rejected[2] != ReasonExclusive && got.Rejected[2] != ReasonGlobalQuota && got.Rejected[2] != ReasonBelowMin {
		t.Fatalf("reason=%s", got.Rejected[2])
	}

	capped := Allocate(pool, []Spec{{
		ID: 9, DeviceID: 9, Mode: Shared, Min: 1, Preferred: 4, Max: 8, DeviceMax: 6, Enabled: true,
	}})
	view := capped.Views[9]
	if view.Current != 4 || view.AvailableMaxTotal != 6 || view.CanGrowBy != 2 {
		t.Fatalf("view=%+v", view)
	}
	found := false
	for _, reason := range view.Reasons {
		if reason == ReasonDeviceQuota {
			found = true
		}
	}
	if !found {
		t.Fatalf("reasons=%v", view.Reasons)
	}
	if !ValidRange(1, 1, 4) || ValidRange(2, 1, 4) || ValidRange(0, 1, 4) {
		t.Fatal("range validation")
	}
	tight := Pool{First: 1, Last: 3, Reserved: 1}
	ordinary := Allocate(tight, []Spec{
		{ID: 1, DeviceID: 1, Mode: Exclusive, Min: 1, Preferred: 1, Max: 1, Enabled: true},
		{ID: 2, DeviceID: 2, Mode: Exclusive, Min: 1, Preferred: 1, Max: 1, Enabled: true},
		{ID: 3, DeviceID: 3, Mode: Exclusive, Min: 1, Preferred: 1, Max: 1, Enabled: true},
	})
	if _, rejected := ordinary.Rejected[3]; !rejected {
		t.Fatal("ordinary allocation used a reserved port")
	}
	for _, item := range ordinary.Assignments {
		if item.Port == 3 {
			t.Fatalf("reserved port assigned: %+v", item)
		}
	}
	allowed := Allocate(tight, []Spec{
		{ID: 1, DeviceID: 1, Mode: Exclusive, Min: 1, Preferred: 1, Max: 1, Enabled: true},
		{ID: 2, DeviceID: 2, Mode: Exclusive, Min: 1, Preferred: 1, Max: 1, Enabled: true},
		{ID: 3, DeviceID: 3, Mode: Exclusive, Min: 1, Preferred: 1, Max: 1, Enabled: true, UseReserved: true},
	})
	if _, rejected := allowed.Rejected[3]; rejected {
		t.Fatalf("authorized reserved allocation rejected: %v", allowed.Rejected)
	}
	gotReserved := false
	for _, item := range allowed.Assignments {
		if item.ForwardID == 3 && item.Port == 3 {
			gotReserved = true
		}
	}
	if !gotReserved {
		t.Fatalf("assignments=%v", allowed.Assignments)
	}
}

func TestDrainKeepsLowerPorts(t *testing.T) {
	items := []Assignment{
		{ForwardID: 1, Port: 5, State: Serving},
		{ForwardID: 1, Port: 6, State: Serving},
		{ForwardID: 2, Port: 7, State: Serving},
	}
	next := MarkDrain(items, 1, 1)
	if next[0].State != Serving || next[1].State != Draining || next[2].State != Serving {
		t.Fatalf("states=%v %v %v", next[0].State, next[1].State, next[2].State)
	}
}

func TestConcurrentExclusiveDoesNotOversubscribe(t *testing.T) {
	book := &Book{pool: Pool{First: 1, Last: 5}}
	errCh := make(chan error, 20)
	for i := 0; i < 20; i++ {
		spec := Spec{ID: int64(i + 1), DeviceID: int64(i + 1), Mode: Exclusive, Min: 1, Preferred: 1, Max: 1, Enabled: true}
		go func(spec Spec) {
			errCh <- book.Try(spec)
		}(spec)
	}
	ok := 0
	for i := 0; i < 20; i++ {
		if <-errCh == nil {
			ok++
		}
	}
	if ok != 5 {
		t.Fatalf("accepted=%d", ok)
	}
	seen := map[int]int{}
	for _, item := range book.Assignments() {
		seen[item.Port]++
		if seen[item.Port] > 1 {
			t.Fatalf("port %d reused", item.Port)
		}
	}
	if len(seen) != 5 {
		t.Fatalf("ports=%v", seen)
	}
}

func TestBookRejectsLaterApplicantThatWouldEvictAcceptedExclusive(t *testing.T) {
	book := &Book{pool: Pool{First: 41000, Last: 41000}}
	old := Spec{ID: 10, DeviceID: 10, Mode: Exclusive, Min: 1, Preferred: 1, Max: 1, Enabled: true}
	if err := book.Try(old); err != nil {
		t.Fatal(err)
	}
	before := book.Assignments()
	later := Spec{ID: 1, DeviceID: 1, Mode: Exclusive, Min: 1, Preferred: 1, Max: 1, Enabled: true}
	if err := book.Try(later); err == nil {
		t.Fatal("later applicant evicted accepted forward")
	}
	after := book.Assignments()
	if len(after) != 1 || len(before) != 1 || after[0].ForwardID != old.ID || after[0].Port != before[0].Port {
		t.Fatalf("before=%v after=%v", before, after)
	}
}
