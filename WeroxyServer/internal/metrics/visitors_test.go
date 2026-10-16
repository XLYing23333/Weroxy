package metrics

import "testing"

func TestDeleteOfflineVisitorsPreservesDetailsAndTotals(t *testing.T) {
	c := New()
	c.Open(Weroxy, "one", 1, 1)
	c.Annotate(Weroxy, "one", "device", "127.0.0.1", "")
	c.Add(Weroxy, "one", Up, 100)
	deleted, busy := c.DeleteVisitors(Weroxy, 1, []string{"127.0.0.1"})
	if len(deleted) != 0 || len(busy) != 1 {
		t.Fatal("deleted active visitor")
	}
	c.Close(Weroxy, "one")
	deleted, busy = c.DeleteVisitors(Weroxy, 1, []string{"127.0.0.1"})
	if len(deleted) != 1 || len(busy) != 0 || len(c.DeviceVisitors(Weroxy, 1)) != 0 {
		t.Fatal("offline visitor retained")
	}
	snap := c.Snapshot()
	if snap.GlobalUp != 100 || len(snap.Sessions) != 1 {
		t.Fatal("deleted accounting or details")
	}
	c.Open(Legacy, "same", 1, 1)
	c.Annotate(Legacy, "same", "device", "127.0.0.1", "")
	if len(c.DeviceVisitors(Legacy, 1)) != 1 {
		t.Fatal("protocols mixed")
	}
	c.Open(Weroxy, "new", 1, 1)
	c.Annotate(Weroxy, "new", "device", "127.0.0.1", "")
	if r := c.DeviceVisitors(Weroxy, 1); len(r) != 1 || !r[0].Active || r[0].Connections != 1 {
		t.Fatal("new visit did not reappear")
	}
}

func TestBatchVisitorDeleteKeepsActivePeerAndAccounting(t *testing.T) {
	c := New()
	c.Open(Weroxy, "active", 1, 2)
	c.Annotate(Weroxy, "active", "box", "192.0.2.1", "")
	c.Open(Weroxy, "closed", 1, 2)
	c.Annotate(Weroxy, "closed", "box", "192.0.2.2", "")
	c.Add(Weroxy, "closed", Up, 42)
	c.Close(Weroxy, "closed")
	deleted, busy := c.DeleteVisitors(Weroxy, 1, []string{"192.0.2.1", "192.0.2.2"})
	if len(deleted) != 1 || deleted[0] != "192.0.2.2" || len(busy) != 1 || busy[0] != "192.0.2.1" {
		t.Fatalf("partial result: %v %v", deleted, busy)
	}
	visitors := c.DeviceVisitors(Weroxy, 1)
	if len(visitors) != 1 || visitors[0].IP != "192.0.2.1" || !visitors[0].Active {
		t.Fatalf("active peer disappeared: %+v", visitors)
	}
	if c.Snapshot().GlobalUp != 42 || c.Snapshot().ForwardUp[2] != 42 {
		t.Fatal("deletion changed traffic accounting")
	}
}
