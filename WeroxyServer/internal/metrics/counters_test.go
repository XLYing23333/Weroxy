package metrics

import (
	"strconv"
	"testing"
)

func TestBytesAreSessionSumNotLayerSum(t *testing.T) {
	c := New()
	c.Open(Weroxy, "1", 7, 9)
	c.Add(Weroxy, "1", Down, 10)
	c.Add(Weroxy, "1", Up, 4)
	c.Add(Weroxy, "1", Up, 0)
	c.Open(Weroxy, "2", 7, 9)
	c.Add(Weroxy, "2", Down, 3)
	c.Close(Weroxy, "2")
	snap := c.Snapshot()
	if snap.GlobalDown != 13 || snap.GlobalUp != 4 {
		t.Fatalf("global up=%d down=%d", snap.GlobalUp, snap.GlobalDown)
	}
	if snap.DeviceDown[7]+snap.ForwardDown[9] != snap.GlobalDown*2 {
		t.Fatal("device and forward totals should each equal the session sum")
	}
	if snap.GlobalDown == snap.DeviceDown[7]+snap.ForwardDown[9] {
		t.Fatal("global must not be the sum of both layers")
	}
	c.Reject("active_limit")
	if c.Snapshot().Rejected["active_limit"] != 1 {
		t.Fatal("reason was not counted")
	}
}

func TestVisitorsGroupByIP(t *testing.T) {
	c := New()
	c.Open(Weroxy, "1", 7, 9)
	c.Annotate(Weroxy, "1", "box", "192.0.2.8", "linux")
	c.Add(Weroxy, "1", Down, 5)
	c.Open(Weroxy, "2", 7, 9)
	c.Annotate(Weroxy, "2", "box", "192.0.2.8", "")
	c.Close(Weroxy, "2")
	rows := c.DeviceVisitors(Weroxy, 7)
	if len(rows) != 1 || rows[0].Connections != 2 || rows[0].Bytes != 5 || rows[0].OS != "linux" || !rows[0].Active {
		t.Fatalf("visitors=%+v", rows)
	}
	if GuessOS([]byte("GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0)\r\n\r\n")) != "windows" {
		t.Fatal("windows user agent was not recognized")
	}
	if GuessOS([]byte("SSH-2.0-OpenSSH")) != "" {
		t.Fatal("ssh should not invent an operating system")
	}
}

func TestPartialWriteCountsOnlyWrittenBytes(t *testing.T) {
	c := New()
	c.Open(Legacy, "9", 1, 2)
	c.Add(Legacy, "9", Down, 6)
	snap := c.Snapshot()
	if snap.GlobalDown != 6 || snap.LegacyDeviceDown[1] != 6 || snap.LegacyForwardDown[2] != 6 || snap.DeviceDown[1] != 0 {
		t.Fatalf("legacy bytes missing from common totals: %+v", snap)
	}
}

func TestClosedSessionRetentionKeepsLifetimeTotals(t *testing.T) {
	c := New()
	for i := 0; i < maxClosedSessions+20; i++ {
		id := strconv.Itoa(i)
		c.Open(Legacy, id, 4, 8)
		c.Add(Legacy, id, Down, 3)
		c.Close(Legacy, id)
		c.Close(Legacy, id)
	}
	snap := c.Snapshot()
	if len(snap.Sessions) != maxClosedSessions {
		t.Fatalf("retained sessions=%d", len(snap.Sessions))
	}
	want := uint64((maxClosedSessions + 20) * 3)
	if snap.GlobalDown != want || snap.LegacyDeviceDown[4] != want || snap.LegacyForwardDown[8] != want {
		t.Fatalf("totals fell after eviction: global=%d device=%d forward=%d", snap.GlobalDown, snap.LegacyDeviceDown[4], snap.LegacyForwardDown[8])
	}
}

func TestLegacyAndWeroxyIDSpacesStaySeparate(t *testing.T) {
	c := New()
	c.Open(Legacy, "l", 1, 2)
	c.Open(Weroxy, "w", 1, 2)
	c.Add(Legacy, "l", Up, 3)
	c.Add(Weroxy, "w", Up, 5)
	snap := c.Snapshot()
	if snap.GlobalUp != 8 || snap.LegacyDeviceUp[1] != 3 || snap.DeviceUp[1] != 5 || snap.LegacyForwardUp[2] != 3 || snap.ForwardUp[2] != 5 {
		t.Fatalf("protocol ID spaces collided: %+v", snap)
	}
}

func TestDeletedEntityTotalsEvictedOnlyAfterDurableSave(t *testing.T) {
	c := New()
	for i := int64(1); i <= 10000; i++ {
		id := strconv.FormatInt(i, 10)
		c.Open(Weroxy, id, i, i)
		c.Add(Weroxy, id, Up, 1)
		c.Close(Weroxy, id)
	}
	saved := c.TotalsSnapshot()
	c.Open(Legacy, "live", 42, 42)
	c.Add(Legacy, "live", Down, 9)
	c.Open(Weroxy, "unsaved", 20000, 20000)
	c.Add(Weroxy, "unsaved", Up, 7)
	c.Close(Weroxy, "unsaved")
	c.PruneTotals(Snapshot{DeviceUp: map[int64]uint64{1: 1}, ForwardUp: map[int64]uint64{1: 1}}, saved)
	snap := c.TotalsSnapshot()
	if len(snap.DeviceUp) != 2 || len(snap.ForwardUp) != 2 || snap.DeviceUp[1] != 1 || snap.DeviceUp[20000] != 7 || snap.LegacyDeviceDown[42] != 9 || snap.GlobalUp != 10007 {
		t.Fatalf("prune lost live, configured, global or unsaved bytes: %+v", snap)
	}
	c.Close(Legacy, "live")
	c.PruneTotals(Snapshot{}, c.TotalsSnapshot())
	if len(c.deviceUp)+len(c.forwardUp)+len(c.legacyDeviceDown)+len(c.legacyForwardDown) != 0 {
		t.Fatal("deleted totals retained")
	}
}
