package legacy

import (
	"net"
	"testing"
	"weroxy/server/internal/metrics"
	lp "weroxy/server/internal/protocol/legacy"
)

func TestFinishedBeforeMetricOpenCannotLeaveActiveCounters(t *testing.T) {
	count := metrics.New()
	forward := Forward{ID: 1, DeviceID: 1, Listen: "127.0.0.1:29000", Target: "127.0.0.1:22"}
	svc := New(Options{Count: count, Devices: []Device{{ID: 1, Name: "review"}}, Forwards: []Forward{forward}})

	for i := 0; i < 5000; i++ {
		server, peer := net.Pipe()
		visitor, visitorPeer := net.Pipe()
		ctrl := &control{deviceID: 1, generation: uint64(i + 1), conn: server, send: make(chan lp.Frame, 16), done: make(chan struct{})}
		svc.controls[1] = ctrl
		svc.beforeMetricOpen = func() { svc.retire(ctrl) }
		svc.onVisitor(forward, visitor)
		svc.retire(ctrl)
		peer.Close()
		visitorPeer.Close()
	}
	if len(svc.active)+len(svc.pending) != 0 {
		t.Fatal("runtime sessions retained")
	}
	snapshot := count.Snapshot()
	for _, entry := range snapshot.Sessions {
		if entry.Active {
			t.Fatal("active ghost metric retained")
		}
	}
	if len(snapshot.Sessions) > 1024 {
		t.Fatalf("closed detail budget exceeded: %d", len(snapshot.Sessions))
	}
	t.Logf("5000 forced interleavings: active=0, closed=%d", len(snapshot.Sessions))
}
