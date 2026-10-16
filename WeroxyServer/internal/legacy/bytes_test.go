package legacy

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"weroxy/server/internal/metrics"
	lp "weroxy/server/internal/protocol/legacy"
)

func TestLegacyCountsWrittenPayloadOnly(t *testing.T) {
	count := metrics.New()
	echoAddr := startEcho(t)
	secret, key := testSecret(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	svc := New(Options{
		Secret:     secret,
		Devices:    []Device{{ID: 1, Name: "box", KeyMAC: MAC(secret, []byte(key))}},
		Forwards:   []Forward{{ID: 4, DeviceID: 1, Listen: "127.0.0.1:0", Target: echoAddr}},
		Idle:       5 * time.Second,
		PendingTTL: 2 * time.Second,
		Count:      count,
	})
	control, forwards, err := svc.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client := dial(t, control)
	frames := readFrames(client)
	mustWrite(t, client, lp.Frame{Type: lp.TypeAuth, URI: key})
	mustWrite(t, client, lp.Frame{Type: lp.TypeHeartbeat})
	if beat := waitType(t, frames, lp.TypeHeartbeat); beat.Type != lp.TypeHeartbeat {
		t.Fatal("auth did not stay up")
	}
	visitor := dial(t, forwards[0])
	connect := waitType(t, frames, lp.TypeConnect)
	data := dial(t, control)
	real := dial(t, echoAddr)
	mustWrite(t, data, lp.Frame{Type: lp.TypeConnect, URI: connect.URI + "@" + key})
	_ = bridgeEcho(t, data, real)
	payload := []byte("abcdef")
	if _, err := visitor.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	_ = visitor.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(visitor, reply); err != nil || !bytes.Equal(reply, payload) {
		t.Fatalf("echo err=%v reply=%q", err, reply)
	}
	snap := count.Snapshot()
	if snap.GlobalDown != uint64(len(payload)) || snap.GlobalUp != uint64(len(payload)) {
		t.Fatalf("down=%d up=%d", snap.GlobalDown, snap.GlobalUp)
	}
	if snap.LegacyDeviceDown[1] != uint64(len(payload)) || snap.LegacyForwardDown[4] != uint64(len(payload)) {
		t.Fatalf("legacy bytes missing from common device/forward totals: %+v", snap)
	}
	if snap.GlobalDown+snap.GlobalUp == snap.LegacyDeviceDown[1]+snap.LegacyForwardDown[4]+snap.LegacyDeviceUp[1]+snap.LegacyForwardUp[4] && snap.GlobalDown != 0 {
		t.Fatal("global counted both layers")
	}
}
