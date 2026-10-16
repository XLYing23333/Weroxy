package webui

import (
	"fmt"
	"testing"
	"time"
)

func TestUnknownSnapshotCannotRecordFalseOffline(t *testing.T) {
	h := &Hub{}
	at := time.Date(2026, 10, 1, 0, 0, 20, 0, time.UTC)
	online := DeviceSample{ID: 1, Name: "legacy", Protocol: "legacy", Online: true}
	h.noteDevices(at, []DeviceSample{online}, time.Minute)
	unknown := online
	unknown.Online = false
	unknown.Unknown = true
	h.noteDevices(at.Add(20*time.Second), []DeviceSample{unknown}, time.Minute)
	if p := h.deviceSamples["legacy:legacy"]; len(p) != 1 || p[0].State != "idle" || !p[0].At.Equal(at) {
		t.Fatal("unknown snapshot changed historical online state")
	}
	offline := unknown
	offline.Unknown = false
	h.noteDevices(at.Add(40*time.Second), []DeviceSample{offline}, time.Minute)
	if p := h.deviceSamples["legacy:legacy"]; len(p) != 2 || p[1].State != "offline" || p[1].At.Second() != 0 {
		t.Fatal("confirmed disconnect was not observed at its actual time")
	}
	h.noteDevices(at.Add(50*time.Second), []DeviceSample{online}, time.Minute)
	if p := h.deviceSamples["legacy:legacy"]; len(p) != 3 || p[2].At.Second() != 10 {
		t.Fatal("reconnect observation was truncated or lost")
	}
}

func TestUnchangedRenamePreservesHistory(t *testing.T) {
	h := &Hub{}
	at := time.Now().UTC()
	h.noteDevices(at, []DeviceSample{{ID: 1, Name: "same", Protocol: "legacy", Online: true}}, time.Minute)
	h.RenameDevice("legacy", 1, "same", "same")
	if len(h.deviceSamples["legacy:same"]) != 1 || len(h.pendingDeviceSamples["legacy:same"]) != 1 {
		t.Fatal("unchanged name discarded history")
	}
}

func TestSamplingJitterDoesNotSkipNextCadence(t *testing.T) {
	for _, cadence := range []time.Duration{time.Minute, 5 * time.Minute} {
		h := &Hub{}
		at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
		device := DeviceSample{ID: 1, Name: "stable", Protocol: "weroxy", Online: true}
		h.noteDevices(at, []DeviceSample{device}, cadence)
		h.noteDevices(at.Add(cadence-100*time.Millisecond), []DeviceSample{device}, cadence)
		points := h.deviceSamples["weroxy:stable"]
		if len(points) != 2 || !points[1].At.Equal(at.Add(cadence-100*time.Millisecond)) {
			t.Fatal("scheduler jitter skipped cadence or changed actual observation time")
		}
		h.noteDevices(at.Add(cadence+time.Second), []DeviceSample{device}, cadence)
		if len(h.deviceSamples["weroxy:stable"]) != 2 {
			t.Fatal("duplicate interval sample")
		}
	}
}

func TestFailedStatusWritesCannotRetainDeletedDevices(t *testing.T) {
	h := &Hub{}
	for i := 0; i < 1000; i++ {
		h.noteDevices(time.Now(), []DeviceSample{{ID: int64(i + 1), Name: fmt.Sprint(i), Protocol: "weroxy", Online: true}}, time.Minute)
		batch := h.TakeDeviceStatus()
		h.noteDevices(time.Now(), nil, time.Minute)
		h.RequeueDeviceStatus(batch)
	}
	if len(h.pendingDeviceSamples) != 0 || len(h.deviceSamples) != 0 {
		t.Fatal("deleted device history retained")
	}
}
