package sqlite

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenPreviewReadsLiveWALWithoutConfigMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weroxy.db")
	live, err := Open(path, DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if err := live.AddLegacyDevice(context.Background(), "box", bytes.Repeat([]byte{1}, 32), "private-box-key"); err != nil {
		t.Fatal(err)
	}
	before := make(map[string][]byte)
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(path + suffix)
		if err == nil {
			before[suffix] = data
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	preview, cleanup, err := OpenPreview(path)
	if err != nil {
		t.Fatal(err)
	}
	devices, _, err := preview.ListLegacy(context.Background())
	_ = preview.Close()
	cleanup()
	if err != nil || len(devices) != 1 || devices[0].ClientKey != "private-box-key" {
		t.Fatalf("snapshot omitted live WAL row: devices=%v err=%v", devices, err)
	}
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(path + suffix)
		if original, ok := before[suffix]; ok {
			if err != nil || !bytes.Equal(original, data) {
				t.Fatalf("source %q changed: %v", suffix, err)
			}
		} else if !os.IsNotExist(err) {
			t.Fatalf("source %q appeared: %v", suffix, err)
		}
	}
}
