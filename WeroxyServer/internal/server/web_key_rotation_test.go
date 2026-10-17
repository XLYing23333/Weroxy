package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"weroxy/server/internal/auth"
	"weroxy/server/internal/legacy"
	"weroxy/server/internal/metrics"
	"weroxy/server/internal/policy"
	wp "weroxy/server/internal/protocol/weroxy"
	"weroxy/server/internal/secure"
	"weroxy/server/internal/storage/sqlite"
	"weroxy/server/internal/webui"
)

func TestWebKeyRotationReachesNoiseRegistryAndPersists(t *testing.T) {
	dir := t.TempDir()
	db, e := sqlite.Open(filepath.Join(dir, "weroxy.db"), sqlite.DefaultQueue)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if e = db.Bootstrap(ctx, auth.NewArgon(), "operator", []byte("local-only-regression")); e != nil {
		t.Fatal(e)
	}
	secret, e := legacy.LoadSecret(dir, true)
	if e != nil {
		t.Fatal(e)
	}
	old := bytes.Repeat([]byte{21}, 32)
	next := bytes.Repeat([]byte{22}, 32)
	other := bytes.Repeat([]byte{23}, 32)
	uid := "00112233445566778899aabbccddeeff"
	otherUID := "11112233445566778899aabbccddeeff"
	for _, d := range []struct {
		name, uid string
		key       []byte
	}{{"rotating", uid, old}, {"unrelated", otherUID, other}} {
		if e = db.AddWeroxyDevice(ctx, d.name, d.uid, legacy.MAC(secret, d.key), hex.EncodeToString(d.key)); e != nil {
			t.Fatal(e)
		}
	}
	svc, _, e := listenWeroxy(ctx, dir, nil, db, "127.0.0.1:0", "127.0.0.1:0", metrics.New(), &policy.Table{}, policy.NewAdmission(32))
	if e != nil {
		t.Fatal(e)
	}
	go pollDevices(ctx, db, nil, svc)
	address := func() string {
		rows, e := db.ListenerReservations(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		for _, r := range rows {
			if r.Role == "weroxy-control" {
				return net.JoinHostPort(r.Host, fmt.Sprint(r.Port))
			}
		}
		t.Fatal("no control listener")
		return ""
	}
	authenticate := func(key []byte, uid string) (net.Conn, error) {
		raw, e := net.DialTimeout("tcp", address(), time.Second)
		if e != nil {
			return nil, e
		}
		raw.SetDeadline(time.Now().Add(time.Second))
		cred := secure.Derive(key, "control")
		conn, _, e := secure.Client(raw, 'C', cred.ID[:], cred.PSK, nil, nil)
		if e != nil {
			raw.Close()
			return nil, e
		}
		b, _ := wp.PutStrings(uid)
		frame, _ := wp.Encode(wp.Frame{Type: wp.TypeAuth, Body: b})
		_, e = conn.Write(frame)
		if e == nil {
			var f wp.Frame
			f, e = (wp.Reader{R: conn}).Next()
			if e == nil && f.Type != wp.TypeSync {
				e = fmt.Errorf("unexpected auth reply")
			}
		}
		if e != nil {
			conn.Close()
			return nil, e
		}
		conn.SetDeadline(time.Time{})
		return conn, nil
	}
	oldControl, e := authenticate(old, uid)
	if e != nil {
		t.Fatal(e)
	}
	defer oldControl.Close()
	unrelated, e := authenticate(other, otherUID)
	if e != nil {
		t.Fatal(e)
	}
	defer unrelated.Close()
	web, e := webui.Start(ctx, webui.Options{Addr: "127.0.0.1:0", DB: db, DataDir: dir})
	if e != nil {
		t.Fatal(e)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 3 * time.Second}
	base := "http://" + web
	post := func(path string, body any, revision bool) int {
		encoded, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", base+path, bytes.NewReader(encoded))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", base)
		if revision {
			rev, e := db.ConfigRevision(ctx, "credential")
			if e != nil {
				t.Fatal(e)
			}
			req.Header.Set("X-Expected-Revision", fmt.Sprint(rev.DesiredRevision))
			req.Header.Set("Idempotency-Key", fmt.Sprintf("test-rotation-%d", time.Now().UnixNano()))
		}
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		return res.StatusCode
	}
	if code := post("/api/v1/auth/login", map[string]string{"username": "operator", "password": "local-only-regression"}, false); code != 200 {
		t.Fatal("login", code)
	}
	replace := func(key string) int {
		return post("/api/v1/devices/key", map[string]string{"name": "rotating", "protocol": "weroxy", "client_key": key}, true)
	}
	if code := replace(hex.EncodeToString(next)); code != 200 {
		t.Fatal("replace", code)
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		r, e := db.ConfigRevision(ctx, "credential")
		if e != nil {
			t.Fatal(e)
		}
		if r.DesiredRevision == r.AppliedRevision {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("key never applied")
		}
		time.Sleep(10 * time.Millisecond)
	}
	oldControl.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = oldControl.Read(make([]byte, 1)); e == nil {
		t.Fatal("old control survived")
	}
	if c, e := authenticate(old, uid); e == nil {
		c.Close()
		t.Fatal("old key accepted")
	}
	fresh, e := authenticate(next, uid)
	if e != nil {
		t.Fatal("new key rejected", e)
	}
	fresh.Close()
	if !svc.OnlineDevices()["unrelated"] {
		t.Fatal("unrelated device disconnected")
	}
	for _, invalid := range []string{"invalid", hex.EncodeToString(other)} {
		if code := replace(invalid); code < 400 {
			t.Fatal("invalid or duplicate key accepted", code)
		}
	}
	stored, _, e := db.ListWeroxy(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, d := range stored {
		if d.Name == "rotating" && !strings.EqualFold(d.ClientKey, hex.EncodeToString(next)) {
			t.Fatal("key changed on rejected request")
		}
	}
	// A fresh runtime reads and derives the persisted replacement credential.
	cancel()
	ctx2, cancel2 := context.WithCancel(t.Context())
	defer cancel2()
	_, _, e = listenWeroxy(ctx2, dir, nil, db, "127.0.0.1:0", "127.0.0.1:0", metrics.New(), &policy.Table{}, policy.NewAdmission(32))
	if e != nil {
		t.Fatal(e)
	}
	restarted, e := authenticate(next, uid)
	if e != nil {
		t.Fatal("persisted key rejected after restart", e)
	}
	restarted.Close()
}
