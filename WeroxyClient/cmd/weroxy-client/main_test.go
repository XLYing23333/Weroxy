package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"encoding/hex"
	"weroxy/client/internal/buildinfo"
	"weroxy/client/internal/config"
	wp "weroxy/client/internal/protocol/weroxy"
	"weroxy/client/internal/secure"
)

func TestVersionDoesNotReadKey(t *testing.T) {
	t.Setenv("LANPROXY_KEY", "client-key-value")
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := run([]string{"version"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(buf.String(), "weroxy-client "+buildinfo.Version) {
		t.Fatalf("output=%s", buf.String())
	}
	if strings.Contains(buf.String(), "client-key-value") {
		t.Fatal("version printed a key")
	}
	if code := run([]string{"run"}); code != 2 {
		t.Fatalf("run code=%d", code)
	}
}

func TestRejectTokenFlag(t *testing.T) {
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	code := run([]string{"run", "--token=supersecretvalue"})
	w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	if code != 2 {
		t.Fatalf("code=%d", code)
	}
	if strings.Contains(buf.String(), "supersecretvalue") {
		t.Fatal("token flag was echoed")
	}
}

func TestKeyStdinRejectsShortToken(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "client.conf")
	body := "server.host=127.0.0.1\nserver.port=1\nclient.key=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	commandStdin = strings.NewReader("abcd\n")
	t.Cleanup(func() { commandStdin = os.Stdin })
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	code := run([]string{"run", "--config", cfg, "--key-stdin"})
	w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	if code != 2 {
		t.Fatalf("code=%d err=%s", code, buf.String())
	}
	if strings.Contains(buf.String(), "not-the-stdin-token") {
		t.Fatal("key file was echoed")
	}
}

func TestInitWritesPlainProfile(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "client", "client.conf")
	key := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	commandStdin = strings.NewReader(key + "\n")
	t.Cleanup(func() { commandStdin = os.Stdin })
	oldOut, oldErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	os.Stderr = w
	code := run([]string{"init", "--config", cfg, "--host", "127.0.0.1", "--key-stdin"})
	w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	if code != 0 {
		t.Fatalf("code=%d out=%s", code, buf.String())
	}
	if strings.Contains(buf.String(), key) {
		t.Fatal("init printed the key")
	}
	loaded, err := config.Load(cfg)
	if err != nil || loaded.Server != "127.0.0.1:29999" {
		t.Fatalf("server=%s err=%v", loaded.Server, err)
	}
	body, err := os.ReadFile(cfg)
	if err != nil || strings.Contains(string(body), "listen") || strings.Contains(string(body), "forward") {
		t.Fatalf("profile=%s", body)
	}
	if _, err := os.Stat(filepath.Join(dir, "client", "weroxy-tls.crt")); !os.IsNotExist(err) {
		t.Fatal("unexpected certificate")
	}

}

func TestAllowCommandAddsAndRemovesExactTargetWithoutKeyOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.conf")
	key := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if err := config.Save(path, "127.0.0.1", key, "29999"); err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = w, w
	codeAdd := run([]string{"allow", "add", "--config", path, "--target", "127.0.0.1:22"})
	codeList := run([]string{"allow", "list", "--config", path})
	codeRemove := run([]string{"allow", "remove", "--config", path, "--target", "127.0.0.1:22"})
	w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	var output bytes.Buffer
	_, _ = io.Copy(&output, r)
	if codeAdd != 2 || codeList != 2 || codeRemove != 2 {
		t.Fatalf("codes=%d/%d/%d output=%s", codeAdd, codeList, codeRemove, output.String())
	}
	if !strings.Contains(output.String(), "removed") || strings.Contains(output.String(), key) {
		t.Fatalf("output=%s", output.String())
	}
	loaded, err := config.Load(path)
	if err != nil || loaded.Key != key {
		t.Fatalf("load err=%v", err)
	}
}

func TestMenuUsesRequestedUserDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "elsewhere"))
	got, err := defaultMenuConfig()
	if err != nil || got != filepath.Join(home, ".config", "weroxy_client", "client.conf") {
		t.Fatalf("got=%s err=%v", got, err)
	}
}

func TestRejectedCredentialsReturnNonRestartableExit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	path := filepath.Join(t.TempDir(), "client.conf")
	if err = config.Save(path, host, strings.Repeat("01", 32), port); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		selector, err := secure.ReadPreface(c, 'C')
		if err != nil {
			return
		}
		token, _ := hex.DecodeString(strings.Repeat("01", 32))
		cred := secure.Derive(token, "control")
		encrypted, _, err := secure.Server(c, 'C', selector, cred.PSK, nil, nil)
		if err != nil {
			return
		}
		c = encrypted
		reader := wp.Reader{R: c}
		var body, raw []byte
		auth, err := reader.Next()
		if err != nil {
			return
		}
		body, _ = wp.PutError(wp.CodeAuth, "")
		raw, _ = wp.Encode(wp.Frame{Type: wp.TypeError, RequestID: auth.RequestID, Body: body})
		c.Write(raw)
	}()
	if code := runTunnel([]string{"--config", path}); code != 78 {
		t.Fatalf("credential rejection exit=%d", code)
	}
	<-done
	unit, err := os.ReadFile("../../deploy/weroxycli.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "RestartPreventExitStatus=2 78") {
		t.Fatal("systemd would loop on invalid configuration or credentials")
	}
}
