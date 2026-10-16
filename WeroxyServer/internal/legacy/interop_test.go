package legacy_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"weroxy/server/internal/cli"
	"weroxy/server/internal/logging"
	"weroxy/server/internal/server"
)

func TestPlainTCPInterop(t *testing.T) {
	javaBin := "/usr/lib/jvm/java-8-openjdk-amd64/bin/java"
	if _, err := os.Stat(javaBin); err != nil {
		t.Skip("optional JRE 8 fixture is unavailable")
	}
	if _, err := os.Stat("../../../RAW/lanproxy-go-client/src/main"); err != nil {
		t.Skip("optional upstream Go client fixture is unavailable")
	}
	libDir := filepath.Join(installedClientHome(t), "distribution", "proxy-client-0.1", "lib")
	jars, err := filepath.Glob(filepath.Join(libDir, "*.jar"))
	if err != nil || len(jars) == 0 {
		t.Skip("optional Java distribution jars are unavailable")
	}
	before := liveClientPIDs(t)
	if out := systemctlActive(t); out != "active" {
		t.Fatalf("lanproxy-client.service state %q", out)
	}

	echo := echoServer(t)
	forward, legacyAddr := twoAddrs(t)
	_, legacyPort, err := net.SplitHostPort(legacyAddr)
	if err != nil {
		t.Fatal(err)
	}
	key := newKey(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "client.key")
	if err := os.WriteFile(keyFile, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCLI(t, "legacy", "device", "add", "--data", dir, "--name", "interop", "--key-file", keyFile)
	runCLI(t, "legacy", "forward", "add", "--data", dir, "--device", "interop", "--listen", forward, "--target", echo)

	log := logging.New(logging.Options{Dir: filepath.Join(dir, "logs")})
	t.Cleanup(func() { _ = log.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(ctx, dir, log, legacyAddr, "", "")
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("serve did not return")
		}
	})
	waitListen(t, legacyAddr)

	javaHome := t.TempDir()
	writeJavaConf(t, javaHome, key, legacyPort)
	javaLog := filepath.Join(dir, "java.log")
	javaCmd := startJava(t, javaBin, javaHome, jars, javaLog)
	if err := waitEcho(forward); err != nil {
		t.Fatalf("java forward failed: %s", redact(readFile(javaLog), key))
	}
	stopProcess(javaCmd)

	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	goLog := filepath.Join(dir, "go-client.log")
	goCmd := startGoClient(t, goBin, key, legacyPort, goLog)
	if err := waitEcho(forward); err != nil {
		t.Fatalf("go forward failed: %s", redact(readFile(goLog), key))
	}
	stopProcess(goCmd)

	if got := systemctlActive(t); got != "active" {
		t.Fatalf("lanproxy-client.service changed to %q", got)
	}
	after := liveClientPIDs(t)
	if strings.Join(before, ",") != strings.Join(after, ",") {
		t.Fatalf("live client pids changed from %v to %v", before, after)
	}
	scanSecret(t, dir, key)
}

func runCLI(t *testing.T, args ...string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := cli.Run(args, cli.Option{Stdout: &stdout, Stderr: &stderr})
	if code != 0 {
		t.Fatalf("cli code=%d stderr=%s", code, stderr.String())
	}
}

func writeJavaConf(t *testing.T, dir, key, port string) {
	t.Helper()
	body := "client.key=" + key + "\nssl.enable=false\nserver.host=127.0.0.1\nserver.port=" + port + "\n"
	if err := os.WriteFile(filepath.Join(dir, "config.properties"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	log4j := "log4j.rootLogger=warn, stdout\n" +
		"log4j.appender.stdout=org.apache.log4j.ConsoleAppender\n" +
		"log4j.appender.stdout.layout=org.apache.log4j.PatternLayout\n" +
		"log4j.appender.stdout.layout.ConversionPattern=%m%n\n"
	if err := os.WriteFile(filepath.Join(dir, "log4j.properties"), []byte(log4j), 0o644); err != nil {
		t.Fatal(err)
	}
}

func startJava(t *testing.T, javaBin, home string, jars []string, logPath string) *exec.Cmd {
	t.Helper()
	classPath := home + string(os.PathListSeparator) + strings.Join(jars, string(os.PathListSeparator))
	cmd := exec.Command(javaBin, "-Dapp.home="+home, "-classpath", classPath, "org.fengfei.lanproxy.client.ProxyClientContainer")
	cmd.Dir = home
	logFile := createLog(t, logPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopProcess(cmd) })
	return cmd
}

func startGoClient(t *testing.T, goBin, key, port, logPath string) *exec.Cmd {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := filepath.Abs("../../../RAW/lanproxy-go-client/src/main")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(raw, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, entry.Name()), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mod := "module lanproxy.local\n\ngo 1.27.1\n"
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	get := exec.Command(goBin, "get", "github.com/urfave/cli@v1.22.16")
	get.Dir = src
	get.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if out, err := get.CombinedOutput(); err != nil {
		t.Fatalf("go get: %v %s", err, out)
	}
	bin := filepath.Join(src, "lanproxy-go-client")
	build := exec.Command(goBin, "build", "-buildvcs=false", "-o", bin, ".")
	build.Dir = src
	build.Env = get.Env
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v %s", err, out)
	}
	portN, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-k", key, "-s", "127.0.0.1", "-p", strconv.Itoa(portN), "-ssl", "false")
	logFile := createLog(t, logPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopProcess(cmd) })
	return cmd
}

func waitEcho(addr string) error {
	deadline := time.Now().Add(20 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			last = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = conn.Write([]byte("ping"))
		buf := make([]byte, 4)
		_, err2 := io.ReadFull(conn, buf)
		_ = conn.Close()
		if err == nil && err2 == nil && string(buf) == "ping" {
			return nil
		}
		last = errors.Join(err, err2)
		time.Sleep(300 * time.Millisecond)
	}
	if last == nil {
		last = errors.New("timed out")
	}
	return last
}

func waitListen(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("legacy listen did not open")
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func twoAddrs(t *testing.T) (string, string) {
	t.Helper()
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	a := first.Addr().String()
	b := second.Addr().String()
	first.Close()
	second.Close()
	return a, b
}

func newKey(t *testing.T) string {
	t.Helper()
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf[:])
}

func createLog(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	return file
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

func systemctlActive(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("systemctl", "is-active", "lanproxy-client").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func liveClientPIDs(t *testing.T) []string {
	t.Helper()
	proc, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var pids []string
	for _, entry := range proc {
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		body, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		if err != nil {
			continue
		}
		text := strings.ReplaceAll(string(body), "\x00", " ")
		if strings.Contains(text, installedClientHome(t)) && strings.Contains(text, "ProxyClientContainer") {
			pids = append(pids, pid)
		}
	}
	return pids
}

func scanSecret(t *testing.T, dir, key string) {
	t.Helper()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		base := filepath.Base(path)
		if base == "client.key" || base == "config.properties" || base == "java.log" || base == "go-client.log" || base == "weroxy.db" || base == "weroxy.db-wal" || base == "weroxy.db-shm" {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(body, []byte(key)) {
			t.Fatalf("%s contains client key", path)
		}
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func readFile(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	if len(body) > 4000 {
		body = body[len(body)-4000:]
	}
	return string(body)
}

func redact(text, key string) string {
	return strings.ReplaceAll(text, key, "[redacted]")
}

// The optional integration fixture is local-only and never copied into releases.
func installedClientHome(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("WEROXY_INTEROP_CLIENT_HOME"); path != "" {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(home, "Software", "lanproxy-client")
}
