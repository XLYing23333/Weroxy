package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	notices "weroxy/server"
)

func TestRejectPasswordFlag(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run([]string{"admin", "bootstrap", "--data", dir, "--password=supersecretvalue"}, Option{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "supersecretvalue") || strings.Contains(stdout.String(), "supersecretvalue") {
		t.Fatal("flag value was echoed")
	}
	walkSecret(t, dir, "supersecretvalue")
}

func TestBootstrapResetAndLogs(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("correct-horse-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"admin", "bootstrap", "--data", dir, "--password-file", secret}, Option{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if code != 0 {
		t.Fatalf("bootstrap code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"admin", "bootstrap", "--data", dir, "--password-file", secret}, Option{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if code == 0 || !strings.Contains(stderr.String(), "管理员已存在") {
		t.Fatalf("second code=%d stderr=%s", code, stderr.String())
	}
	next := filepath.Join(dir, "next")
	if err := os.WriteFile(next, []byte("123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"admin", "reset-password", "--data", dir, "--password-file", next}, Option{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if code != 0 {
		t.Fatalf("reset code=%d stderr=%s", code, stderr.String())
	}
	walkSecret(t, filepath.Join(dir, "logs"), "correct-horse-1")
	walkSecret(t, filepath.Join(dir, "logs"), "123456")
	body, err := os.ReadFile(filepath.Join(dir, "weroxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("correct-horse-1")) || bytes.Contains(body, []byte("123456")) {
		t.Fatal("password stored in database file")
	}
}

func TestLegacyDeviceAndForward(t *testing.T) {
	dir := t.TempDir()
	key := "temp-key-0123456789abcdef"
	keyFile := filepath.Join(dir, "client.key")
	if err := os.WriteFile(keyFile, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"legacy", "device", "add", "--data", dir, "--name", "box", "--key-file", keyFile}, Option{
		Stdout: &stdout, Stderr: &stderr,
	})
	if code != 0 {
		t.Fatalf("device code=%d stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), key) || strings.Contains(stderr.String(), key) {
		t.Fatal("client key echoed")
	}
	longFile := filepath.Join(dir, "long.key")
	if err := os.WriteFile(longFile, bytes.Repeat([]byte("k"), 128), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"legacy", "device", "add", "--data", dir, "--name", "long", "--key-file", longFile}, Option{
		Stdout: &stdout, Stderr: &stderr,
	})
	if code == 0 || !strings.Contains(stderr.String(), "超过 127") {
		t.Fatalf("long key code=%d stderr=%s", code, stderr.String())
	}
	info, err := os.Stat(filepath.Join(dir, "legacy-mac.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("secret mode %o", info.Mode().Perm())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"legacy", "forward", "add", "--data", dir, "--device", "box", "--listen", "127.0.0.1:20111", "--target", "127.0.0.1:8080"}, Option{
		Stdout: &stdout, Stderr: &stderr,
	})
	if code != 0 {
		t.Fatalf("forward code=%d stderr=%s", code, stderr.String())
	}
	body, err := os.ReadFile(filepath.Join(dir, "weroxy.db"))
	if err != nil || bytes.Contains(body, []byte(key)) {
		t.Fatal("client key leaked into database file")
	}
	walkSecret(t, filepath.Join(dir, "logs"), key)
	code = Run([]string{"run", "--data", dir, "--legacy-listen"}, Option{Stdout: &stdout, Stderr: &stderr})
	if code != 2 {
		t.Fatalf("missing listen code=%d", code)
	}
}

func TestWeroxyDeviceHidesToken(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run([]string{"weroxy", "device", "add", "--data", dir, "--name", "box", "--token=sekretvalue"}, Option{
		Stdout: &stdout, Stderr: &stderr,
	})
	if code != 2 || strings.Contains(stdout.String()+stderr.String(), "sekretvalue") {
		t.Fatalf("code=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"weroxy", "device", "add", "--data", dir, "--name", "box"}, Option{
		Stdout: &stdout, Stderr: &stderr,
	})
	if code != 0 || !strings.Contains(stdout.String(), "管理页可以再次查看并复制这个 token") {
		t.Fatalf("code=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}
	token := ""
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(line, "token: ") {
			token = strings.TrimPrefix(line, "token: ")
		}
	}
	if len(token) != 64 {
		t.Fatalf("token output=%s", stdout.String())
	}
	stored, err := os.ReadFile(filepath.Join(dir, "weroxy.db"))
	if err != nil || bytes.Contains(stored, []byte(token)) {
		t.Fatal("token leaked into database file")
	}
	walkSecret(t, filepath.Join(dir, "logs"), token)
	if _, err := os.Stat(filepath.Join(dir, "weroxy-tls.key")); !os.IsNotExist(err) {
		t.Fatal("plaintext mode generated a certificate")
	}

}

func walkSecret(t *testing.T, root, secret string) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(body, []byte(secret)) {
			t.Fatalf("%s contains secret", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWeroxyRotatePreservesIdentityAndChangesKey(t *testing.T) {
	dir := t.TempDir()
	var out, errs bytes.Buffer
	opt := Option{Stdout: &out, Stderr: &errs}
	if code := Run([]string{"weroxy", "device", "add", "--data", dir, "--name", "rotatebox"}, opt); code != 0 {
		t.Fatal(code, errs.String())
	}
	before := out.String()
	out.Reset()
	if code := Run([]string{"weroxy", "device", "rotate", "--data", dir, "--name", "rotatebox"}, opt); code != 0 {
		t.Fatal(code, errs.String())
	}
	after := out.String()
	if !strings.HasPrefix(after, "token: ") || strings.Contains(before, strings.TrimSpace(strings.TrimPrefix(after, "token: "))) {
		t.Fatal("key did not rotate")
	}
	logs, _ := os.ReadFile(filepath.Join(dir, "logs", "weroxy.log"))
	if bytes.Contains(logs, []byte(strings.TrimSpace(strings.TrimPrefix(after, "token: ")))) {
		t.Fatal("key logged")
	}
}

func TestNoticesWithoutConfiguration(t *testing.T) {
	var out, errs bytes.Buffer
	if code := Run([]string{"notices"}, Option{Stdout: &out, Stderr: &errs}); code != 0 || out.String() != notices.Text() || errs.Len() != 0 {
		t.Fatalf("notices failed: %s", errs.String())
	}
}
