package menu

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	notices "weroxy/client"
	"weroxy/client/internal/config"
)

type fakeTerminal struct {
	keys   []string
	closed bool
}

func (t *fakeTerminal) Key(context.Context) (string, error) {
	if len(t.keys) == 0 {
		return "", io.EOF
	}
	k := t.keys[0]
	t.keys = t.keys[1:]
	return k, nil
}
func (t *fakeTerminal) Size() (int, int) { return 30, 100 }
func (*fakeTerminal) Pause() error       { return nil }
func (*fakeTerminal) Resume() error      { return nil }
func (t *fakeTerminal) Close() error     { t.closed = true; return nil }

type fakeSystem struct {
	active, enabled string
	calls           []string
	fail            bool
}

func (s *fakeSystem) HasSudo(context.Context) bool            { return true }
func (s *fakeSystem) Active(context.Context) (string, error)  { return s.active, nil }
func (s *fakeSystem) Enabled(context.Context) (string, error) { return s.enabled, nil }
func (s *fakeSystem) record(v string) error {
	s.calls = append(s.calls, v)
	if s.fail {
		return errors.New("fixture failure")
	}
	return nil
}
func (s *fakeSystem) EnsureUser(context.Context) error                      { return s.record("user") }
func (s *fakeSystem) Install(context.Context, string, string, string) error { return s.record("sync") }
func (s *fakeSystem) DaemonReload(context.Context) error                    { return s.record("reload") }
func (s *fakeSystem) Enable(context.Context) error                          { return s.record("enable") }
func (s *fakeSystem) Disable(context.Context) error                         { return s.record("disable") }
func (s *fakeSystem) Start(context.Context) error                           { return s.record("start") }
func (s *fakeSystem) Stop(context.Context) error                            { return s.record("stop") }
func (s *fakeSystem) Restart(context.Context) error                         { return s.record("restart") }
func (s *fakeSystem) Installed(context.Context) bool                        { return true }
func (s *fakeSystem) Remove(context.Context) error                          { return s.record("remove") }
func (s *fakeSystem) Uninstall(context.Context, string) error               { return s.record("uninstall") }

const key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func profile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "client.conf")
	if err := config.Save(p, "localhost", key, ""); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestMenuProfileDefaultPortAndPlainKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "client.conf")
	_ = config.EnsureUserProfile(p)
	term := &fakeTerminal{keys: []string{"enter", "localhost", "enter", "enter", key, "enter", "q"}}
	var out bytes.Buffer
	if Run(t.Context(), Option{ConfigPath: p, System: &fakeSystem{}, Terminal: term, Stdout: &out}) != 0 {
		t.Fatal("run")
	}
	cfg, err := config.Load(p)
	if err != nil || cfg.Server != "localhost:29999" || cfg.Key != key {
		t.Fatalf("saved: %v", err)
	}
	if !strings.Contains(out.String(), key) || !strings.Contains(out.String(), "29999") || strings.Contains(out.String(), "YES") {
		t.Fatal("wrong form")
	}
	if !term.closed {
		t.Fatal("terminal not restored")
	}
}
func TestCancelKeepsExistingProfile(t *testing.T) {
	p := profile(t)
	before, _ := os.ReadFile(p)
	term := &fakeTerminal{keys: []string{"enter", "other-host", "enter", "esc", "q"}}
	Run(t.Context(), Option{ConfigPath: p, System: &fakeSystem{}, Terminal: term, Stdout: io.Discard})
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("cancel wrote configuration")
	}
}
func TestStartAlwaysSyncsAndRestartsIfActive(t *testing.T) {
	for _, active := range []string{"inactive", "active"} {
		sys := &fakeSystem{active: active}
		_, err := apply(t.Context(), Option{ConfigPath: profile(t), System: sys}, "start/restart")
		if err != nil {
			t.Fatal(err)
		}
		want := "user,sync,reload,start"
		if active == "active" {
			want = "user,sync,reload,restart"
		}
		if strings.Join(sys.calls, ",") != want {
			t.Fatal(sys.calls)
		}
	}
}
func TestAutostartDoesNotChangeRuntime(t *testing.T) {
	sys := &fakeSystem{}
	_, _ = apply(t.Context(), Option{System: sys}, "enable")
	_, _ = apply(t.Context(), Option{System: sys}, "disable")
	if strings.Join(sys.calls, ",") != "enable,disable" {
		t.Fatal(sys.calls)
	}
}
func TestUninstallOrderAndFailure(t *testing.T) {
	sys := &fakeSystem{}
	_, err := apply(t.Context(), Option{System: sys}, "uninstall")
	if err != nil || strings.Join(sys.calls, ",") != "stop,disable,uninstall" {
		t.Fatal(sys.calls, err)
	}
	sys = &fakeSystem{fail: true}
	_, err = apply(t.Context(), Option{System: sys}, "uninstall")
	if err == nil || len(sys.calls) != 1 {
		t.Fatal("failed stop continued")
	}
}
func TestStatusIncludesRuntimeAndEnabled(t *testing.T) {
	sys := &fakeSystem{active: "active", enabled: "disabled"}
	lines := strings.Join(statusLines(t.Context(), Option{System: sys}), "\n")
	for _, v := range []string{"系统：", "服务：active", "开机自启：disabled", "控制连接：未知"} {
		if !strings.Contains(lines, v) {
			t.Fatal(lines)
		}
	}
}
func TestNonTerminalOnlyShowsHelp(t *testing.T) {
	var out bytes.Buffer
	sys := &fakeSystem{}
	Run(t.Context(), Option{ConfigPath: profile(t), System: sys, Stdin: strings.NewReader("2\n"), Stdout: &out})
	if len(sys.calls) != 0 || !strings.Contains(out.String(), "interactive terminal") {
		t.Fatal("nonterminal executed an action")
	}
}
func TestFailureStaysInMenu(t *testing.T) {
	var out bytes.Buffer
	sys := &fakeSystem{fail: true}
	term := &fakeTerminal{keys: []string{"down", "down", "enter", "enter", "q"}}
	Run(t.Context(), Option{ConfigPath: profile(t), System: sys, Terminal: term, Stdout: &out})
	if !strings.Contains(out.String(), "fixture failure") {
		t.Fatal("missing failure feedback")
	}
}
func TestProfileRepairsCorruptFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "client.conf")
	os.WriteFile(p, []byte("broken"), 0600)
	term := &fakeTerminal{keys: []string{"enter", "localhost", "enter", "enter", key, "enter", "q"}}
	Run(t.Context(), Option{ConfigPath: p, System: &fakeSystem{}, Terminal: term, Stdout: io.Discard})
	if _, err := config.Load(p); err != nil {
		t.Fatal(err)
	}
	backups, _ := filepath.Glob(p + ".repair-*.bak")
	if len(backups) != 1 {
		t.Fatal("missing repair backup")
	}
}

func TestNoticesAllPages(t *testing.T) {
	term := &fakeTerminal{}
	// Extra keys are harmless: this directly exercises the viewer, not menu actions.
	for range len(notices.Text()) {
		term.keys = append(term.keys, "enter")
	}
	var out bytes.Buffer
	if err := showNotices(t.Context(), term, &out); err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(out.String(), "\x1b[H\x1b[2J", "")
	text = strings.ReplaceAll(text, "Enter: 下一页 / 返回 · Esc: 返回", "")
	compact := func(s string) string { return strings.Join(strings.Fields(s), "") }
	if compact(text) != compact(notices.Text()) {
		t.Fatal("paged notices lost content")
	}
}
