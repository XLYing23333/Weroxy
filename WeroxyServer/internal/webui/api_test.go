package webui

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"weroxy/server/internal/auth"
	"weroxy/server/internal/logging"
	"weroxy/server/internal/storage/sqlite"
)

func TestManagementSessionAndForwards(t *testing.T) {
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := t.Context()
	pass := auth.NewArgon()
	password := []byte("correct-horse-1")
	if err := db.Bootstrap(ctx, pass, "admin", password); err != nil {
		t.Fatal(err)
	}
	if err := db.SetPortPool(ctx, sqlite.PortSettings{
		ForwardFirst: 29000, ForwardLast: 29099, DataFirst: 29100, DataLast: 29199, Reserved: 10, BindHost: "127.0.0.1",
	}); err != nil {
		t.Fatal(err)
	}
	log := logging.New(logging.Options{Dir: filepath.Join(dir, "logs"), Err: io.Discard})
	defer log.Close()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	addr, err := Start(runCtx, Options{Addr: "127.0.0.1:0", DB: db, Log: log, DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + addr
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	open, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(open.Body)
	open.Body.Close()
	if open.StatusCode != 200 || !bytes.Contains(page, []byte("Weroxy")) {
		t.Fatalf("page status=%d body=%s", open.StatusCode, page)
	}
	if !strings.Contains(open.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") || open.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing management page framing protection: %v", open.Header)
	}

	evil, _ := http.NewRequest(http.MethodPost, base+"/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"correct-horse-1"}`))
	evil.Header.Set("Origin", "https://evil.example")
	evilRes, err := client.Do(evil)
	if err != nil {
		t.Fatal(err)
	}
	evilRes.Body.Close()
	if evilRes.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site login=%d", evilRes.StatusCode)
	}
	denied, err := client.Get(base + "/api/v1/devices")
	if err != nil {
		t.Fatal(err)
	}
	denied.Body.Close()
	if denied.StatusCode != http.StatusUnauthorized {
		t.Fatalf("devices status=%d", denied.StatusCode)
	}

	loginReq, _ := http.NewRequest(http.MethodPost, base+"/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"correct-horse-1"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRes, err := http.DefaultClient.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := io.ReadAll(loginRes.Body)
	loginRes.Body.Close()
	cookie := loginRes.Header.Get("Set-Cookie")
	if !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "SameSite=Lax") || !strings.Contains(cookie, "Max-Age=86400") || strings.Contains(cookie, "Secure") {
		t.Fatalf("cookie=%s", cookie)
	}
	if strings.Contains(string(loginBody), "correct-horse-1") {
		t.Fatal("password echoed")
	}
	client.Jar.SetCookies(loginReq.URL, loginRes.Cookies())

	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"username":"admin","password":"correct-horse-1"}{}`, http.StatusBadRequest},
		{strings.Repeat(" ", int(jsonBodyLimit)+1), http.StatusRequestEntityTooLarge},
	} {
		req, err := http.NewRequest(http.MethodPost, base+"/api/v1/auth/login", strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != tc.want {
			t.Fatalf("bounded login body status=%d want=%d", res.StatusCode, tc.want)
		}
	}

	request := func(path, body string, want int) {
		t.Helper()
		res, err := client.Post(base+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != want {
			payload, _ := io.ReadAll(res.Body)
			t.Fatalf("%s status=%d want=%d body=%s", path, res.StatusCode, want, payload)
		}
	}
	request("/api/v1/devices/key", `{}`, http.StatusBadRequest)

	dashRes, err := client.Get(base + "/api/v1/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	var dash map[string]any
	if err := json.NewDecoder(dashRes.Body).Decode(&dash); err != nil {
		t.Fatal(err)
	}
	dashRes.Body.Close()
	if dash["online_devices"].(float64) != 0 || dash["up_bytes"].(float64) != 0 || dash["down_bytes"].(float64) != 0 {
		t.Fatalf("dashboard=%v", dash)
	}
	if len(dash["series"].([]any)) != 1 {
		t.Fatalf("series=%v", dash["series"])
	}
	if _, ok := dash["devices"].([]any); !ok {
		t.Fatalf("devices=%T", dash["devices"])
	}

	createRes := postJSON(t, client, base+"/api/v1/devices", `{"name":"box","protocol":"weroxy"}`)
	var created struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(createRes, &created); err != nil || len(created.Token) != 64 {
		t.Fatalf("create=%s", createRes)
	}
	listRes, err := client.Get(base + "/api/v1/devices")
	if err != nil {
		t.Fatal(err)
	}
	listBody, _ := io.ReadAll(listRes.Body)
	listRes.Body.Close()
	if !strings.Contains(string(listBody), created.Token) || strings.Contains(string(listBody), "password") {
		t.Fatalf("list key=%s", listBody)
	}
	if !strings.Contains(string(listBody), `"protocol":"weroxy"`) || !strings.Contains(string(listBody), `"online":false`) {
		t.Fatalf("list=%s", listBody)
	}
	boardRes, err := client.Get(base + "/api/v1/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	var board map[string]any
	if err := json.NewDecoder(boardRes.Body).Decode(&board); err != nil {
		t.Fatal(err)
	}
	boardRes.Body.Close()
	rows, _ := board["devices"].([]any)
	if len(rows) != 1 {
		t.Fatalf("device board=%v", board["devices"])
	}
	row := rows[0].(map[string]any)
	if row["name"] != "box" || row["state"] != "offline" || len(row["history"].([]any)) != 1 {
		t.Fatalf("device row=%v", row)
	}

	saved := postJSON(t, client, base+"/api/v1/forwards", `{"device":"box","protocol":"weroxy","listen":"127.0.0.1:29010","target":"127.0.0.1:9","mode":"shared","min":1,"preferred":1,"max":1}`)
	if !strings.Contains(string(saved), "29010") {
		t.Fatalf("forward=%s", saved)
	}
	conflict := postJSON(t, client, base+"/api/v1/forwards", `{"device":"box","protocol":"weroxy","listen":"127.0.0.1:9415","target":"127.0.0.1:9"}`)
	if !strings.Contains(string(conflict), "port_range") && !strings.Contains(string(conflict), "port_conflict") {
		t.Fatalf("web port=%s", conflict)
	}
	channel := postJSON(t, client, base+"/api/v1/forwards", `{"device":"box","protocol":"weroxy","listen":"127.0.0.1:29110","target":"127.0.0.1:9"}`)
	if !strings.Contains(string(channel), "port_range") && !strings.Contains(string(channel), "port_conflict") {
		t.Fatalf("channel=%s", channel)
	}
	legacy := postJSON(t, client, base+"/api/v1/devices", `{"name":"old","protocol":"legacy","client_key":"legacy-key-1"}`)
	if !strings.Contains(string(legacy), "legacy-key-1") {
		t.Fatalf("legacy=%s", legacy)
	}
	again, err := client.Get(base + "/api/v1/devices")
	if err != nil {
		t.Fatal(err)
	}
	againBody, _ := io.ReadAll(again.Body)
	again.Body.Close()
	if !strings.Contains(string(againBody), "legacy-key-1") || !strings.Contains(string(againBody), `"key_saved":true`) {
		t.Fatalf("list after key=%s", againBody)
	}
	if !strings.Contains(string(againBody), `"client_version":null`) || !strings.Contains(string(againBody), "version_unknown") || !strings.Contains(string(againBody), "no_dynamic_data") {
		t.Fatalf("legacy capabilities=%s", againBody)
	}
	if strings.Contains(string(againBody), `"client_version":"1`) || strings.Contains(string(againBody), "lanproxy-client") {
		t.Fatalf("legacy version was invented: %s", againBody)
	}
	changed := postJSON(t, client, base+"/api/v1/devices/key", `{"name":"old","protocol":"legacy","client_key":"legacy-key-2"}`)
	if !strings.Contains(string(changed), "legacy-key-2") {
		t.Fatalf("replace=%s", changed)
	}
	afterKey, err := client.Get(base + "/api/v1/devices")
	if err != nil {
		t.Fatal(err)
	}
	afterKeyBody, _ := io.ReadAll(afterKey.Body)
	afterKey.Body.Close()
	if !strings.Contains(string(afterKeyBody), "legacy-key-2") || strings.Contains(string(afterKeyBody), "legacy-key-1") {
		t.Fatalf("list replacement %s", afterKeyBody)
	}
	removed := postJSON(t, client, base+"/api/v1/forwards/delete", `{"device":"box","protocol":"weroxy","listen":"127.0.0.1:29010"}`)
	if !strings.Contains(string(removed), `"ok":true`) || !strings.Contains(string(removed), `"status":"saved"`) {
		t.Fatalf("delete=%s", removed)
	}
	preview := postJSON(t, client, base+"/api/v1/forwards/preview", `{"device":"box","protocol":"weroxy","listen":"127.0.0.1:9415","target":"127.0.0.1:9","mode":"shared","min":1,"preferred":1,"max":1}`)
	if !strings.Contains(string(preview), `"ok":false`) || !strings.Contains(string(preview), "port_range") {
		t.Fatalf("preview=%s", preview)
	}
	kept, err := client.Get(base + "/api/v1/devices")
	if err != nil {
		t.Fatal(err)
	}
	keptBody, _ := io.ReadAll(kept.Body)
	kept.Body.Close()
	if strings.Contains(string(keptBody), "9415") {
		t.Fatalf("preview wrote a forward %s", keptBody)
	}
	againForward := postJSON(t, client, base+"/api/v1/forwards", `{"device":"box","protocol":"weroxy","listen":"127.0.0.1:29010","target":"127.0.0.1:9","mode":"shared","min":1,"preferred":1,"max":1}`)
	if !strings.Contains(string(againForward), `"status":"saved"`) {
		t.Fatalf("forward status=%s", againForward)
	}
	editPreview := postJSON(t, client, base+"/api/v1/forwards/preview", `{"device":"box","protocol":"weroxy","previous_listen":"127.0.0.1:29010","listen":"127.0.0.1:29010","target":"127.0.0.1:10","mode":"shared","min":1,"preferred":1,"max":1}`)
	if !strings.Contains(string(editPreview), `"ok":true`) {
		t.Fatalf("edit preview=%s", editPreview)
	}
	edited := postJSON(t, client, base+"/api/v1/forwards", `{"device":"box","protocol":"weroxy","previous_listen":"127.0.0.1:29010","listen":"127.0.0.1:29010","target":"127.0.0.1:10","mode":"shared","min":1,"preferred":1,"max":1}`)
	if !strings.Contains(string(edited), `"status":"saved"`) {
		t.Fatalf("edit=%s", edited)
	}
	failedEdit := postJSON(t, client, base+"/api/v1/forwards", `{"device":"box","protocol":"weroxy","previous_listen":"127.0.0.1:29010","listen":"127.0.0.1:9415","target":"127.0.0.1:11","mode":"shared","min":1,"preferred":1,"max":1}`)
	if !strings.Contains(string(failedEdit), "port_range") && !strings.Contains(string(failedEdit), "port_conflict") {
		t.Fatalf("failed edit=%s", failedEdit)
	}
	_, storedForwards, err := db.ListWeroxy(ctx)
	if err != nil || len(storedForwards) != 1 || storedForwards[0].Listen != "127.0.0.1:29010" || storedForwards[0].Target != "127.0.0.1:10" {
		t.Fatalf("forward after failed edit=%v err=%v", storedForwards, err)
	}
	policySaved := postJSON(t, client, base+"/api/v1/policy", `{"scope":"device","device":"box","listen":"","max_per_ip":2,"max_pending":null,"rate":null,"burst":null}`)
	if !strings.Contains(string(policySaved), `"status":"saved"`) {
		t.Fatalf("policy=%s", policySaved)
	}
	banned := postJSON(t, client, base+"/api/v1/bans", `{"scope":"device","device":"box","listen":"","cidr":"10.1.0.0/16","action":"ban"}`)
	if !strings.Contains(string(banned), `"status":"saved"`) {
		t.Fatalf("ban=%s", banned)
	}
	withRule, err := client.Get(base + "/api/v1/devices")
	if err != nil {
		t.Fatal(err)
	}
	withRuleBody, _ := io.ReadAll(withRule.Body)
	withRule.Body.Close()
	if !strings.Contains(string(withRuleBody), `"max_per_ip":2`) || !strings.Contains(string(withRuleBody), "10.1.0.0/16") || !strings.Contains(string(withRuleBody), "version_unknown") {
		t.Fatalf("rules=%s", withRuleBody)
	}
	if !strings.Contains(string(withRuleBody), "legacy-key-2") || !strings.Contains(string(withRuleBody), created.Token) || strings.Contains(string(withRuleBody), "password") {
		t.Fatalf("list key=%s", withRuleBody)
	}
	cleared := postJSON(t, client, base+"/api/v1/bans/delete", `{"scope":"device","device":"box","listen":"","cidr":"10.1.0.0/16","action":"ban"}`)
	if !strings.Contains(string(cleared), `"status":"saved"`) {
		t.Fatalf("unban=%s", cleared)
	}
	disabled := postJSON(t, client, base+"/api/v1/forwards/enabled", `{"device":"box","protocol":"weroxy","listen":"127.0.0.1:29010","enabled":false}`)
	if !strings.Contains(string(disabled), `"enabled":false`) || !strings.Contains(string(disabled), `"status":"saved"`) {
		t.Fatalf("enabled=%s", disabled)
	}
	revoked := postJSON(t, client, base+"/api/v1/devices/revoke", `{"name":"box","protocol":"weroxy"}`)
	if !strings.Contains(string(revoked), `"status":"saved"`) {
		t.Fatalf("revoke=%s", revoked)
	}
	legacyRevoke := postJSON(t, client, base+"/api/v1/devices/revoke", `{"name":"old","protocol":"legacy"}`)
	if !strings.Contains(string(legacyRevoke), "unsupported") {
		t.Fatalf("legacy revoke=%s", legacyRevoke)
	}
	made := postJSON(t, client, base+"/api/v1/devices", `{"name":"gone","protocol":"legacy","client_key":"legacy-key-9"}`)
	if !strings.Contains(string(made), "legacy-key-9") {
		t.Fatalf("gone=%s", made)
	}
	dropped := postJSON(t, client, base+"/api/v1/devices/delete", `{"name":"gone","protocol":"legacy"}`)
	if !strings.Contains(string(dropped), `"status":"saved"`) {
		t.Fatalf("drop=%s", dropped)
	}
	finalList, err := client.Get(base + "/api/v1/devices")
	if err != nil {
		t.Fatal(err)
	}
	finalBody, _ := io.ReadAll(finalList.Body)
	finalList.Body.Close()
	if strings.Contains(string(finalBody), `"name":"gone"`) || strings.Contains(string(finalBody), "10.1.0.0/16") || strings.Contains(string(finalBody), "legacy-key-9") || !strings.Contains(string(finalBody), `"revoked":true`) || !strings.Contains(string(finalBody), `"enabled":false`) {
		t.Fatalf("final=%s", finalBody)
	}

	settingsRes, err := client.Get(base + "/api/v1/settings")
	if err != nil {
		t.Fatal(err)
	}
	settingsBody, _ := io.ReadAll(settingsRes.Body)
	settingsRes.Body.Close()
	if strings.Contains(string(settingsBody), "$argon2") || !strings.Contains(string(settingsBody), "29000") || !strings.Contains(string(settingsBody), "29100") {
		t.Fatalf("settings=%s", settingsBody)
	}
	put := putJSON(t, client, base+"/api/v1/settings", `{"locale":"en","theme":"dark"}`)
	if !strings.Contains(string(put), `"theme":"dark"`) {
		t.Fatalf("theme=%s", put)
	}

	wrong := postJSON(t, client, base+"/api/v1/auth/password", `{"current":"not-the-password","password":"correct-horse-2","confirm":"correct-horse-2"}`)
	if !strings.Contains(string(wrong), `"error":"current"`) || strings.Contains(string(wrong), "not-the-password") {
		t.Fatalf("wrong current=%s", wrong)
	}
	passRes := postJSON(t, client, base+"/api/v1/auth/password", `{"current":"correct-horse-1","password":"123456","confirm":"123456"}`)
	if !strings.Contains(string(passRes), `"ok":true`) || strings.Contains(string(passRes), "123456") {
		t.Fatalf("password=%s", passRes)
	}
	after, err := client.Get(base + "/api/v1/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked status=%d", after.StatusCode)
	}
	loginAgain := postJSON(t, client, base+"/api/v1/auth/login", `{"username":"admin","password":"123456"}`)
	if !strings.Contains(string(loginAgain), `"username":"admin"`) || strings.Contains(string(loginAgain), "123456") {
		t.Fatalf("six-byte login=%s", loginAgain)
	}
}

func TestSetupOnce(t *testing.T) {
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	log := logging.New(logging.Options{Dir: filepath.Join(dir, "logs"), Err: io.Discard})
	defer log.Close()
	runCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	addr, err := Start(runCtx, Options{Addr: "127.0.0.1:0", DB: db, Log: log, DataDir: dir, SetupOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + addr
	status, err := http.Get(base + "/api/v1/setup")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(status.Body)
	status.Body.Close()
	if !strings.Contains(string(body), `"initialized":false`) {
		t.Fatalf("setup=%s", body)
	}
	denied, err := http.Post(base+"/api/v1/setup", "application/json", strings.NewReader(`{"password":"correct-horse-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("remote bootstrap status=%d", denied.StatusCode)
	}
	if err := db.Bootstrap(t.Context(), auth.NewArgon(), "admin", []byte("correct-horse-1")); err != nil {
		t.Fatal(err)
	}
	ready, err := http.Get(base + "/api/v1/setup")
	if err != nil {
		t.Fatal(err)
	}
	readyBody, _ := io.ReadAll(ready.Body)
	ready.Body.Close()
	if !strings.Contains(string(readyBody), `"initialized":true`) {
		t.Fatalf("ready=%s", readyBody)
	}
}

func TestBackupRestoreAndIdleDefault(t *testing.T) {
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := t.Context()
	if err := db.Bootstrap(ctx, auth.NewArgon(), "admin", []byte("correct-horse-1")); err != nil {
		t.Fatal(err)
	}
	var idle int
	if err := db.QueryRow(ctx, `SELECT idle_sec FROM access_policies WHERE scope = 'global' AND scope_key = ''`).Scan(&idle); err != nil {
		t.Fatal(err)
	}
	if idle < 3600 {
		t.Fatalf("idle=%d", idle)
	}
	log := logging.New(logging.Options{Dir: filepath.Join(dir, "logs"), Err: io.Discard})
	defer log.Close()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	addr, err := Start(runCtx, Options{Addr: "127.0.0.1:0", DB: db, Log: log, DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + addr
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	loginReq, _ := http.NewRequest(http.MethodPost, base+"/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"correct-horse-1"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRes, err := client.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	loginRes.Body.Close()
	if loginRes.StatusCode != http.StatusOK {
		t.Fatalf("login=%d", loginRes.StatusCode)
	}
	made := postJSON(t, client, base+"/api/v1/backup", `{}`)
	if !strings.Contains(string(made), `"status":"saved"`) || strings.Contains(string(made), "correct-horse") || strings.Contains(string(made), "$argon2") {
		t.Fatalf("backup=%s", made)
	}
	var payload struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(made, &payload); err != nil || payload.File == "" {
		t.Fatal(err)
	}
	down, err := client.Get(base + "/api/v1/backup/download?file=" + payload.File)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(down.Body)
	down.Body.Close()
	if disposition := down.Header.Get("Content-Disposition"); !strings.Contains(disposition, payload.File) {
		t.Fatalf("disposition=%s file=%s", disposition, payload.File)
	}
	if down.StatusCode != http.StatusOK || len(body) < 16 || bytes.Contains(body, []byte("correct-horse-1")) {
		t.Fatalf("download status=%d bytes=%d", down.StatusCode, len(body))
	}
	check, err := sql.Open("sqlite", filepath.Join(dir, "backups", payload.File))
	if err != nil {
		t.Fatal(err)
	}
	var result string
	if err := check.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil || result != "ok" {
		t.Fatalf("integrity=%s err=%v", result, err)
	}
	check.Close()
	var invalidBackup bytes.Buffer
	form := multipart.NewWriter(&invalidBackup)
	part, err := form.CreateFormFile("file", "invalid.db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("SQLite format 3\x00garbage")); err != nil {
		t.Fatal(err)
	}
	if err := form.WriteField("confirm", "true"); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	invalidRes, err := client.Post(base+"/api/v1/backup/upload", form.FormDataContentType(), &invalidBackup)
	if err != nil {
		t.Fatal(err)
	}
	invalidRes.Body.Close()
	if invalidRes.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid backup status=%d", invalidRes.StatusCode)
	}
	if staged, err := filepath.Glob(filepath.Join(dir, "backups", "upload-*.db")); err != nil || len(staged) != 0 {
		t.Fatalf("failed upload left staged files: %v %v", staged, err)
	}
	restored := postJSON(t, client, base+"/api/v1/backup/restore", `{"file":"`+payload.File+`","confirm":true}`)
	if !strings.Contains(string(restored), `"status":"saved"`) {
		t.Fatalf("restore=%s", restored)
	}
	again, err := client.Get(base + "/api/v1/settings")
	if err != nil {
		t.Fatal(err)
	}
	again.Body.Close()
	if again.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session status=%d", again.StatusCode)
	}
}

func testMutationDomain(path string) string {
	switch {
	case strings.HasPrefix(path, "/api/v1/devices"):
		return "credential"
	case strings.HasPrefix(path, "/api/v1/forwards"):
		return "listener"
	case path == "/api/v1/policy" || strings.HasPrefix(path, "/api/v1/bans"):
		return "policy"
	case strings.HasPrefix(path, "/api/v1/settings"):
		return "ui"
	default:
		return ""
	}
}

func testJSON(t *testing.T, client *http.Client, url, body, method string) []byte {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if domain := testMutationDomain(req.URL.Path); domain != "" {
		revisions, err := client.Get(req.URL.Scheme + "://" + req.URL.Host + "/api/v1/config/revisions")
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Revisions map[string]struct {
				Desired int64 `json:"desired_revision"`
			} `json:"revisions"`
		}
		if err := json.NewDecoder(revisions.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		revisions.Body.Close()
		req.Header.Set("X-Expected-Revision", strconv.FormatInt(result.Revisions[domain].Desired, 10))
		req.Header.Set("Idempotency-Key", strconv.FormatInt(time.Now().UnixNano(), 10))
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return out
}

func postJSON(t *testing.T, client *http.Client, url, body string) []byte {
	return testJSON(t, client, url, body, http.MethodPost)
}

func putJSON(t *testing.T, client *http.Client, url, body string) []byte {
	return testJSON(t, client, url, body, http.MethodPut)
}
