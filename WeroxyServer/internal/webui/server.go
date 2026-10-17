package webui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"weroxy/server/internal/auth"
	"weroxy/server/internal/firewallsync"
	"weroxy/server/internal/logging"
	"weroxy/server/internal/storage/sqlite"
)

const (
	cookieName              = "weroxy_session"
	jsonBodyLimit     int64 = 1 << 16
	backupUploadLimit int64 = 33 << 20
)

// Options starts the management HTTP listener.
type Options struct {
	Addr        string
	QuickList   http.Handler
	DB          *sqlite.DB
	Log         *logging.Logger
	Hub         *Hub
	DataDir     string
	DataPlane   bool
	Firewall    *firewallsync.Manager
	Ready       func() bool
	SetupOutput io.Writer
}

// Start listens until the context ends. The address is the bound host:port.
func Start(ctx context.Context, opt Options) (string, error) {
	if opt.DB == nil {
		return "", errors.New("management database required")
	}
	if opt.Hub == nil {
		opt.Hub = &Hub{}
	}
	handler := &api{
		db:            opt.DB,
		updates:       &updateCache{},
		firewall:      opt.Firewall,
		log:           opt.Log,
		hub:           opt.Hub,
		dataDir:       opt.DataDir,
		pass:          auth.NewArgon(),
		loginGuard:    newLoginGuard(),
		dataPlane:     opt.DataPlane,
		backupOps:     make(chan struct{}, 1),
		downloadSlots: make(chan struct{}, 2),
		streamSlots:   make(chan struct{}, 16),
		requestSlots:  make(chan struct{}, 64),
		passwordSlots: make(chan struct{}, 2),
		stopStreams:   ctx.Done(),
	}
	initialized, err := opt.DB.HasAdmin(ctx)
	if err != nil {
		return "", err
	}
	if !initialized && opt.DataDir != "" {
		handler.setupToken, err = auth.SetupToken(opt.DataDir)
		if err != nil {
			return "", err
		}
	} else if initialized && opt.DataDir != "" {
		_ = os.Remove(auth.SetupPath(opt.DataDir))
	}
	stored, err := opt.DB.LoadDeviceStatus(ctx)
	if err != nil {
		return "", err
	}
	history := make(map[string][]DevicePoint)
	for i := len(stored) - 1; i >= 0; i-- {
		row := stored[i]
		key := row.Protocol + ":" + row.Device
		history[key] = append(history[key], DevicePoint{At: row.At, State: row.State, Sessions: row.Sessions, Up: row.Up, Down: row.Down, DurationSec: row.DurationSec})
	}
	opt.Hub.RestoreDeviceStatus(history)
	if opt.DB != nil {
		ui, err := opt.DB.UI(ctx)
		if err != nil {
			return "", err
		}
		handler.loginGuard.configure(ui.GuardEnabled, ui.GuardFindSec, ui.GuardMaxRetry, ui.GuardBanSec)
	}
	mux := http.NewServeMux()
	if opt.QuickList != nil {
		mux.Handle("/list", opt.QuickList)

	}
	mux.HandleFunc("/healthz", healthHandler(ctx, nil, false))
	mux.HandleFunc("/readyz", healthHandler(ctx, opt.Ready, true))
	mux.HandleFunc("/api/", handler.serve)
	mux.HandleFunc("/", serveStatic)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	if _, _, err := net.SplitHostPort(opt.Addr); err != nil {
		return "", err
	}
	ln, err := net.Listen("tcp", opt.Addr)
	if err != nil {
		return "", err
	}
	if err := opt.DB.RegisterListener(ctx, "web", ln.Addr().String()); err != nil {
		_ = ln.Close()
		return "", err
	}
	a := handler
	go a.backgroundDeviceStatus(ctx)
	a.reconcileLogs(ctx)
	go a.watchLogSettings(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}
	}()
	ln = newBudgetListener(ln)
	go func() {
		err := server.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && opt.Log != nil {
			opt.Log.Error("web closed", map[string]string{"err": err.Error()})
		}
	}()
	if handler.setupToken != "" {
		out := opt.SetupOutput
		if out == nil {
			out = os.Stdout
		}
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		fmt.Fprintf(out, "Administrator setup: http://<server-IP>:%s/init%s (replace <server-IP>; this path expires after setup)\n", port, handler.setupToken)
	}
	return ln.Addr().String(), nil
}

type api struct {
	updates       *updateCache
	setupToken    string
	requestSlots  chan struct{}
	passwordSlots chan struct{}
	streamSlots   chan struct{}
	stopStreams   <-chan struct{}
	db            *sqlite.DB
	log           *logging.Logger
	hub           *Hub
	dataDir       string
	pass          *auth.Argon
	loginGuard    *loginGuard
	dataPlane     bool
	firewall      *firewallsync.Manager
	backupOps     chan struct{}
	downloadSlots chan struct{}
}

func (a *api) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "cross_origin")
		return
	}
	path := r.URL.Path
	// Budgets cover active requests, including pre-authenticated requests. Streams
	// retain their request slot as well as their smaller, independent stream budget.
	if a.requestSlots != nil {
		select {
		case a.requestSlots <- struct{}{}:
			defer func() { <-a.requestSlots }()
		default:
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, "request_capacity")
			return
		}
	}
	passwordOperation := path == "/api/v1/auth/login" || path == "/api/v1/auth/password" || path == "/api/v1/setup"
	if passwordOperation && r.Method == http.MethodPost && a.passwordSlots != nil {
		select {
		case a.passwordSlots <- struct{}{}:
			defer func() { <-a.passwordSlots }()
		default:
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusTooManyRequests, "login_rate")
			return
		}
	}
	if path != "/api/v1/dashboard/events" {
		duration := 10 * time.Second
		if strings.HasPrefix(path, "/api/v1/backup") {
			duration = 2 * time.Minute
		}
		ctx, cancel := context.WithTimeout(r.Context(), duration)
		defer cancel()
		r = r.WithContext(ctx)
		controller := http.NewResponseController(w)
		_ = controller.SetWriteDeadline(time.Now().Add(duration))
		defer controller.SetWriteDeadline(time.Time{})
	}
	if passwordOperation {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second))
	}

	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		limit := jsonBodyLimit
		if path == "/api/v1/backup/upload" {
			limit = backupUploadLimit
		}
		if r.ContentLength > limit {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
	}
	if path == "/api/v1/auth/login" && r.Method == http.MethodPost {
		a.login(w, r)
		return
	}
	if path == "/api/v1/setup" && r.Method == http.MethodPost {
		a.initialize(w, r)
		return
	}
	if path == "/api/v1/setup" && r.Method == http.MethodGet {
		a.setup(w, r)
		return
	}
	user, digest, ok := a.session(r)
	if path == "/api/v1/auth/session" && r.Method == http.MethodGet {
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"username": user})
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	switch {
	case path == "/api/v1/update" && r.Method == http.MethodGet, path == "/api/v1/update/check" && r.Method == http.MethodPost:
		a.update(w, r)
	case path == "/api/v1/firewall/sync" && (r.Method == http.MethodGet || r.Method == http.MethodPut):
		a.firewallSync(w, r)
	case path == "/api/v1/firewall/plan" && r.Method == http.MethodPost:
		a.firewallPreview(w, r)
	case path == "/api/v1/settings/quick-list" && (r.Method == http.MethodGet || r.Method == http.MethodPut):
		a.quickListSettings(w, r)
	case path == "/api/v1/auth/logout" && r.Method == http.MethodPost:
		_ = a.db.RevokeAdminSession(r.Context(), digest)
		clearCookie(w)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case path == "/api/v1/auth/password" && r.Method == http.MethodPost:
		a.password(w, r, user)
	case path == "/api/v1/auth/sessions" && r.Method == http.MethodGet:
		a.adminSessions(w, r, user, digest)
	case path == "/api/v1/auth/sessions/revoke" && r.Method == http.MethodPost:
		a.revokeAdminSession(w, r, user, digest)
	case path == "/api/v1/dashboard/events" && r.Method == http.MethodGet:
		a.dashboardEvents(w, r)
	case path == "/api/v1/dashboard" && r.Method == http.MethodGet:
		a.dashboard(w, r)
	case path == "/api/v1/metrics/history" && r.Method == http.MethodGet:
		a.metricHistory(w, r)
	case path == "/api/v1/connections" && r.Method == http.MethodGet:
		a.connections(w, r)
	case path == "/api/v1/devices" && r.Method == http.MethodGet:
		a.devices(w, r)
	case path == "/api/v1/devices" && r.Method == http.MethodPost:
		a.createDevice(w, r)
	case path == "/api/v1/devices/rename" && r.Method == http.MethodPost:
		a.renameDevice(w, r)
	case path == "/api/v1/devices/visitors/delete" && r.Method == http.MethodPost:
		a.deleteVisitors(w, r)
	case path == "/api/v1/devices/key" && r.Method == http.MethodPost:
		a.replaceKey(w, r)
	case path == "/api/v1/devices/visitors" && r.Method == http.MethodGet:
		a.visitors(w, r)
	case strings.HasPrefix(path, "/api/v1/devices/") && r.Method == http.MethodGet:
		a.device(w, r, strings.TrimPrefix(path, "/api/v1/devices/"))
	case path == "/api/v1/forwards" && r.Method == http.MethodPost:
		a.addForward(w, r)
	case path == "/api/v1/forwards/shrink" && r.Method == http.MethodPost:
		a.shrink(w, r)
	case path == "/api/v1/forwards/preview" && r.Method == http.MethodPost:
		a.previewForward(w, r)
	case path == "/api/v1/forwards/delete" && r.Method == http.MethodPost:
		a.deleteForward(w, r)
	case path == "/api/v1/forwards/enabled" && r.Method == http.MethodPost:
		a.setForwardEnabled(w, r)
	case path == "/api/v1/policy" && r.Method == http.MethodPost:
		a.policy(w, r)
	case path == "/api/v1/bans" && r.Method == http.MethodPost:
		a.ban(w, r)
	case path == "/api/v1/bans/delete" && r.Method == http.MethodPost:
		a.deleteBan(w, r)
	case path == "/api/v1/devices/protocol" && r.Method == http.MethodPost:
		a.switchProtocol(w, r)
	case path == "/api/v1/devices/paused" && r.Method == http.MethodPost:
		a.pauseDevice(w, r)
	case path == "/api/v1/devices/delete" && r.Method == http.MethodPost:
		a.deleteDevice(w, r)
	case path == "/api/v1/devices/revoke" && r.Method == http.MethodPost:
		a.revokeDevice(w, r)
	case path == "/api/v1/deployment/publication" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, publicationStatus(a.dataDir))
	case path == "/api/v1/config/revisions" && r.Method == http.MethodGet:
		a.configRevisions(w, r)
	case path == "/api/v1/settings" && r.Method == http.MethodGet:
		a.settings(w, r)
	case path == "/api/v1/settings" && r.Method == http.MethodPut:
		a.saveSettings(w, r)
	case path == "/api/v1/settings/defaults" && r.Method == http.MethodPut:
		a.saveDefaults(w, r)
	case path == "/api/v1/backup" && r.Method == http.MethodPost:
		a.backup(w, r)
	case path == "/api/v1/backup/download" && r.Method == http.MethodGet:
		a.backupDownload(w, r)
	case path == "/api/v1/backup/restore" && r.Method == http.MethodPost:
		a.backupRestore(w, r)
	case path == "/api/v1/backup/upload" && r.Method == http.MethodPost:
		a.backupUpload(w, r)
	case path == "/api/v1/settings/metrics" && r.Method == http.MethodPut:
		a.saveMetricSettings(w, r)
	case path == "/api/v1/capabilities/firewall" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, probeFirewall(r.Context()))
	default:
		writeError(w, http.StatusNotFound, "not_found")
	}
}

func (a *api) session(r *http.Request) (string, []byte, bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return "", nil, false
	}
	raw, err := hex.DecodeString(cookie.Value)
	if err != nil || len(raw) != 32 {
		return "", nil, false
	}
	sum := sha256.Sum256(raw)
	user, err := a.db.AdminBySession(r.Context(), sum[:])
	if err != nil {
		return "", nil, false
	}
	return user, sum[:], true
}

func (a *api) read(r *http.Request, dest any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func setCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
		MaxAge:   24 * 60 * 60,
	})
}

func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// sameOrigin rejects cross-site browser writes before authentication or password hashing.
// Headerless local tools are accepted only over the loopback interface.
func sameOrigin(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		return err == nil && net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	scheme := "http"
	return parsed.Scheme == scheme && parsed.Host == r.Host
}

func (a *api) backgroundDeviceStatus(ctx context.Context) {
	sample := func() {
		queryCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(queryCtx, http.MethodGet, "http://localhost/api/v1/dashboard", nil)
		if err == nil {
			_, _ = a.dashboardSnapshot(request, 5*time.Minute)
		}
	}
	sample()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sample()
		}
	}
}
