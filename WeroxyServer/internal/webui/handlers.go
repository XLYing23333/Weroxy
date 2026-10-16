package webui

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"weroxy/server/internal/auth"
	"weroxy/server/internal/catalog"
	"weroxy/server/internal/deployment"
	"weroxy/server/internal/legacy"
	"weroxy/server/internal/policy"
	"weroxy/server/internal/ports"
	"weroxy/server/internal/storage/sqlite"
)

func (a *api) setup(w http.ResponseWriter, r *http.Request) {
	ready, err := a.db.HasAdmin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"initialized": ready, "authorized": !ready && auth.SetupMatches(a.setupToken, r.Header.Get("X-Weroxy-Setup"))})
}

func (a *api) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := a.read(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return
	}
	// Request size alone permits oversized usernames to occupy every guard
	// entry. Keep cache identities within the account format and bound hashing.
	if !auth.ValidUsername(body.Username) || len(body.Password) > auth.MaxPasswordLen {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !a.loginGuard.allow(body.Username, r.RemoteAddr) {
		writeError(w, http.StatusTooManyRequests, "login_rate")
		return
	}
	hash, err := a.db.PasswordPHC(r.Context(), body.Username)
	var ok bool
	var verifyErr error
	if err == nil {
		ok, verifyErr = a.pass.Verify([]byte(body.Password), hash)
	}
	if err != nil || verifyErr != nil || !ok {
		a.loginGuard.fail(body.Username, r.RemoteAddr)
		_ = a.db.RecordAudit(r.Context(), "web.login", "failure", body.Username)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	a.loginGuard.success(body.Username, r.RemoteAddr)
	a.issueSession(w, r, body.Username)
}

func (a *api) issueSession(w http.ResponseWriter, r *http.Request, username string) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	sum := sha256.Sum256(raw)
	if err := a.db.CreateAdminSession(r.Context(), username, sum[:], time.Now().Add(24*time.Hour)); err != nil {
		if errors.Is(err, sqlite.ErrSessionCapacity) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "session_capacity")
			return
		}
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	setCookie(w, r, hex.EncodeToString(raw))
	writeJSON(w, http.StatusOK, map[string]string{"username": username})
}

func (a *api) password(w http.ResponseWriter, r *http.Request, user string) {
	var body struct {
		Current  string `json:"current"`
		Password string `json:"password"`
		Confirm  string `json:"confirm"`
	}
	if err := a.read(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return
	}
	if body.Password != body.Confirm {
		writeError(w, http.StatusBadRequest, "mismatch")
		return
	}
	hash, err := a.db.PasswordPHC(r.Context(), user)
	if err != nil {
		writeError(w, http.StatusBadRequest, "current")
		return
	}
	ok, verifyErr := a.pass.Verify([]byte(body.Current), hash)
	if verifyErr != nil || !ok {
		writeError(w, http.StatusBadRequest, "current")
		return
	}
	if err := a.db.ResetPassword(r.Context(), a.pass, user, []byte(body.Password)); err != nil {
		writeError(w, http.StatusBadRequest, "password")
		return
	}
	clearCookie(w)
	a.writeApply(w, map[string]any{"ok": true}, "ui")
}

func (a *api) adminSessions(w http.ResponseWriter, r *http.Request, user string, digest []byte) {
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		limit = value
	}
	var after int64
	if raw := r.URL.Query().Get("after"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 0 {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		after = value
	}
	items, next, err := a.db.ListAdminSessions(r.Context(), user, digest, after, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": items, "next_after": next})
}

func (a *api) revokeAdminSession(w http.ResponseWriter, r *http.Request, user string, digest []byte) {
	var body struct {
		ID int64 `json:"id"`
	}
	if err := a.read(r, &body); err != nil || body.ID < 1 {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	current, err := a.db.RevokeAdminSessionByID(r.Context(), user, body.ID, digest)
	if err != nil {
		if errors.Is(err, sqlite.ErrSession) {
			writeError(w, http.StatusNotFound, "not_found")
		} else {
			writeError(w, http.StatusInternalServerError, "invalid")
		}
		return
	}
	if current {
		clearCookie(w)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "current": current})
}

func (a *api) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	board, err := a.dashboardSnapshot(r.WithContext(ctx))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "invalid")
		return
	}
	writeJSON(w, http.StatusOK, board)
}

func (a *api) dashboardSnapshot(r *http.Request, interval ...time.Duration) (map[string]any, error) {
	list, err := a.deviceList(r)
	if err != nil {
		return nil, err
	}
	samples := make([]DeviceSample, 0, len(list))
	forwards := 0
	for _, item := range list {
		rows, _ := item["forwards"].([]map[string]any)
		forwards += len(rows)
		sessions, _ := item["sessions"].(int)
		up, _ := item["up_bytes"].(uint64)
		down, _ := item["down_bytes"].(uint64)
		online, _ := item["online"].(bool)
		name, _ := item["name"].(string)
		protocol, _ := item["protocol"].(string)
		rtt, _ := item["control_rtt_ms"].(*int64)
		samples = append(samples, DeviceSample{
			ID: item["id"].(int64), Name: name, Protocol: protocol, Online: online, Unknown: item["online_known"] == false, Sessions: sessions, Up: up, Down: down, Forwards: len(rows), ControlRTT: rtt,
		})
	}
	querySettings, cancelSettings := context.WithTimeout(r.Context(), 2*time.Second)
	config, err := a.db.MetricSettings(querySettings)
	cancelSettings()
	if err != nil {
		return nil, err
	}
	board := a.hub.Dashboard(forwards, samples, interval...)
	a.persistDeviceStatus(r.Context())
	board["refresh_sec"] = config.RefreshSec
	board["sample_sec"] = config.SampleSec
	queryCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	history, _, err := a.db.MetricHistory(queryCtx, "1h")
	if err == nil {
		board["traffic_history"] = history
	}
	return board, nil
}

func (a *api) forwardCount(r *http.Request) int {
	_, forwards, err := a.db.ListWeroxy(r.Context())
	if err != nil {
		return 0
	}
	_, legacyForwards, err := a.db.ListLegacy(r.Context())
	if err != nil {
		return len(forwards)
	}
	return len(forwards) + len(legacyForwards)
}

func (a *api) visitors(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("device"))
	if !validName(name) {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	protocol := r.URL.Query().Get("protocol")
	if protocol == "" {
		// Existing callers omitted protocol. Infer only an unambiguous configured name.
		ds, _, err := a.db.ListWeroxy(r.Context())
		if err != nil {
			writeStore(w, err)
			return
		}
		protocol = "legacy"
		for _, d := range ds {
			if d.Name == name {
				protocol = "weroxy"
				break
			}
		}
	}
	id, err := a.deviceIdentity(r.Context(), protocol, name)
	if err != nil {
		writeStore(w, err)
		return
	}
	a.hub.mu.Lock()
	count := a.hub.count
	a.hub.mu.Unlock()
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 || n > 100 {
			writeError(w, 400, "invalid")
			return
		}
		limit = n
	}
	local := count.VisitorTotals(protocol, id)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	items, next, e := a.db.VisitorPage(ctx, protocol, id, r.URL.Query().Get("cursor"), limit, count.VisitorRunID(), local, count.DeviceVisitors(protocol, id))
	if e != nil {
		writeStore(w, e)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"visitors": items, "next_cursor": next})
}

func (a *api) devices(w http.ResponseWriter, r *http.Request) {
	list, err := a.deviceList(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	revisions, err := a.revisions(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": list, "revisions": revisions})
}

func (a *api) device(w http.ResponseWriter, r *http.Request, name string) {
	name = strings.Trim(name, "/")
	if strings.Contains(name, "/") || !validName(name) {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	list, err := a.deviceList(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	for _, item := range list {
		if item["name"] == name {
			writeJSON(w, http.StatusOK, item)
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found")
}

func (a *api) deviceList(r *http.Request) ([]map[string]any, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	weroxyDevices, weroxyForwards, err := a.db.ListWeroxy(r.Context())
	if err != nil {
		return nil, err
	}
	legacyDevices, legacyForwards, err := a.db.ListLegacy(r.Context())
	if err != nil {
		return nil, err
	}
	rules, err := a.db.ListAccessRules(r.Context())
	if err != nil {
		return nil, err
	}
	policies, err := a.db.ListPolicies(r.Context())
	if err != nil {
		return nil, err
	}
	publication := publicationStatus(a.dataDir)
	liveForwards := map[int64]catalog.Row{}
	legacyLive := map[int64]catalog.Row{}
	for _, row := range a.hub.rows() {
		if row.Legacy {
			legacyLive[row.ForwardID] = row
		}
		if !row.Legacy {
			liveForwards[row.ForwardID] = row
		}
	}
	live := a.hub.liveByDevice()
	rtts := a.hub.ControlRTTs()
	// Index once instead of rescanning all forwards for every device.
	weroxyByDevice := make(map[string][]sqlite.WeroxyForward)
	for _, forward := range weroxyForwards {
		weroxyByDevice[forward.Device] = append(weroxyByDevice[forward.Device], forward)
	}
	legacyByDevice := make(map[int64][]sqlite.LegacyForward)
	for _, forward := range legacyForwards {
		legacyByDevice[forward.DeviceID] = append(legacyByDevice[forward.DeviceID], forward)
	}
	var list []map[string]any
	for _, device := range weroxyDevices {
		item, known := live["weroxy:"+device.Name]
		known = known || !a.dataPlane
		var controlRTT *int64
		if value, ok := rtts[device.ID]; ok {
			controlRTT = &value
		}
		physical := map[int]bool{}
		allocationCount := 0
		forwards := []map[string]any{}
		for _, forward := range weroxyByDevice[device.Name] {
			actual, running := liveForwards[forward.ID]
			allocationCount += len(actual.DataPorts)
			for _, port := range actual.DataPorts {
				physical[port] = true
			}
			publishState := publication.Status
			if publishState == "published" || publishState == "partial" {
				publishState = "published"
				if len(actual.DataPorts) == 0 {
					publishState = "unverified"
				}
				for _, port := range actual.DataPorts {
					value := publication.PortStatus[port]
					if value == "" {
						publishState = "missing"
						break
					}
					if value != "published" {
						publishState = value
					}
				}
			}
			if !running {
				publishState = "unverified"
			}

			forwards = append(forwards, map[string]any{
				"listen": forward.Listen, "target": forward.Target, "mode": forward.Mode, "up_bytes": actual.UpBytes, "down_bytes": actual.DownBytes,
				"data_ports": actual.DataPorts, "publication_status": publishState, "device_reachability": actual.DataReachability,
				"runtime_known": running, "data_current": actual.DataCurrent, "data_healthy": actual.DataHealthy, "data_draining": actual.DataDraining, "available_max": actual.AvailableMax, "can_grow": actual.CanGrow, "limiting_reasons": actual.Reasons,
				"min": forward.Min, "preferred": forward.Preferred, "max": forward.Max, "enabled": forward.Enabled, "manual_data_ports": forward.ManualPorts,
			})
		}
		list = append(list, map[string]any{
			"id": device.ID, "name": device.Name, "protocol": "weroxy", "client_key": device.ClientKey, "key_saved": device.ClientKey != "", "online": item.Online, "online_known": known, "sessions": item.Sessions,
			"up_bytes": item.Up, "down_bytes": item.Down, "forwards": withEffective(policies, device.Name, forwards),
			"rules": rulesFor(rules, device.Name), "policies": policiesFor(policies, device.Name),
			"effective":           effectiveJSON(policies, device.Name, ""),
			"data_physical_count": len(physical), "data_allocation_count": allocationCount,
			"revoked": device.Revoked, "paused": device.Paused, "client_version": nil, "control_rtt_ms": controlRTT, "legacy_limits": []string{},
		})
	}
	for _, device := range legacyDevices {
		item, known := live["legacy:"+device.Name]
		known = known || !a.dataPlane
		forwards := []map[string]any{}
		for _, forward := range legacyByDevice[device.ID] {
			forwards = append(forwards, map[string]any{
				"listen": forward.Listen, "target": forward.Target, "mode": "legacy", "enabled": true, "up_bytes": legacyLive[forward.ID].UpBytes, "down_bytes": legacyLive[forward.ID].DownBytes,
			})
		}
		list = append(list, map[string]any{
			"id": device.ID, "name": device.Name, "protocol": "legacy", "client_key": device.ClientKey, "key_saved": device.ClientKey != "", "online": item.Online, "online_known": known, "sessions": item.Sessions,
			"up_bytes": item.Up, "down_bytes": item.Down, "forwards": withEffective(policies, device.Name, forwards),
			"rules": rulesFor(rules, device.Name), "policies": policiesFor(policies, device.Name),
			"effective": effectiveJSON(policies, device.Name, ""),
			"revoked":   false, "paused": device.Paused, "client_version": nil, "control_rtt_ms": nil,
			"legacy_limits": []string{"fixed_listen", "no_dynamic_data", "no_hello", "version_unknown"},
		})
	}
	if list == nil {
		list = []map[string]any{}
	}
	return list, nil
}

func rulesFor(rules []sqlite.AccessRule, device string) []map[string]any {
	out := []map[string]any{}
	for _, rule := range rules {
		if !belongs(rule.Scope, rule.Key, device) {
			continue
		}
		name, listen, _ := strings.Cut(rule.Key, "|")
		if rule.Scope != "forward" {
			name, listen = rule.Key, ""
		}
		out = append(out, map[string]any{
			"scope": rule.Scope, "device": name, "listen": listen, "cidr": rule.CIDR, "action": rule.Action,
			"expires_at": rule.ExpiresAt, "kernel_status": rule.KernelStatus,
			"kernel_retry_count": rule.RetryCount, "policy_generation": rule.Generation,
		})
	}
	return out
}

func policiesFor(rows map[string]sqlite.PolicyValues, device string) []map[string]any {
	out := []map[string]any{}
	for id, row := range rows {
		scope, key, _ := strings.Cut(id, "\n")
		if !belongs(scope, key, device) {
			continue
		}
		name, listen, _ := strings.Cut(key, "|")
		if scope != "forward" {
			name, listen = key, ""
		}
		out = append(out, map[string]any{
			"scope": scope, "device": name, "listen": listen,
			"max_pending": row.MaxPending, "max_per_ip": row.MaxPerIP,
			"rate": row.RatePerSec, "burst": row.Burst,
			"idle_sec": row.IdleSec, "connect_sec": row.ConnectSec, "wait_sec": row.WaitSec, "bandwidth": row.Bandwidth,
		})
	}
	return out
}

func belongs(scope, key, device string) bool {
	if scope == "global" {
		return true
	}
	if scope == "device" {
		return key == device
	}
	name, _, ok := strings.Cut(key, "|")
	return scope == "forward" && ok && name == device
}

func (a *api) createDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name      string `json:"name"`
		Protocol  string `json:"protocol"`
		ClientKey string `json:"client_key"`
	}
	if err := a.read(r, &body); err != nil || !validName(body.Name) {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	secret, err := legacy.LoadSecret(a.dataDir, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	switch body.Protocol {
	case "weroxy":
		raw, token, err := weroxySecret(body.ClientKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		defer func() {
			for i := range raw {
				raw[i] = 0
			}
		}()
		uidRaw := make([]byte, 16)
		if _, err := rand.Read(uidRaw); err != nil {
			writeError(w, http.StatusInternalServerError, "invalid")
			return
		}
		uid := hex.EncodeToString(uidRaw)
		result, ok := a.mutateConfig(w, r, "credential", true, body, func(txCtx context.Context) error {
			if err := a.db.AddWeroxyDevice(txCtx, body.Name, uid, legacy.MAC(secret, raw), token); err != nil {
				return err
			}
			return a.db.RecordAudit(txCtx, "weroxy_device_add", "success", body.Name)
		})
		if !ok {
			return
		}
		response := mutationBody(result, map[string]any{"name": body.Name, "protocol": "weroxy"})
		if !result.Duplicate {
			response["token"] = token
		}
		writeJSON(w, http.StatusOK, response)
	case "legacy":
		key, err := legacySecret(body.ClientKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		result, ok := a.mutateConfig(w, r, "credential", true, body, func(txCtx context.Context) error {
			if err := a.db.AddLegacyDevice(txCtx, body.Name, legacy.MAC(secret, []byte(key)), key); err != nil {
				return err
			}
			return a.db.RecordAudit(txCtx, "legacy_device_add", "success", body.Name)
		})
		if !ok {
			return
		}
		response := mutationBody(result, map[string]any{"name": body.Name, "protocol": "legacy"})
		if !result.Duplicate {
			response["client_key"] = key
		}
		writeJSON(w, http.StatusOK, response)
	default:
		writeError(w, http.StatusBadRequest, "invalid")
	}
}

func (a *api) addForward(w http.ResponseWriter, r *http.Request) {
	body, listen, target, ok := a.readForward(w, r)
	if !ok {
		return
	}
	if _, port, parsed := ports.ParseHostPort(listen); parsed {
		blocked, err := a.hostForwardUnavailable(port)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "host_port_plan_invalid")
			return
		}
		if blocked {
			writeError(w, http.StatusConflict, "host_port_occupied")
			return
		}
	}
	result, ok := a.mutateConfig(w, r, "listener", true, body, func(txCtx context.Context) error {
		var err error
		switch body.Protocol {
		case "legacy":
			if body.PreviousListen != "" {
				err = a.db.UpdateLegacyForward(txCtx, body.Device, body.PreviousListen, listen, target)
			} else {
				err = a.db.AddLegacyForward(txCtx, body.Device, listen, target)
			}
		case "weroxy":
			if body.PreviousListen != "" {
				err = a.db.UpdateWeroxyForward(txCtx, body.Device, body.PreviousListen, listen, target, body.Mode, body.Min, body.Preferred, body.Max, body.ManualPorts)
			} else {
				err = a.db.AddWeroxyForward(txCtx, body.Device, listen, target, body.Mode, body.Min, body.Preferred, body.Max, false, false, body.ManualPorts)
			}
		default:
			return sqlite.ErrPortRange
		}
		if err != nil {
			return err
		}
		if body.Protocol != "weroxy" && len(body.ManualPorts) != 0 {
			return sqlite.ErrPortRange
		}
		action := "forward_add"
		if body.PreviousListen != "" {
			action = "forward_update"
		}
		return a.db.RecordAudit(txCtx, action, "success", body.Device)
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, mutationBody(result, map[string]any{"listen": listen, "target": target, "deployment_required": true}))
}

func (a *api) previewForward(w http.ResponseWriter, r *http.Request) {
	body, listen, target, ok := a.readForward(w, r)
	if !ok {
		return
	}
	if _, port, parsed := ports.ParseHostPort(listen); parsed {
		blocked, err := a.hostForwardUnavailable(port)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "host_port_plan_invalid")
			return
		}
		if blocked {
			writeError(w, http.StatusConflict, "host_port_occupied")
			return
		}
	}
	claims, err := a.db.ListenClaims(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	host, port, parsed := ports.ParseHostPort(listen)
	if !parsed {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	out := map[string]any{
		"ok": true, "error": "", "conflict_role": "",
		"listen": listen, "target": target, "protocol": body.Protocol,
		"mode": body.Mode, "min": body.Min, "preferred": body.Preferred, "max": body.Max,
		"apply": a.applyKind("listen"), "deployment_required": true,
	}
	if body.PreviousListen != "" {
		exists, err := a.db.ForwardExists(r.Context(), body.Protocol, body.Device, body.PreviousListen)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "invalid")
			return
		}
		if !exists {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		oldHost, oldPort, _ := ports.ParseHostPort(body.PreviousListen)
		filtered := make([]ports.Endpoint, 0, len(claims))
		skipped := false
		for _, claim := range claims {
			if !skipped && claim.Role == "forward" && claim.Host == oldHost && claim.Port == oldPort {
				skipped = true
				continue
			}
			filtered = append(filtered, claim)
		}
		claims = filtered
	}
	if hit, conflict := ports.FirstConflict(claims, ports.Endpoint{Host: host, Port: port, Role: "forward"}); conflict {
		out["ok"] = false
		out["error"] = "port_conflict"
		out["conflict_role"] = hit.Role
		writeJSON(w, http.StatusOK, out)
		return
	}
	allowed, err := a.db.ForwardPortAllowed(r.Context(), listen)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	if !allowed && body.PreviousListen != listen {
		out["ok"] = false
		out["error"] = "port_range"
	}
	if body.Protocol == "weroxy" && body.Mode != "" && body.Mode != ports.Shared && body.Mode != ports.Exclusive {
		out["ok"] = false
		out["error"] = "port_range"
	}
	if body.Protocol == "weroxy" && !ports.ValidRange(body.Min, body.Preferred, body.Max) {
		out["ok"] = false
		out["error"] = "port_range"
	}
	if len(body.ManualPorts) != 0 {
		settings, err := a.db.PortPool(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "invalid")
			return
		}
		seen := map[int]bool{}
		if body.Protocol != "weroxy" || len(body.ManualPorts) > 200 || len(body.ManualPorts) < body.Min {
			out["ok"] = false
			out["error"] = "port_range"
		}
		for _, port := range body.ManualPorts {
			if port < settings.DataFirst || port > settings.DataLast-settings.Reserved || seen[port] {
				out["ok"] = false
				out["error"] = "port_range"
			}
			seen[port] = true
		}
	}
	policies, err := a.db.ListPolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	out["effective"] = effectiveJSON(policies, body.Device, listen)
	writeJSON(w, http.StatusOK, out)
}

func (a *api) replaceKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name      string `json:"name"`
		Protocol  string `json:"protocol"`
		ClientKey string `json:"client_key"`
	}
	if err := a.read(r, &body); err != nil || !validName(body.Name) || body.ClientKey == "" {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	secret, err := legacy.LoadSecret(a.dataDir, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	switch body.Protocol {
	case "weroxy":
		raw, token, err := weroxySecret(body.ClientKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		defer func() {
			for i := range raw {
				raw[i] = 0
			}
		}()
		result, ok := a.mutateConfig(w, r, "credential", true, body, func(txCtx context.Context) error {
			if err := a.db.SetWeroxyToken(txCtx, body.Name, legacy.MAC(secret, raw), token); err != nil {
				return err
			}
			return a.db.RecordAudit(txCtx, "weroxy_device_key", "success", body.Name)
		})
		if !ok {
			return
		}
		response := mutationBody(result, map[string]any{"ok": true})
		if !result.Duplicate {
			response["token"] = token
		}
		writeJSON(w, http.StatusOK, response)
	case "legacy":
		key, err := legacySecret(body.ClientKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		result, ok := a.mutateConfig(w, r, "credential", true, body, func(txCtx context.Context) error {
			if err := a.db.SetLegacyKey(txCtx, body.Name, legacy.MAC(secret, []byte(key)), key); err != nil {
				return err
			}
			return a.db.RecordAudit(txCtx, "legacy_device_key", "success", body.Name)
		})
		if !ok {
			return
		}
		response := mutationBody(result, map[string]any{"ok": true})
		if !result.Duplicate {
			response["client_key"] = key
		}
		writeJSON(w, http.StatusOK, response)
	default:
		writeError(w, http.StatusBadRequest, "invalid")
	}
}

func (a *api) deleteForward(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Device   string `json:"device"`
		Protocol string `json:"protocol"`
		Listen   string `json:"listen"`
	}
	if err := a.read(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return
	}
	listen, err := canonical(body.Listen)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	body.Listen = listen
	result, ok := a.mutateConfig(w, r, "listener", true, body, func(txCtx context.Context) error {
		var err error
		switch body.Protocol {
		case "legacy":
			err = a.db.DeleteLegacyForward(txCtx, body.Device, listen)
		case "weroxy":
			err = a.db.DeleteWeroxyForward(txCtx, body.Device, listen)
		default:
			return sqlite.ErrPortRange
		}
		if err != nil {
			return err
		}
		return a.db.RecordAudit(txCtx, "forward_delete", "success", body.Device)
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, mutationBody(result, map[string]any{"ok": true, "deployment_required": true}))
}

func (a *api) setForwardEnabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Device   string `json:"device"`
		Protocol string `json:"protocol"`
		Listen   string `json:"listen"`
		Enabled  bool   `json:"enabled"`
	}
	if err := a.read(r, &body); err != nil || body.Protocol != "weroxy" {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	listen, err := canonical(body.Listen)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	body.Listen = listen
	result, ok := a.mutateConfig(w, r, "listener", true, body, func(txCtx context.Context) error {
		if err := a.db.SetWeroxyForwardEnabled(txCtx, body.Device, listen, body.Enabled); err != nil {
			return err
		}
		return a.db.RecordAudit(txCtx, "forward_enabled", "success", body.Device)
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, mutationBody(result, map[string]any{"ok": true, "enabled": body.Enabled, "deployment_required": true}))
}

func (a *api) switchProtocol(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
	}
	if err := a.read(r, &body); err != nil || !validName(body.Name) {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	secret, err := legacy.LoadSecret(a.dataDir, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	var next string
	result, ok := a.mutateConfig(w, r, "credential", true, body, func(txCtx context.Context) error {
		var err error
		next, err = a.db.SwitchProtocol(txCtx, body.Protocol, body.Name, secret)
		if err != nil {
			return err
		}
		if err := a.db.BumpRelatedRevision(txCtx, "listener"); err != nil {
			return err
		}
		return a.db.RecordAudit(txCtx, "device_protocol", "success", body.Name)
	})
	if !ok {
		return
	}
	if result.Duplicate {
		if body.Protocol == "legacy" {
			next = "weroxy"
		} else {
			next = "legacy"
		}
	}
	writeJSON(w, http.StatusOK, mutationBody(result, map[string]any{"ok": true, "protocol": next}))
}

func (a *api) pauseDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		Paused   bool   `json:"paused"`
	}
	if err := a.read(r, &body); err != nil || !validName(body.Name) || (body.Protocol != "weroxy" && body.Protocol != "legacy") {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	result, ok := a.mutateConfig(w, r, "credential", true, body, func(txCtx context.Context) error {
		if err := a.db.SetDevicePaused(txCtx, body.Protocol, body.Name, body.Paused); err != nil {
			return err
		}
		return a.db.RecordAudit(txCtx, "device_paused", "success", body.Name)
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, mutationBody(result, map[string]any{"ok": true, "paused": body.Paused}))
}

func (a *api) deleteDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
	}
	if err := a.read(r, &body); err != nil || !validName(body.Name) {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	result, ok := a.mutateConfig(w, r, "credential", true, body, func(txCtx context.Context) error {
		var err error
		switch body.Protocol {
		case "weroxy":
			err = a.db.DeleteWeroxyDevice(txCtx, body.Name)
		case "legacy":
			err = a.db.DeleteLegacyDevice(txCtx, body.Name)
		default:
			return sqlite.ErrPortRange
		}
		if err != nil {
			return err
		}
		if err := a.db.BumpRelatedRevision(txCtx, "listener"); err != nil {
			return err
		}
		if err := a.db.BumpRelatedRevision(txCtx, "policy"); err != nil {
			return err
		}
		return a.db.RecordAudit(txCtx, "device_delete", "success", body.Name)
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, mutationBody(result, map[string]any{"ok": true, "deployment_required": true}))
}

func (a *api) revokeDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
	}
	if err := a.read(r, &body); err != nil || !validName(body.Name) || body.Protocol != "weroxy" {
		writeError(w, http.StatusBadRequest, "unsupported")
		return
	}
	result, ok := a.mutateConfig(w, r, "credential", true, body, func(txCtx context.Context) error {
		if err := a.db.RevokeWeroxyDevice(txCtx, body.Name); err != nil {
			return err
		}
		return a.db.RecordAudit(txCtx, "weroxy_device_revoke", "success", body.Name)
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, mutationBody(result, map[string]any{"ok": true}))
}

func weroxySecret(given string) ([]byte, string, error) {
	if given == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil, "", err
		}
		return raw, hex.EncodeToString(raw), nil
	}
	raw, err := hex.DecodeString(given)
	if err != nil || len(raw) != 32 {
		return nil, "", errors.New("token")
	}
	return raw, hex.EncodeToString(raw), nil
}

func legacySecret(given string) (string, error) {
	if given == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		return hex.EncodeToString(raw), nil
	}
	if len(given) < 8 || len(given) > 127 {
		return "", errors.New("key")
	}
	for _, r := range given {
		if r < 0x21 || r > 0x7e {
			return "", errors.New("key")
		}
	}
	return given, nil
}

func (a *api) shrink(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Device string `json:"device"`
		Listen string `json:"listen"`
		Max    int    `json:"max"`
	}
	if err := a.read(r, &body); err != nil || body.Max < 0 {
		writeError(w, http.StatusBadRequest, "bad_json")
		return
	}
	listen, err := canonical(body.Listen)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	body.Listen = listen
	result, ok := a.mutateConfig(w, r, "listener", true, body, func(txCtx context.Context) error {
		if err := a.db.ShrinkForward(txCtx, body.Device, listen, body.Max); err != nil {
			return err
		}
		return a.db.RecordAudit(txCtx, "forward_shrink", "success", body.Device)
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, mutationBody(result, map[string]any{"listen": listen, "max": body.Max}))
}

func (a *api) policy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope      string `json:"scope"`
		Device     string `json:"device"`
		Listen     string `json:"listen"`
		MaxPending *int   `json:"max_pending"`
		MaxPerIP   *int   `json:"max_per_ip"`
		Rate       *int   `json:"rate"`
		Burst      *int   `json:"burst"`
		IdleSec    *int   `json:"idle_sec"`
		ConnectSec *int   `json:"connect_sec"`
		WaitSec    *int   `json:"wait_sec"`
		Bandwidth  *int   `json:"bandwidth"`
	}
	if err := a.read(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return
	}
	key, err := policyKey(body.Scope, body.Device, body.Listen)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	result, ok := a.mutateConfig(w, r, "policy", true, body, func(txCtx context.Context) error {
		if err := a.db.SetPolicy(txCtx, body.Scope, key, sqlite.PolicyValues{
			MaxPending: body.MaxPending, MaxPerIP: body.MaxPerIP, RatePerSec: body.Rate, Burst: body.Burst,
			IdleSec: body.IdleSec, ConnectSec: body.ConnectSec, WaitSec: body.WaitSec, Bandwidth: body.Bandwidth,
		}); err != nil {
			return err
		}
		return a.db.RecordAudit(txCtx, "policy_set", "success", body.Scope)
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, mutationBody(result, map[string]any{"ok": true}))
}

func (a *api) ban(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope      string `json:"scope"`
		Device     string `json:"device"`
		Listen     string `json:"listen"`
		CIDR       string `json:"cidr"`
		Action     string `json:"action"`
		TTLSeconds *int   `json:"ttl_sec"`
	}
	if err := a.read(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return
	}
	key, err := policyKey(body.Scope, body.Device, body.Listen)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	var expires *time.Time
	if body.TTLSeconds != nil {
		if *body.TTLSeconds < 60 || *body.TTLSeconds > 24*60*60 {
			writeError(w, http.StatusBadRequest, "invalid_ttl")
			return
		}
		at := time.Now().UTC().Add(time.Duration(*body.TTLSeconds) * time.Second)
		expires = &at
	} else if body.Action == "ban" {
		at := time.Now().UTC().Add(30 * time.Minute)
		expires = &at
	}
	result, ok := a.mutateConfig(w, r, "policy", true, body, func(txCtx context.Context) error {
		if err := a.db.AddAccessRule(txCtx, sqlite.AccessRule{Scope: body.Scope, Key: key, CIDR: body.CIDR, Action: body.Action, ExpiresAt: expires}); err != nil {
			return err
		}
		return a.db.RecordAudit(txCtx, "access_rule_add", "success", body.Scope)
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, mutationBody(result, map[string]any{"ok": true}))
}

func (a *api) deleteBan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope  string `json:"scope"`
		Device string `json:"device"`
		Listen string `json:"listen"`
		CIDR   string `json:"cidr"`
		Action string `json:"action"`
	}
	if err := a.read(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return
	}
	key, err := policyKey(body.Scope, body.Device, body.Listen)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	result, ok := a.mutateConfig(w, r, "policy", true, body, func(txCtx context.Context) error {
		if err := a.db.DeleteAccessRule(txCtx, sqlite.AccessRule{Scope: body.Scope, Key: key, CIDR: body.CIDR, Action: body.Action}); err != nil {
			return err
		}
		return a.db.RecordAudit(txCtx, "access_rule_delete", "success", body.Scope)
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, mutationBody(result, map[string]any{"ok": true}))
}

func (a *api) settings(w http.ResponseWriter, r *http.Request) {
	ui, err := a.db.UI(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	pool, err := a.db.PortPool(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	plan, _ := deployment.HostPortPlan(a.dataDir)
	unavailableForward := []int{}
	if plan != nil {
		unavailableForward = plan.UnavailableForward
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"locale": ui.Locale,
		"theme":  ui.Theme,
		"pool": map[string]any{
			"enabled": pool.Enabled, "forward_first": pool.ForwardFirst, "forward_last": pool.ForwardLast,
			"unavailable_forward": unavailableForward,
			"data_first":          pool.DataFirst, "data_last": pool.DataLast, "bind_host": pool.BindHost,
		},
		"publication": publicationStatus(a.dataDir),
		"defaults":    a.defaultSettings(r, ui),
	})
}

func (a *api) saveSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Locale string `json:"locale"`
		Theme  string `json:"theme"`
	}
	if err := a.read(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return
	}
	if (body.Locale != "zh" && body.Locale != "en") || (body.Theme != "system" && body.Theme != "light" && body.Theme != "dark") {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	result, ok := a.mutateConfig(w, r, "ui", false, body, func(txCtx context.Context) error {
		current, err := a.db.UI(txCtx)
		if err != nil {
			return err
		}
		current.Locale = body.Locale
		current.Theme = body.Theme
		if err := a.db.SetUI(txCtx, current); err != nil {
			return err
		}
		return a.db.RecordAudit(txCtx, "ui_settings", "success", "")
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"locale": body.Locale, "theme": body.Theme, "status": "applied",
		"domain": result.Domain, "desired_revision": result.DesiredRevision,
		"applied_revision": result.AppliedRevision, "failure_reason": result.FailureReason,
	})
}

type forwardBody struct {
	PreviousListen string `json:"previous_listen"`
	Device         string `json:"device"`
	Protocol       string `json:"protocol"`
	Listen         string `json:"listen"`
	Target         string `json:"target"`
	Mode           string `json:"mode"`
	Min            int    `json:"min"`
	Preferred      int    `json:"preferred"`
	Max            int    `json:"max"`
	ManualPorts    []int  `json:"manual_data_ports"`
}

func (a *api) readForward(w http.ResponseWriter, r *http.Request) (forwardBody, string, string, bool) {
	var body forwardBody
	if err := a.read(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return body, "", "", false
	}
	if body.Protocol != "legacy" && body.Protocol != "weroxy" {
		writeError(w, http.StatusBadRequest, "invalid")
		return body, "", "", false
	}
	listen, err := canonical(body.Listen)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid")
		return body, "", "", false
	}
	target, err := canonical(body.Target)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid")
		return body, "", "", false
	}
	if body.PreviousListen != "" {
		previous, err := canonical(body.PreviousListen)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid")
			return body, "", "", false
		}
		body.PreviousListen = previous
	}
	if body.Protocol == "weroxy" && body.Min == 0 && body.Preferred == 0 && body.Max == 0 {
		body.Min, body.Preferred, body.Max = 1, 1, 4
	}
	return body, listen, target, true
}

func (a *api) applyKind(kind string) string {
	switch kind {
	case "ui":
		return "applied"
	case "policy":
		if a.dataPlane {
			return "applying"
		}
		return "saved"
	default:
		return "saved"
	}
}

func (a *api) writeApply(w http.ResponseWriter, body map[string]any, kind string) {
	body["status"] = a.applyKind(kind)
	if kind == "listen" {
		body["deployment_required"] = true
	}
	writeJSON(w, http.StatusOK, body)
}

func withEffective(policies map[string]sqlite.PolicyValues, device string, forwards []map[string]any) []map[string]any {
	for _, forward := range forwards {
		listen, _ := forward["listen"].(string)
		forward["effective"] = effectiveJSON(policies, device, listen)
	}
	return forwards
}

func effectiveJSON(policies map[string]sqlite.PolicyValues, device, listen string) map[string]any {
	global := policies["global\n"].Rule()
	deviceRule := policies["device\n"+device].Rule()
	forwardRule := policies["forward\n"+sqlite.ForwardKey(device, listen)].Rule()
	rule := policy.Effective(global, deviceRule, forwardRule)
	return map[string]any{
		"max_pending": limitOut(rule.MaxPending),
		"max_per_ip":  limitOut(rule.MaxPerIP), "rate": limitOut(rule.RatePerSec), "burst": limitOut(rule.Burst),
		"idle_sec": limitOut(rule.IdleSec), "connect_sec": limitOut(rule.ConnectSec),
		"wait_sec": limitOut(rule.WaitSec), "bandwidth": limitOut(rule.Bandwidth),
	}
}

func limitOut(value policy.Limit) any {
	if !value.Set {
		return nil
	}
	return value.Value
}

func writeStore(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sqlite.ErrPortConflict), errors.Is(err, sqlite.ErrLegacyListen):
		writeError(w, http.StatusConflict, "port_conflict")
	case errors.Is(err, sqlite.ErrPortRange):
		writeError(w, http.StatusBadRequest, "port_range")
	case errors.Is(err, sqlite.ErrPortQuota):
		writeError(w, http.StatusConflict, "port_quota")
	case errors.Is(err, sqlite.ErrPolicyLooser):
		writeError(w, http.StatusBadRequest, "policy_looser")
	case errors.Is(err, sqlite.ErrLegacyNotFound), errors.Is(err, sqlite.ErrWeroxyNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, sqlite.ErrAccessRuleExists), errors.Is(err, sqlite.ErrLegacyExists), errors.Is(err, sqlite.ErrWeroxyExists):
		writeError(w, http.StatusConflict, "exists")
	default:
		writeError(w, http.StatusBadRequest, "invalid")
	}
}

func policyKey(scope, device, listen string) (string, error) {
	switch scope {
	case "device":
		if !validName(device) {
			return "", errors.New("device")
		}
		return device, nil
	case "forward":
		addr, err := canonical(listen)
		if err != nil || !validName(device) {
			return "", errors.New("forward")
		}
		return sqlite.ForwardKey(device, addr), nil
	default:
		return "", errors.New("scope")
	}
}

func (a *api) timeoutSettings(r *http.Request) map[string]any {
	policies, err := a.db.ListPolicies(r.Context())
	if err != nil {
		return map[string]any{"status": "failed"}
	}
	global := policies["global\n"]
	status := "saved"
	if state, err := a.db.ConfigRevision(r.Context(), "policy"); err == nil {
		switch {
		case state.FailureReason != "":
			status = "failed"
		case state.DesiredRevision == state.AppliedRevision:
			status = "applied"
		case a.dataPlane:
			status = "applying"
		}
	}
	return map[string]any{
		"max_pending": global.MaxPending, "max_per_ip": global.MaxPerIP,
		"rate": global.RatePerSec, "burst": global.Burst,
		"idle_sec": global.IdleSec, "connect_sec": global.ConnectSec,
		"wait_sec": global.WaitSec, "bandwidth": global.Bandwidth, "status": status,
	}
}

func (a *api) defaultSettings(r *http.Request, ui sqlite.UISettings) map[string]any {
	limits := a.timeoutSettings(r)
	return map[string]any{
		"mode": ui.ForwardMode, "min": ui.ForwardMin, "preferred": ui.ForwardPreferred, "max": ui.ForwardMax,
		"limits": limits,
	}
}

func (a *api) saveDefaults(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode      string `json:"mode"`
		Min       int    `json:"min"`
		Preferred int    `json:"preferred"`
		Max       int    `json:"max"`
	}
	if err := a.read(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return
	}
	if (body.Mode != "shared" && body.Mode != "exclusive") || !ports.ValidRange(body.Min, body.Preferred, body.Max) {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	result, ok := a.mutateConfig(w, r, "ui", true, body, func(txCtx context.Context) error {
		current, err := a.db.UI(txCtx)
		if err != nil {
			return err
		}
		current.ForwardMode = body.Mode
		current.ForwardMin = body.Min
		current.ForwardPreferred = body.Preferred
		current.ForwardMax = body.Max
		if err := a.db.SetUI(txCtx, current); err != nil {
			return err
		}
		return a.db.RecordAudit(txCtx, "forward_defaults", "success", "")
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, mutationBody(result, map[string]any{"ok": true}))
}

func (a *api) backupDir() string {
	return filepath.Join(a.dataDir, "backups")
}

func (a *api) backup(w http.ResponseWriter, r *http.Request) {
	if !a.enterBackup(w) {
		return
	}
	defer a.leaveBackup()
	name, err := a.db.BackupFile(r.Context(), a.backupDir())
	if err != nil {
		if errors.Is(err, sqlite.ErrBackupBudget) {
			writeError(w, http.StatusInsufficientStorage, "backup_budget")
		} else {
			writeError(w, http.StatusInternalServerError, "failed")
		}
		return
	}
	_ = a.db.RecordAudit(r.Context(), "backup", "success", name)
	writeJSON(w, http.StatusOK, map[string]any{"status": "saved", "file": name})
}

func (a *api) backupDownload(w http.ResponseWriter, r *http.Request) {
	select {
	case a.downloadSlots <- struct{}{}:
		defer func() { <-a.downloadSlots }()
	default:
		writeError(w, http.StatusTooManyRequests, "backup_busy")
		return
	}
	name := r.URL.Query().Get("file")
	if name == "" || name != filepath.Base(name) || filepath.Ext(name) != ".db" {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	path, err := sqlite.BackupReadPath(a.backupDir(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeFile(w, r, path)
}

func (a *api) backupUpload(w http.ResponseWriter, r *http.Request) {
	if !a.enterBackup(w) {
		return
	}
	defer a.leaveBackup()
	if a.dataPlane {
		writeError(w, http.StatusConflict, "stop_data_plane_before_restore")
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "confirm")
		return
	}
	defer r.MultipartForm.RemoveAll()
	if r.FormValue("confirm") != "true" {
		writeError(w, http.StatusBadRequest, "confirm")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil || header.Size <= 0 || header.Size > 32<<20 {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	defer file.Close()
	buf := make([]byte, 16)
	if _, err := io.ReadFull(file, buf); err != nil || string(buf) != "SQLite format 3\x00" {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	if err := os.MkdirAll(a.backupDir(), 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "failed")
		return
	}
	if err := os.Chmod(a.backupDir(), 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "failed")
		return
	}
	if err := sqlite.BackupSpace(a.backupDir(), header.Size); err != nil {
		writeError(w, http.StatusInsufficientStorage, "backup_budget")
		return
	}
	name := "upload-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".db"
	path := filepath.Join(a.backupDir(), name)
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed")
		return
	}
	if _, err := out.Write(buf); err != nil {
		out.Close()
		os.Remove(path)
		writeError(w, http.StatusInternalServerError, "failed")
		return
	}
	if _, err := io.Copy(out, file); err != nil {
		out.Close()
		os.Remove(path)
		writeError(w, http.StatusInternalServerError, "failed")
		return
	}
	if err := out.Close(); err != nil {
		os.Remove(path)
		writeError(w, http.StatusInternalServerError, "failed")
		return
	}
	if err := a.db.RestoreFile(r.Context(), a.backupDir(), name); err != nil {
		_ = os.Remove(path)
		writeError(w, http.StatusBadRequest, "failed")
		return
	}
	retentionWarning := sqlite.PruneBackupFiles(a.backupDir()) != nil
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]any{"status": "saved", "retention_warning": retentionWarning})
}

func (a *api) backupRestore(w http.ResponseWriter, r *http.Request) {
	if !a.enterBackup(w) {
		return
	}
	defer a.leaveBackup()
	if a.dataPlane {
		writeError(w, http.StatusConflict, "stop_data_plane_before_restore")
		return
	}
	var body struct {
		File    string `json:"file"`
		Confirm bool   `json:"confirm"`
	}
	if err := a.read(r, &body); err != nil || !body.Confirm || body.File == "" {
		writeError(w, http.StatusBadRequest, "confirm")
		return
	}
	if err := a.db.RestoreFile(r.Context(), a.backupDir(), body.File); err != nil {
		writeError(w, http.StatusBadRequest, "failed")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]any{"status": "saved"})
}

func canonical(addr string) (string, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(portText)
	if ip == nil || err != nil || port < 1 || port > 65535 {
		return "", errors.New("address")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func validName(name string) bool {
	if len(name) < 1 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func (a *api) metricHistory(w http.ResponseWriter, r *http.Request) {
	queryCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	points, resolution, err := a.db.MetricHistory(queryCtx, r.URL.Query().Get("window"))
	if err != nil {
		if errors.Is(err, sqlite.ErrMetricBatch) {
			writeError(w, http.StatusBadRequest, "invalid_window")
		} else {
			writeError(w, http.StatusServiceUnavailable, "metrics_unavailable")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resolution": resolution, "points": points})
}

func (a *api) connections(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			writeError(w, http.StatusBadRequest, "invalid_limit")
			return
		}
		limit = value
	}
	before := int64(1<<63 - 1)
	if raw := r.URL.Query().Get("before"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 1 {
			writeError(w, http.StatusBadRequest, "invalid_cursor")
			return
		}
		before = value
	}
	protocol, device := r.URL.Query().Get("protocol"), r.URL.Query().Get("device")
	if len(device) > 128 {
		writeError(w, http.StatusBadRequest, "invalid_device")
		return
	}
	queryCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	rows, next, err := a.db.Connections(queryCtx, protocol, device, before, limit)
	if err != nil {
		if errors.Is(err, sqlite.ErrConnectionPage) {
			writeError(w, http.StatusBadRequest, "invalid")
		} else {
			writeError(w, http.StatusServiceUnavailable, "connections_unavailable")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connections": rows, "next_before": next})
}

func (a *api) enterBackup(w http.ResponseWriter) bool {
	select {
	case a.backupOps <- struct{}{}:
		return true
	default:
		writeError(w, http.StatusTooManyRequests, "backup_busy")
		return false
	}
}
func (a *api) leaveBackup() { <-a.backupOps }

func (a *api) saveMetricSettings(w http.ResponseWriter, r *http.Request) {
	var body sqlite.MetricSettings
	if a.read(r, &body) != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return
	}
	if body.SampleSec < 1 || body.SampleSec > 60 || body.RefreshSec < 1 || body.RefreshSec > 60 {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	result, ok := a.mutateConfig(w, r, "storage", true, body, func(ctx context.Context) error {
		if err := a.db.SetMetricSettings(ctx, body); err != nil {
			return err
		}
		return a.db.RecordAudit(ctx, "metric_settings", "success", "")
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, mutationBody(result, map[string]any{"ok": true}))
}

func (a *api) persistDeviceStatus(ctx context.Context) {
	pending := a.hub.TakeDeviceStatus()
	if len(pending) == 0 {
		return
	}
	items := make([]sqlite.DeviceStatus, 0)
	for key, points := range pending {
		protocol, device := SplitDeviceStatusKey(key)
		for _, point := range points {
			items = append(items, sqlite.DeviceStatus{DeviceID: point.DeviceID, Protocol: protocol, Device: device, At: point.At, DurationSec: point.DurationSec, State: point.State, Sessions: point.Sessions, Up: point.Up, Down: point.Down})
		}
	}
	for len(items) > 0 {
		size := min(512, len(items))
		if err := a.db.SaveDeviceStatus(ctx, items[:size]); err != nil {
			remaining := make(map[string][]DevicePoint)
			for _, p := range items {
				key := p.Protocol + ":" + p.Device
				remaining[key] = append(remaining[key], DevicePoint{DeviceID: p.DeviceID, At: p.At, DurationSec: p.DurationSec, State: p.State, Sessions: p.Sessions, Up: p.Up, Down: p.Down})
			}
			a.hub.RequeueDeviceStatus(remaining)
			return
		}
		items = items[size:]
	}
}

func (a *api) hostForwardUnavailable(port int) (bool, error) {
	plan, err := deployment.HostPortPlan(a.dataDir)
	if err != nil || plan == nil {
		return false, err
	}
	for _, blocked := range plan.UnavailableForward {
		if blocked == port {
			return true, nil
		}
	}
	return false, nil
}
