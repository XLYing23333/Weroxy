package webui

import (
	"context"
	"net"
	"net/http"
	"weroxy/server/internal/metrics"
	"weroxy/server/internal/storage/sqlite"
)

func (a *api) deviceIdentity(ctx context.Context, protocol, name string) (int64, error) {
	if protocol == "weroxy" {
		ds, _, e := a.db.ListWeroxy(ctx)
		if e != nil {
			return 0, e
		}
		for _, d := range ds {
			if d.Name == name {
				return d.ID, nil
			}
		}
	} else if protocol == "legacy" {
		ds, _, e := a.db.ListLegacy(ctx)
		if e != nil {
			return 0, e
		}
		for _, d := range ds {
			if d.Name == name {
				return d.ID, nil
			}
		}
	} else {
		return 0, sqlite.ErrPortRange
	}
	return 0, sqlite.ErrWeroxyNotFound
}
func (a *api) renameDevice(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Protocol string `json:"protocol"`
		Name     string `json:"name"`
		NewName  string `json:"new_name"`
	}
	if a.read(r, &b) != nil || !validName(b.Name) || !validName(b.NewName) || (b.Protocol != "legacy" && b.Protocol != "weroxy") {
		writeError(w, 400, "invalid")
		return
	}
	var id int64
	result, ok := a.mutateConfig(w, r, "credential", true, b, func(ctx context.Context) error {
		var e error
		id, e = a.deviceIdentity(ctx, b.Protocol, b.Name)
		if e != nil {
			return e
		}
		if e = a.db.RenameDevice(ctx, b.Protocol, b.Name, b.NewName); e != nil {
			return e
		}
		if e = a.db.BumpRelatedRevision(ctx, "policy"); e != nil {
			return e
		}
		return a.db.RecordAudit(ctx, "device_rename", "success", b.NewName)
	})
	if !ok {
		return
	}
	if !result.Duplicate {
		a.hub.RenameDevice(b.Protocol, id, b.Name, b.NewName)
	}
	writeJSON(w, 200, mutationBody(result, map[string]any{"ok": true, "name": b.NewName}))
}
func (a *api) deleteVisitors(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Protocol string   `json:"protocol"`
		Device   string   `json:"device"`
		IPs      []string `json:"ips"`
	}
	if a.read(r, &b) != nil || !validName(b.Device) || len(b.IPs) < 1 || len(b.IPs) > 256 {
		writeError(w, 400, "invalid")
		return
	}
	seen := map[string]bool{}
	ips := []string{}
	for _, ip := range b.IPs {
		p := net.ParseIP(ip)
		if p == nil {
			writeError(w, 400, "invalid")
			return
		}
		v := p.String()
		if !seen[v] {
			ips = append(ips, v)
			seen[v] = true
		}
	}
	id, e := a.deviceIdentity(r.Context(), b.Protocol, b.Device)
	if e != nil {
		writeStore(w, e)
		return
	}
	a.hub.mu.Lock()
	count := a.hub.count
	a.hub.mu.Unlock()
	deleted, active := count.DeleteVisitors(b.Protocol, id, ips)
	// Persist the hiding checkpoint first, so an older queued snapshot cannot unhide it.
	selected := map[string]bool{}
	for _, ip := range deleted {
		selected[ip] = true
	}
	hidden := []metrics.VisitorTotal{}
	for _, v := range count.VisitorTotals(b.Protocol, id) {
		if selected[v.IP] {
			hidden = append(hidden, v)
		}
	}
	if err := a.db.SaveVisitorTotals(r.Context(), hidden); err != nil {
		writeStore(w, err)
		return
	}
	if len(hidden) != len(deleted) {
		writeError(w, http.StatusServiceUnavailable, "telemetry_capacity")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": deleted, "skipped_active": active})
}
func (h *Hub) RenameDevice(protocol string, id int64, oldName, newName string) {
	if oldName == newName {
		return
	}
	h.mu.Lock()
	if h.deviceSamples == nil {
		h.deviceSamples = map[string][]DevicePoint{}
	}
	oldKey, newKey := protocol+":"+oldName, protocol+":"+newName
	h.deviceSamples[newKey] = h.deviceSamples[oldKey]
	delete(h.deviceSamples, oldKey)
	if h.pendingDeviceSamples != nil {
		h.pendingDeviceSamples[newKey] = h.pendingDeviceSamples[oldKey]
		delete(h.pendingDeviceSamples, oldKey)
	}
	count := h.count
	h.mu.Unlock()
	count.RenameDevice(protocol, id, newName)
}
