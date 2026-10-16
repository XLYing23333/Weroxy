package webui

import (
	"net/http"
)

func (a *api) quickListSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		enabled, err := a.db.QuickListEnabled(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "invalid")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"enabled": enabled})
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := a.read(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return
	}
	if err := a.db.SetQuickListEnabled(r.Context(), body.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": body.Enabled})
}
