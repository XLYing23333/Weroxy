package webui

import (
	"errors"
	"net/http"
	"os"
	"weroxy/server/internal/auth"
	"weroxy/server/internal/storage/sqlite"
)

func (a *api) initialize(w http.ResponseWriter, r *http.Request) {
	exists, err := a.db.HasAdmin(r.Context())
	if err != nil {
		writeError(w, 503, "setup_unavailable")
		return
	}
	if exists {
		writeError(w, 409, "already_initialized")
		return
	}
	if !auth.SetupMatches(a.setupToken, r.Header.Get("X-Weroxy-Setup")) {
		writeError(w, 403, "setup_unauthorized")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Confirm  string `json:"confirm"`
	}
	if a.read(r, &body) != nil {
		writeError(w, 400, "bad_json")
		return
	}
	if !auth.ValidUsername(body.Username) {
		writeError(w, 400, "invalid_username")
		return
	}
	if body.Password != body.Confirm {
		writeError(w, 400, "password_mismatch")
		return
	}
	err = a.db.Bootstrap(r.Context(), a.pass, body.Username, []byte(body.Password))
	body.Password = ""
	body.Confirm = ""
	if errors.Is(err, sqlite.ErrAdminExists) {
		writeError(w, 409, "already_initialized")
		return
	}
	if errors.Is(err, auth.ErrPasswordLength) {
		writeError(w, 400, "password_length")
		return
	}
	if err != nil {
		writeError(w, 503, "setup_unavailable")
		return
	}
	_ = os.Remove(auth.SetupPath(a.dataDir))
	writeJSON(w, 201, map[string]bool{"initialized": true})
}
