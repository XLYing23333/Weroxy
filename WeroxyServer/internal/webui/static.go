package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var dist embed.FS

func serveStatic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
	}
	if name == "index.html" || !strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "no-store")
	}
	if file, err := sub.Open(name); err == nil {
		file.Close()
		http.FileServer(http.FS(sub)).ServeHTTP(w, r)
		return
	}
	r.URL.Path = "/"
	http.FileServer(http.FS(sub)).ServeHTTP(w, r)
}
