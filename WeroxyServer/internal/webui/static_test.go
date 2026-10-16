package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
	notices "weroxy/server"
)

func TestPublicEmbeddedNotices(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		w := httptest.NewRecorder()
		serveStatic(w, httptest.NewRequest(method, "/THIRD_PARTY_NOTICES", nil))
		if method == http.MethodPost {
			if w.Code != 405 {
				t.Fatalf("POST status: %d", w.Code)
			}
			continue
		}
		if w.Code != 200 || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("headers: %v", w.Header())
		}
		want := notices.Text()
		if method == http.MethodHead {
			want = ""
		}
		if w.Body.String() != want {
			t.Fatal("incomplete notices")
		}
	}
}
