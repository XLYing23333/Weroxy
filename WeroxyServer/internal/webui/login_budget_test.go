package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOversizedLoginDoesNotRetainGuardKeys(t *testing.T) {
	a := &api{loginGuard: newLoginGuard()}
	for _, body := range []string{
		`{"username":"` + strings.Repeat("x", 60000) + `","password":"bad"}`,
		`{"username":"admin","password":"` + strings.Repeat("x", 60000) + `"}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
		result := httptest.NewRecorder()
		a.login(result, request)
		if result.Code != http.StatusUnauthorized {
			t.Fatalf("response=%d", result.Code)
		}
	}
	if len(a.loginGuard.attempts) != 0 {
		t.Fatal("oversized identity retained")
	}
}
