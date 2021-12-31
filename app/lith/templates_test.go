package lith

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func acquireCSRFToken(t testing.TB, endpoint string, app http.Handler) (string, string) {
	t.Helper()

	r := httptest.NewRequest("GET", endpoint, nil)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusOK, w.Code; want != got {
		t.Fatalf("want login response %d status, got %d: %s", want, got, w.Body)
	}
	return readCSRFToken(t, w)
}

func readCSRFToken(t testing.TB, w *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	matches := csrfRx.FindStringSubmatch(w.Body.String())
	if len(matches) == 0 {
		t.Fatalf("No CSRF field found in the HTML body.")
	}
	token := string(matches[1])

	return token, w.HeaderMap.Get("set-cookie")
}

// A fragile but an extremly low effort way to extract csrf token value.
var csrfRx = regexp.MustCompile(`<input type="hidden" name="csrf" value="([^"]+)">`)
