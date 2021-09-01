package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrailingSlashMiddleware(t *testing.T) {
	cases := map[string]struct {
		url          string
		middleware   func(http.Handler) http.Handler
		wantCode     int
		wantLocation string
	}{
		"index, ts": {
			url:        "/",
			middleware: TrailingSlashMiddleware(true),
			wantCode:   http.StatusTeapot,
		},
		"index, nots": {
			url:        "/",
			middleware: TrailingSlashMiddleware(false),
			wantCode:   http.StatusTeapot,
		},
		"url with ts, ts": {
			url:        "/some/url/",
			middleware: TrailingSlashMiddleware(true),
			wantCode:   http.StatusTeapot,
		},
		"url with ts, nots": {
			url:          "/some/url/",
			middleware:   TrailingSlashMiddleware(false),
			wantCode:     http.StatusPermanentRedirect,
			wantLocation: "/some/url",
		},
		"url without ts, ts": {
			url:          "/some/url",
			middleware:   TrailingSlashMiddleware(true),
			wantCode:     http.StatusPermanentRedirect,
			wantLocation: "/some/url/",
		},
		"url without ts, nots": {
			url:        "/some/url",
			middleware: TrailingSlashMiddleware(false),
			wantCode:   http.StatusTeapot,
		},
	}

	for testName, tc := range cases {
		t.Run(testName, func(t *testing.T) {
			r := httptest.NewRequest("POST", tc.url, nil)
			w := httptest.NewRecorder()

			hn := tc.middleware(staticHandler(http.StatusTeapot))
			hn.ServeHTTP(w, r)

			if code := w.Result().StatusCode; code != tc.wantCode {
				t.Fatalf("want %d status code, got %d", tc.wantCode, code)
			}
			location := w.Result().Header.Get("location")
			if location != tc.wantLocation {
				t.Fatalf("want %q location, got %q", tc.wantLocation, location)
			}
		})
	}
}

type staticHandler int

func (code staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(int(code))
}
