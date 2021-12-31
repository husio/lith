package web

import (
	"net/http"
	"regexp"
	"strings"
)

// CORSMiddleware retunrs a middleware to enable Cross-Origin Resource Sharing
// (CORS) for provided configuration.
//
// Origins is a list of comma separated domain list that controls which domains
// are allowed. Localhost is always allowed.
//
// Methods allows to enable certain method execution. Use * for all/any
// wildcard.
//
// Header allows to enable certain header sending. Use * for all/any wildcard.
//
// https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
func CORSMiddleware(origins, methods, headers string) func(h http.Handler) http.Handler {
	oIdx := make(map[string]struct{})
	for _, o := range strings.Split(origins, ",") {
		oIdx[o] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return &corsMiddleware{
			next:    next,
			origins: oIdx,
			methods: methods,
			headers: headers,
		}
	}
}

type corsMiddleware struct {
	next    http.Handler
	origins map[string]struct{}
	methods string
	headers string
}

func (m corsMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	header := w.Header()

	// Ensure origin is not cached. It is mandatory if CORS is included for
	// only some endpoints, and we cannot ensure this is not the case.
	header.Add("Vary", "Origin")

	// Do not cache cookie to prevent leaking it.
	header.Add("Vary", "Cookie")

	origin := r.Header.Get("Origin")
	if _, ok := m.origins[origin]; ok || localhostDomain(origin) {
		header.Set("Access-Control-Allow-Origin", origin)
	}

	if r.Method == "OPTIONS" {
		// This is a preflight request.
		header.Set("Access-Control-Allow-Methods", m.methods)
		header.Set("Access-Control-Allow-Headers", m.headers)
		header.Set("Access-Control-Allow-Credentials", "true")

		// The Access-Control-Max-Age header indicates how long the
		// results of a preflight request can be cached (in seconds).
		// Default might vary between browsers, so set up something
		// predictable.
		header.Set("Access-Control-Max-Age", "300")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	m.next.ServeHTTP(w, r)
}

var localhostDomain = regexp.MustCompile(`^https?://localhost(:\d+)?$`).MatchString
