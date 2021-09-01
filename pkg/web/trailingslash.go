package web

import (
	"net/http"
	"strings"
)

// TrailingSlashMiddleware enforce all URLs to a single format of always either having a
// trailign slash or not.
func TrailingSlashMiddleware(requiredTrailingSlash bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return trailingSlashMiddleware{
			next:          next,
			trailignSlash: requiredTrailingSlash,
		}
	}
}

type trailingSlashMiddleware struct {
	next          http.Handler
	trailignSlash bool
}

func (h trailingSlashMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, "/") == h.trailignSlash {
		h.next.ServeHTTP(w, r)
		return
	}

	fixedURL := r.URL.Path
	if h.trailignSlash {
		fixedURL += "/"
	} else {
		fixedURL = strings.TrimRight(fixedURL, "/")
	}
	http.Redirect(w, r, fixedURL, http.StatusPermanentRedirect)
}
