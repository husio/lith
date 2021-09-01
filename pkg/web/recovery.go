package web

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/husio/lith/pkg/alert"
)

// RecoverMiddleware captures any panic, emits an alert event for it and writes
// 500 response code.
func RecoverMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return recoverMiddleware{
			next: next,
		}
	}
}

type recoverMiddleware struct {
	next http.Handler
}

func (h recoverMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			alert.Emit(r.Context(),
				"msg", "HTTP handler panic recovered.",
				"err", fmt.Sprint(err),
				"stack", string(debug.Stack()),
			)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}()
	h.next.ServeHTTP(w, r)
}
