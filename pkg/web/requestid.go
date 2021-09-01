package web

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/husio/lith/pkg/alert"
)

func RequestIDMiddleware() func(http.Handler) http.Handler {
	idc := make(chan string, 8)
	go func() {
		for {
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				panic(err)
			}
			idc <- hex.EncodeToString(b)
		}
	}()
	return func(next http.Handler) http.Handler {
		return requestIDMiddleware{
			next: next,
			idc:  idc,
		}
	}
}

type requestIDMiddleware struct {
	next http.Handler
	idc  <-chan string
}

func (h requestIDMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := <-h.idc

	ctx := r.Context()
	emitter := alert.WithPairs(alert.UsedEmitter(ctx), "request_id", requestID)
	r = r.WithContext(alert.WithEmitter(ctx, emitter))

	r.Header.Set("x-request-id", requestID)

	h.next.ServeHTTP(w, r)
}
