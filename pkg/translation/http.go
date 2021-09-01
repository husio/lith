package translation

import (
	"context"
	"net/http"
)

func LanguageMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		language := r.Header.Get("accept-language")
		// If locale is provided, cut it off. We support only the base
		// language (i.e. en and not en_US).
		if len(language) > 2 {
			language = language[:2]
		}

		w.Header().Set("content-language", language)

		ctx := context.WithValue(r.Context(), languageContextKey, language)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func Language(ctx context.Context) string {
	code, _ := ctx.Value(languageContextKey).(string)
	return code
}

type contextKey int

const (
	languageContextKey contextKey = iota
)
