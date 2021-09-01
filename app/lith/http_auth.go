package lith

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/husio/lith/pkg/alert"
)

// CurrentAccount returns the account bound to current request.
//
// This function requires AuthMiddleware.
func CurrentAccount(ctx context.Context) (*Account, bool) {
	info, ok := ctx.Value(authInfoContextKey).(authinfo)
	if ok {
		return info.account, true
	}
	return nil, false
}

// CurrentSessionID returns the session ID  bound to current request.
//
// This function requires AuthMiddleware.
func CurrentSessionID(ctx context.Context) (string, bool) {
	info, ok := ctx.Value(authInfoContextKey).(authinfo)
	if ok {
		return info.sessionID, true
	}
	return "", false
}

func withAuthInfo(ctx context.Context, sessionID string, a *Account) context.Context {
	return context.WithValue(ctx, authInfoContextKey, authinfo{
		account:   a,
		sessionID: sessionID,
	})
}

// AuthMiddleware read the request and injects into the context authentication
// information.
// This middleware is required by the CurrentAccount function.
func AuthMiddleware(store Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &authMiddleware{store: store, next: next}
	}
}

type authMiddleware struct {
	store Store
	next  http.Handler
}

func (m *authMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var sessionID string
	if s := sessionIDFromHeader(r); s != "" {
		sessionID = s
	} else if s := sessionIDFromCookie(r); s != "" {
		sessionID = s
	}

	if account := accountBySessionID(r.Context(), m.store, sessionID); account != nil {
		r = r.WithContext(withAuthInfo(r.Context(), sessionID, account))
	}

	m.next.ServeHTTP(w, r)
}

func accountBySessionID(ctx context.Context, store Store, sessionID string) *Account {
	if sessionID == "" {
		return nil
	}
	session, err := store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		return nil
	}
	defer session.Rollback()

	switch account, err := session.AccountBySession(ctx, sessionID); {
	case err == nil:
		return account
	case errors.Is(err, ErrNotFound):
		return nil
	default:
		alert.EmitErr(ctx, err, "Cannot get account by session ID.",
			"session_id", sessionID)
		return nil
	}
}

func sessionIDFromCookie(r *http.Request) string {
	c, err := r.Cookie("s")
	if err != nil {
		return ""
	}
	return c.Value

}

func sessionIDFromHeader(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	chunks := strings.Fields(header)
	if len(chunks) != 2 {
		return ""
	}
	if chunks[0] != "Bearer" {
		return ""
	}
	return chunks[1]
}

type contextKey int

const (
	authInfoContextKey contextKey = iota
)

type authinfo struct {
	account   *Account
	sessionID string
}
