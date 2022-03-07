package lith

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/husio/lith/app/lith/store"
	"github.com/husio/lith/pkg/alert"
)

// Currentstore.Account returns the account bound to current request.
//
// This function requires AuthMiddleware.
func CurrentAccount(ctx context.Context) (*store.Account, bool) {
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

func withAuthInfo(ctx context.Context, sessionID string, a *store.Account) context.Context {
	return context.WithValue(ctx, authInfoContextKey, authinfo{
		account:   a,
		sessionID: sessionID,
	})
}

// AuthMiddleware read the request and injects into the context authentication
// information.
//
// Session information is looked up using provided lookup functions. This way
// you can configure endpoints to use different session storage mechanisms and
// for example, avoid using cookie lookup everywhere.
//
// Be catious when using a lookup function that checks cookie, because cookie
// authentication requires extra care (i.e. use CSRF protection).
//
// This middleware is required by the Currentstore.Account function.
func AuthMiddleware(store store.Store, lookups ...LookupFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &authMiddleware{
			lookups: lookups,
			store:   store,
			next:    next,
		}
	}
}

type LookupFunc func(*http.Request) string

type authMiddleware struct {
	lookups []LookupFunc
	store   store.Store
	next    http.Handler
}

func (m *authMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var sessionID string
	for _, fn := range m.lookups {
		if s := fn(r); s != "" {
			sessionID = s
			break
		}
	}
	if sessionID != "" {
		if account := accountBySessionID(r.Context(), m.store, sessionID); account != nil {
			r = r.WithContext(withAuthInfo(r.Context(), sessionID, account))
		}
	}

	m.next.ServeHTTP(w, r)
}

func accountBySessionID(ctx context.Context, s store.Store, sessionID string) *store.Account {
	if sessionID == "" {
		return nil
	}
	session, err := s.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		return nil
	}
	defer session.Rollback()

	switch account, err := session.AccountBySession(ctx, sessionID); {
	case err == nil:
		return account
	case errors.Is(err, store.ErrNotFound):
		return nil
	default:
		alert.EmitErr(ctx, err, "Cannot get account by session ID.",
			"session_id", sessionID)
		return nil
	}
}

// SessionFromCookie returns session ID from the "s" cookie if present.
func SessionFromCookie(r *http.Request) string {
	c, err := r.Cookie("s")
	if err != nil {
		return ""
	}
	return c.Value

}

// SessionFromHeader returns session ID from the Authorization header if
// present.
func SessionFromHeader(r *http.Request) string {
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
	account   *store.Account
	sessionID string
}
