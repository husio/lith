package lith

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

// NewClient returns an authentication service client.
func NewClient(apiURL string, client *http.Client) *Client {
	if client == nil {
		client = http.DefaultClient
	}
	return &Client{
		apiURL:  apiURL,
		httpcli: client,
	}
}

type Client struct {
	apiURL  string
	httpcli *http.Client
}

// SessionCreate verifies provided credentials and returns a newly created
// session. If provided credentials cannot be used to create a new session,
// ErrUnauthorized error is returned.
//
// Session token can be used instead of login and password pair to
// authenticate.
func (c Client) SessionCreate(ctx context.Context, login, password, twoFactorCode string) (*AccountSession, error) {
	var body bytes.Buffer
	err := json.NewEncoder(&body).Encode(struct {
		Login    string `json:"login"`
		Password string `json:"password"`
		Code     string `json:"code,omitempty"`
	}{
		Login:    login,
		Password: password,
		Code:     twoFactorCode,
	})
	if err != nil {
		return nil, fmt.Errorf("serialize payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.apiURL+"/sessions", &body)
	if err != nil {
		return nil, fmt.Errorf("new HTTP request: %w", err)
	}

	resp, err := c.httpcli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do HTTP request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated:
		// All good.
	case http.StatusForbidden:
		return nil, ErrUnauthorized
	default:
		b, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 1e5))
		return nil, fmt.Errorf("unexpected response %d: %s", resp.StatusCode, string(b))
	}

	var as AccountSession
	if err := json.NewDecoder(resp.Body).Decode(&as); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &as, nil
}

// SessionDelete deletes an active session associated with given token. If
// session does not exist or expired, ErrNotFound error is returned.
func (c Client) SessionDelete(ctx context.Context, token string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.apiURL+"/sessions", nil)
	if err != nil {
		return fmt.Errorf("new HTTP request: %w", err)
	}
	req.Header.Set("authorization", "Bearer "+token)

	resp, err := c.httpcli.Do(req)
	if err != nil {
		return fmt.Errorf("do HTTP request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrNotFound
	default:
		b, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 1e5))
		return fmt.Errorf("unexpected response %d: %s", resp.StatusCode, string(b))
	}
}

// SessionIntrospect returns information about the session associated with
// provided session token.
func (c Client) SessionIntrospect(ctx context.Context, token string) (*AccountSession, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.apiURL+"/sessions", nil)
	if err != nil {
		return nil, fmt.Errorf("new HTTP request: %w", err)
	}
	req.Header.Set("authorization", "Bearer "+token)

	resp, err := c.httpcli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do HTTP request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// All good.
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	default:
		b, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 1e5))
		return nil, fmt.Errorf("unexpected response %d: %s", resp.StatusCode, string(b))
	}

	var as AccountSession
	if err := json.NewDecoder(resp.Body).Decode(&as); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &as, nil

}

// AccountSession contains all details about authentication session instance.
type AccountSession struct {
	// AccountID is the identifier of an account for which the session was
	// created.
	AccountID string `json:"account_id"`
	// SessionID is the identifier of the session, often called "token".
	SessionID string `json:"session_id"`
	// Permissions is a list of tags describing what account referenced by
	// this session is allowed to.
	Permissions []string `json:"permissions"`
}

// TwoFactor returns true if two-factor authentication is enabled for the
// account referenced by session with given token.
func (c Client) TwoFactor(ctx context.Context, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.apiURL+"/twofactor", nil)
	if err != nil {
		return false, fmt.Errorf("new HTTP request: %w", err)
	}
	req.Header.Set("authorization", "Bearer "+token)

	resp, err := c.httpcli.Do(req)
	if err != nil {
		return false, fmt.Errorf("do HTTP request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// All good.
	case http.StatusUnauthorized:
		return false, ErrUnauthorized
	default:
		b, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 1e5))
		return false, fmt.Errorf("unexpected response %d: %s", resp.StatusCode, string(b))
	}

	var status struct {
		Enabled bool
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return false, fmt.Errorf("decode response: %w", err)
	}
	return status.Enabled, nil
}

// TwoFactorEnable enables two-factor authentication for the account referenced
// by session with given token. Only an account that does not have two-factor
// authentication enabled can make this call.
// Additionally to the session token a secret and generated with this secret
// code must be provided. Code must be generated using TOTP algorithm.
func (c Client) TwoFactorEnable(ctx context.Context, token, secret, code string) error {
	body, err := json.Marshal(struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}{
		Secret: secret,
		Code:   code,
	})
	if err != nil {
		return fmt.Errorf("serialize payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.apiURL+"/twofactor", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new HTTP request: %w", err)
	}
	req.Header.Set("authorization", "Bearer "+token)

	resp, err := c.httpcli.Do(req)
	if err != nil {
		return fmt.Errorf("do HTTP request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusConflict:
		return errors.New("two factor authentication already enabled")
	case http.StatusBadRequest:
		b, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 1e5))
		return fmt.Errorf("bad request: %s", string(b))
	default:
		b, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 1e5))
		return fmt.Errorf("unexpected response %d: %s", resp.StatusCode, string(b))
	}
}

// AuthMiddleware return an http.Handler middleware introspects each incoming
// request and if authentication information is provided, verifies it and
// includes session information in the context.
//
// Session information can be either stored in the cookie or the HTTP header.
//
// Within decorated http.Handler, CurrentAccount function can be called to
// retrieve the authentication information.
func AuthMiddleware(introspector SessionIntrospector) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &authMiddleware{
			introspector: introspector,
			next:         next,
		}
	}
}

// SessionIntrospector is implemented by any authentication engine that allows
// to introspect session token.
type SessionIntrospector interface {
	// SessionIntrospect returns information about authentication session
	// with given token.
	SessionIntrospect(context.Context, string) (*AccountSession, error)
}

type authMiddleware struct {
	introspector SessionIntrospector
	next         http.Handler
}

func (m authMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a := m.authenticatedAccount(r); a != nil {
		ctx := context.WithValue(r.Context(), currentAccountContextKey, a)
		r = r.WithContext(ctx)
	}
	m.next.ServeHTTP(w, r)
}

func (m *authMiddleware) authenticatedAccount(r *http.Request) *AccountSession {
	sid := sessionID(r)
	if sid == "" {
		return nil
	}
	switch account, err := m.introspector.SessionIntrospect(r.Context(), sid); {
	case err == nil:
		return account
	case errors.Is(err, ErrUnauthorized):
		return nil
	default:
		// TODO log
		return nil
	}
}

func sessionID(r *http.Request) string {
	if s := sessionIDFromCookie(r); s != "" {
		return s
	}
	if s := sessionIDFromHeader(r); s != "" {
		return s
	}
	return ""
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

// CurrentAccount returns authentication session details if request contains a
// valid authentication information.
//
// For this function to work, handler that calls CurrentAccount must be wrapped
// with AuthMiddleware.
func CurrentAccount(ctx context.Context) (*AccountSession, bool) {
	a, ok := ctx.Value(currentAccountContextKey).(*AccountSession)
	return a, ok && a != nil
}

var (
	// ErrNotFound is returned when operation cannot succeed because an
	// entity cannot be found or does not exist.
	ErrNotFound = errors.New("not found")
	// ErrUnauthorized is returned when an operation cannot succeed because
	// of missing or insufficient authorization.
	ErrUnauthorized = errors.New("unauthorized")
)

type contextKey int

const (
	currentAccountContextKey contextKey = iota
)
