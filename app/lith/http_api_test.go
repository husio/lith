package lith

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/husio/lith/pkg/alert"
	"github.com/husio/lith/pkg/cache"
	"github.com/husio/lith/pkg/eventbus"
	"github.com/husio/lith/pkg/secret"
	"github.com/husio/lith/pkg/taskqueue"
	"github.com/husio/lith/pkg/totp"
	"github.com/husio/lith/pkg/validation"
)

func TestAPIManageSessionNoTwoFactor(t *testing.T) {
	ctx := context.Background()
	ctx = alert.WithEmitter(ctx, alert.NewTestEmitter(t))

	store := newTestSQLiteStore(t)
	cache := cache.NewLocalMemCache(1e6)

	conf := APIConfiguration{
		PathPrefix:           "/api/",
		SessionMaxAge:        time.Hour,
		SessionRefreshAge:    time.Hour,
		RequireTwoFactorAuth: false,
	}

	var accountID string
	atomic(t, store, func(s StoreSession) {
		accountID = insertAccount(t, s, "jim@example.com", "loginpass", "", []uint64{PermissionGroupActiveAccount})
	})

	app := APIHandler(conf, store, cache, eventbus.NewNoopSink(), nil)

	r := httptest.NewRequest("POST", "/api/sessions", jsonBody(t, struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{
		Email:    "jim@example.com",
		Password: "loginpass",
	}))
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)

	if want, got := http.StatusCreated, w.Code; want != got {
		t.Fatalf("want login response %d status, got %d: %s", want, got, w.Body)
	}

	var loginPayload struct {
		SessionID   string   `json:"session_id"`
		AccountID   string   `json:"account_id"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(w.Body).Decode(&loginPayload); err != nil {
		t.Fatalf("decode response body: %s", err)
	}
	if loginPayload.AccountID != accountID {
		t.Errorf("want account ID %q, got %q", accountID, loginPayload.AccountID)
	}
	if want, got := []string{"login"}, loginPayload.Permissions; !reflect.DeepEqual(want, got) {
		t.Errorf("want %q permissions, got %q", want, got)
	}

	// Once we have a session ID, we can introspect it.
	r = httptest.NewRequest("GET", "/api/sessions", nil)
	r.Header.Set("authorization", "Bearer "+loginPayload.SessionID)
	w = httptest.NewRecorder()

	app.ServeHTTP(w, r)

	if want, got := http.StatusOK, w.Code; want != got {
		t.Fatalf("want introspect response %d status, got %d: %s", want, got, w.Body)
	}

	var introspectPayload struct {
		SessionID   string   `json:"session_id"`
		AccountID   string   `json:"account_id"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(w.Body).Decode(&introspectPayload); err != nil {
		t.Fatalf("decode response body: %s", err)
	}
	if introspectPayload.AccountID != accountID {
		t.Errorf("want account ID %q, got %q", accountID, introspectPayload.AccountID)
	}
	if introspectPayload.SessionID != loginPayload.SessionID {
		t.Errorf("want %q session ID, got %q", loginPayload.SessionID, introspectPayload.SessionID)
	}
	if want, got := []string{"login"}, introspectPayload.Permissions; !reflect.DeepEqual(want, got) {
		t.Errorf("want %q permissions, got %q", want, got)
	}

	// A session can be deleted. This should erase any traces of that
	// session existence.
	r = httptest.NewRequest("DELETE", "/api/sessions", nil)
	r.Header.Set("authorization", "Bearer "+loginPayload.SessionID)
	w = httptest.NewRecorder()

	app.ServeHTTP(w, r)

	if want, got := http.StatusGone, w.Code; want != got {
		t.Fatalf("want delete response %d status, got %d: %s", want, got, w.Body)
	}

	// Deleting a session twice does not "work". Since there is no
	// information about just deleted session, we get 404.
	r = httptest.NewRequest("DELETE", "/api/sessions", nil)
	r.Header.Set("authorization", "Bearer "+loginPayload.SessionID)
	w = httptest.NewRecorder()

	app.ServeHTTP(w, r)

	if want, got := http.StatusUnauthorized, w.Code; want != got {
		t.Fatalf("want double delete response %d status, got %d: %s", want, got, w.Body)
	}
}

func TestAPICreateSessionWithTwoFactor(t *testing.T) {
	ctx := context.Background()
	ctx = alert.WithEmitter(ctx, alert.NewTestEmitter(t))

	now := time.Now()

	store := newTestSQLiteStore(t)
	cache := cache.NewLocalMemCache(1e6)

	conf := APIConfiguration{
		PathPrefix:           "/api/",
		SessionMaxAge:        time.Hour,
		SessionRefreshAge:    time.Hour,
		RequireTwoFactorAuth: true,
	}

	var accountID string
	atomic(t, store, func(s StoreSession) {
		accountID = insertAccount(t, s, "jim@example.com", "loginpass", "totpsecret", []uint64{PermissionGroupActiveAccount})
	})

	app := APIHandler(conf, store, cache, eventbus.NewNoopSink(), nil)

	r := httptest.NewRequest("POST", "/api/sessions", jsonBody(t, struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{
		Email:    "jim@example.com",
		Password: "loginpass",
	}))
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)

	// Two-Factor is required and not provided. Login attempt must fail.
	if want, got := http.StatusUnauthorized, w.Code; want != got {
		t.Fatalf("want login response %d status, got %d: %s", want, got, w.Body)
	}

	r = httptest.NewRequest("POST", "/api/sessions", jsonBody(t, struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}{
		Email:    "jim@example.com",
		Password: "loginpass",
		Code:     totp.Generate(now, secret.Value("totpsecret")),
	}))
	w = httptest.NewRecorder()
	app.ServeHTTP(w, r)

	// Once 2fa code is provided as well, session creation succeeds.
	if want, got := http.StatusCreated, w.Code; want != got {
		t.Fatalf("want login response %d status, got %d: %s", want, got, w.Body)
	}

	var loginPayload struct {
		SessionID   string   `json:"session_id"`
		AccountID   string   `json:"account_id"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(w.Body).Decode(&loginPayload); err != nil {
		t.Fatalf("decode response body: %s", err)
	}
	if loginPayload.AccountID != accountID {
		t.Errorf("want account ID %q, got %q", accountID, loginPayload.AccountID)
	}
	if want, got := []string{"login"}, loginPayload.Permissions; !reflect.DeepEqual(want, got) {
		t.Errorf("want %q permissions, got %q", want, got)
	}
}

func TestAPIEnableTwoFactorWithSession(t *testing.T) {
	ctx := context.Background()
	ctx = alert.WithEmitter(ctx, alert.NewTestEmitter(t))

	store := newTestSQLiteStore(t)
	cache := cache.NewLocalMemCache(1e6)

	conf := APIConfiguration{
		PathPrefix:           "/api/",
		SessionMaxAge:        time.Hour,
		SessionRefreshAge:    time.Hour,
		RequireTwoFactorAuth: false,
	}

	atomic(t, store, func(s StoreSession) {
		insertAccount(t, s, "andy@example.com", "loginpass", "", []uint64{PermissionGroupActiveAccount})
		insertAccount(t, s, "bill@example.com", "loginpass", "", []uint64{PermissionGroupActiveAccount})
	})

	app := APIHandler(conf, store, cache, eventbus.NewNoopSink(), nil)

	// Create session in order to access two factor info API.
	r := httptest.NewRequest("POST", "/api/sessions", jsonBody(t, struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{
		Email:    "andy@example.com",
		Password: "loginpass",
	}))
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusCreated, w.Code; want != got {
		t.Fatalf("want login response %d status, got %d: %s", want, got, w.Body)
	}
	var auth struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(w.Body).Decode(&auth); err != nil {
		t.Fatalf("decode response body: %s", err)
	}

	r = httptest.NewRequest("GET", "/api/twofactor", nil)
	r.Header.Set("authorization", "Bearer "+auth.SessionID)
	w = httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusOK, w.Code; want != got {
		t.Fatalf("want two-factor info %d status, got %d: %s", want, got, w.Body)
	}
	var twoFactorStatus struct {
		Enabled bool
	}
	if err := json.NewDecoder(w.Body).Decode(&twoFactorStatus); err != nil {
		t.Fatalf("decode response body: %s", err)
	}
	if twoFactorStatus.Enabled {
		t.Fatal("two factor is enabled")
	}

	// Enable two-factor using session token.
	secret := bytes.Repeat([]byte("a"), 32)
	now := time.Now()
	r = httptest.NewRequest("POST", "/api/twofactor", jsonBody(t, struct {
		Secret string
		Code   string
	}{
		Secret: base32.StdEncoding.EncodeToString(secret),
		Code:   totp.Generate(now, secret),
	}))
	r.Header.Set("authorization", "Bearer "+auth.SessionID)
	w = httptest.NewRecorder()
	totp.WithCurrentTime(t, now.Add(time.Second))
	app.ServeHTTP(w, r)
	if want, got := http.StatusCreated, w.Code; want != got {
		t.Fatalf("want two-factor enabling %d status, got %d: %s", want, got, w.Body)
	}

	r = httptest.NewRequest("GET", "/api/twofactor", nil)
	r.Header.Set("authorization", "Bearer "+auth.SessionID)
	w = httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusOK, w.Code; want != got {
		t.Fatalf("want two-factor info %d status, got %d: %s", want, got, w.Body)
	}
	if err := json.NewDecoder(w.Body).Decode(&twoFactorStatus); err != nil {
		t.Fatalf("decode response body: %s", err)
	}
	if !twoFactorStatus.Enabled {
		t.Fatal("two factor is not enabled")
	}
}

func TestAPIEnableTwoFactorWithCredentials(t *testing.T) {
	ctx := context.Background()
	ctx = alert.WithEmitter(ctx, alert.NewTestEmitter(t))

	store := newTestSQLiteStore(t)
	cache := cache.NewLocalMemCache(1e6)

	conf := APIConfiguration{
		PathPrefix:        "/api/",
		SessionMaxAge:     time.Hour,
		SessionRefreshAge: time.Hour,
		// Because we are authenticating with credentials,
		// configuration might require two-factor. We do not create
		// session just yet.
		RequireTwoFactorAuth: true,
	}

	atomic(t, store, func(s StoreSession) {
		insertAccount(t, s, "andy@example.com", "loginpass", "", []uint64{PermissionGroupActiveAccount})
		insertAccount(t, s, "bill@example.com", "loginpass", "", []uint64{PermissionGroupActiveAccount})
	})

	app := APIHandler(conf, store, cache, eventbus.NewNoopSink(), nil)

	now := time.Now()
	secret := bytes.Repeat([]byte("a"), 32)

	// Optionally to using a session, two factor endpoint accepts
	// email/password combination.
	r := httptest.NewRequest("POST", "/api/twofactor", jsonBody(t, struct {
		Secret   string
		Code     string
		Email    string
		Password string
	}{
		Secret:   base32.StdEncoding.EncodeToString(secret),
		Code:     totp.Generate(now.Add(time.Hour), secret),
		Email:    "andy@example.com",
		Password: "loginpass",
	}))
	w := httptest.NewRecorder()
	totp.WithCurrentTime(t, now.Add(time.Hour+time.Second))
	app.ServeHTTP(w, r)
	if want, got := http.StatusCreated, w.Code; want != got {
		t.Fatalf("want two-factor enabling %d status, got %d: %s", want, got, w.Body)
	}
}

func TestAPICreateAccount(t *testing.T) {
	ctx := context.Background()
	ctx = alert.WithEmitter(ctx, alert.NewTestEmitter(t))

	conf := APIConfiguration{
		PathPrefix:                 "/api/",
		SessionMaxAge:              time.Hour,
		SessionRefreshAge:          time.Hour,
		AllowRegisterAccount:       true,
		MinPasswordLength:          8,
		RegisterAccountCompleteURL: "/register/{token}",
	}

	var events eventbus.RecordingSink
	var tasks taskqueue.RecordingScheduler
	store := newTestSQLiteStore(t)
	cache := cache.NewLocalMemCache(1e6)

	app := APIHandler(conf, store, cache, &events, &tasks)

	r := httptest.NewRequest("POST", "/api/accounts", jsonBody(t, struct {
		Email string `json:"email"`
	}{
		Email: "danny@example.com",
	})).WithContext(ctx)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusAccepted, w.Code; want != got {
		t.Fatalf("want  %d status, got %d: %s", want, got, w.Body)
	}

	var task SendConfirmRegistration
	tasks.LoadRecorded(t, 0, &task)

	if want, got := "danny@example.com", task.AccountEmail; want != got {
		t.Errorf("task scheduled with %q email, but registered with %q", got, want)
	}

	// Password limit must be respected.
	shortPass := strings.Repeat("a", int(conf.MinPasswordLength-1))
	r = httptest.NewRequest("PUT", "/api/accounts", jsonBody(t, struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}{
		Password: shortPass,
		Token:    task.Token,
	})).WithContext(ctx)
	w = httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusBadRequest, w.Code; want != got {
		t.Fatalf(" wat %d status, got %d: %s", want, got, w.Body)
	}
	validation.AssertHas(t, w.Body.Bytes(), "password")

	goodPass := strings.Repeat("a", int(conf.MinPasswordLength))
	r = httptest.NewRequest("PUT", "/api/accounts", jsonBody(t, struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}{
		Password: goodPass,
		Token:    task.Token,
	})).WithContext(ctx)
	w = httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusCreated, w.Code; want != got {
		t.Fatalf(" wat %d status, got %d: %s", want, got, w.Body)
	}
	var created struct {
		AccountID string `json:"account_id"`
	}
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode response body: %s", err)
	}

	atomic(t, store, func(s StoreSession) {
		a, err := s.AccountByID(ctx, created.AccountID)
		if err != nil {
			t.Fatal("created account cannot be found")
		}
		events.AssertPublished(t, AccountRegisteredEvent(a.AccountID, a.Email, a.CreatedAt))
	})

}

func TestAPIResetPasswordUnknownEmail(t *testing.T) {
	ctx := context.Background()
	ctx = alert.WithEmitter(ctx, alert.NewTestEmitter(t))

	conf := APIConfiguration{
		PathPrefix:         "/api/",
		SessionMaxAge:      time.Hour,
		SessionRefreshAge:  time.Hour,
		AllowPasswordReset: true,
		MinPasswordLength:  4,
	}

	var tasks taskqueue.RecordingScheduler
	store := newTestSQLiteStore(t)
	cache := cache.NewLocalMemCache(1e6)
	app := APIHandler(conf, store, cache, eventbus.NewNoopSink(), &tasks)

	r := httptest.NewRequest("POST", "/api/passwordreset", jsonBody(t, struct {
		Email string `json:"email"`
	}{
		Email: "roger@example.com",
	}))
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)

	// To prevent discovery of which emails are registered, response is always successful,
	if want, got := http.StatusAccepted, w.Code; want != got {
		t.Fatalf("want  %d status, got %d: %s", want, got, w.Body)
	}
	if len(tasks.Scheduled) != 0 {
		t.Fatalf("no tasks should be scheduled, found %d, %+v", len(tasks.Scheduled), tasks.Scheduled)
	}
}

func TestAPIResetPasswordSuccess(t *testing.T) {
	ctx := context.Background()
	ctx = alert.WithEmitter(ctx, alert.NewTestEmitter(t))

	conf := APIConfiguration{
		PathPrefix:         "/api/",
		SessionMaxAge:      time.Hour,
		SessionRefreshAge:  time.Hour,
		AllowPasswordReset: true,
		MinPasswordLength:  4,
	}

	var tasks taskqueue.RecordingScheduler
	store := newTestSQLiteStore(t)
	cache := cache.NewLocalMemCache(1e6)
	app := APIHandler(conf, store, cache, eventbus.NewNoopSink(), &tasks)

	atomic(t, store, func(s StoreSession) {
		insertAccount(t, s, "roger@example.com", "forgottenpassword", "", []uint64{PermissionGroupActiveAccount})
	})

	r := httptest.NewRequest("POST", "/api/passwordreset", jsonBody(t, struct {
		Email string `json:"email"`
	}{
		Email: "roger@example.com",
	}))
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusAccepted, w.Code; want != got {
		t.Fatalf("want  %d status, got %d: %s", want, got, w.Body)
	}

	// A token required to reset the password is sent by email. Introspect
	// task responsible for that.
	var task SendResetPassword
	tasks.LoadRecorded(t, 0, &task)

	r = httptest.NewRequest("PUT", "/api/passwordreset", jsonBody(t, struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}{
		Token:    task.Token,
		Password: strings.Repeat("a", int(conf.MinPasswordLength-1)),
	}))
	w = httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusBadRequest, w.Code; want != got {
		t.Fatalf("want  %d status, got %d: %s", want, got, w.Body)
	}
	validation.AssertHas(t, w.Body.Bytes(), "password")

	r = httptest.NewRequest("PUT", "/api/passwordreset", jsonBody(t, struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}{
		Token:    task.Token,
		Password: strings.Repeat("a", int(conf.MinPasswordLength)),
	}))
	w = httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusOK, w.Code; want != got {
		t.Fatalf("want  %d status, got %d: %s", want, got, w.Body)
	}

	// Login using new password.
	r = httptest.NewRequest("POST", "/api/sessions", jsonBody(t, struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{
		Email:    "roger@example.com",
		Password: strings.Repeat("a", int(conf.MinPasswordLength)),
	}))
	w = httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusCreated, w.Code; want != got {
		t.Fatalf("want  %d status, got %d: %s", want, got, w.Body)
	}
}

func jsonBody(t testing.TB, payload interface{}) io.Reader {
	t.Helper()

	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(payload); err != nil {
		t.Fatal(err)
	}
	return &b
}
