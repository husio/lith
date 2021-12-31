package lith

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/husio/lith/pkg/alert"
	"github.com/husio/lith/pkg/cache"
	"github.com/husio/lith/pkg/secret"
	"github.com/husio/lith/pkg/taskqueue"
	"github.com/husio/lith/pkg/totp"
)

func TestPublicEnableTwoFactorAuth(t *testing.T) {
	now := time.Now()
	totp.WithCurrentTime(t, now)

	conf := PublicUIConfiguration{
		PathPrefix:           "/t/",
		SessionMaxAge:        time.Hour,
		RequireTwoFactorAuth: false,
	}
	cases := map[string]struct {
		// Prepare is called before each test in order to
		// bootstrap the store state and return an authentication
		// session ID.
		Prepare      func(testing.TB, StoreSession) string
		WantGetCode  int
		Form         url.Values
		WantPostCode int
	}{
		"session is required": {
			Prepare: func(testing.TB, StoreSession) string {
				return "a-non-existing-session-id"
			},
			WantGetCode: http.StatusTemporaryRedirect,
		},
		"a valid code must be given to confirm": {
			Prepare: func(t testing.TB, s StoreSession) string {
				ctx := context.Background()
				a, err := s.CreateAccount(ctx, "joe@example.com", "asdldsdlkhsadsalkhdsa")
				if err != nil {
					t.Fatalf("create account: %s", err)
				}
				sessionID, err := s.CreateSession(ctx, a.AccountID, time.Hour)
				if err != nil {
					t.Fatalf("create session: %s", err)
				}
				return sessionID
			},
			Form: url.Values{
				// No input.
			},
			WantGetCode:  http.StatusOK,
			WantPostCode: http.StatusBadRequest,
		},
		"two factor already enabled": {
			Prepare: func(t testing.TB, s StoreSession) string {
				ctx := context.Background()
				a, err := s.CreateAccount(ctx, "joe@example.com", "akdlajdsalklkjoqiqwewqe")
				if err != nil {
					t.Fatalf("create account: %s", err)
				}
				if err := s.UpdateAccountTOTPSecret(ctx, a.AccountID, secret.Value("totp-t0p-secret")); err != nil {
					t.Fatalf("setup totp secret: %s", err)
				}
				sessionID, err := s.CreateSession(ctx, a.AccountID, time.Hour)
				if err != nil {
					t.Fatalf("create session: %s", err)
				}
				return sessionID
			},
			Form: url.Values{
				// No input.
			},
			WantGetCode: http.StatusSeeOther,
		},
		"providing a valid code enables two-factor authentication": {
			Prepare: func(t testing.TB, s StoreSession) string {
				ctx := context.Background()
				a, err := s.CreateAccount(ctx, "joe@example.com", "akdlajdsalklkjoqiqwewqe")
				if err != nil {
					t.Fatalf("create account: %s", err)
				}
				sessionID, err := s.CreateSession(ctx, a.AccountID, time.Hour)
				if err != nil {
					t.Fatalf("create session: %s", err)
				}

				// Used to generate a TOTP secret.
				secret.WithDeterministicGenerate(t, secret.Value("not-so-random"))

				return sessionID
			},
			WantGetCode: http.StatusOK,
			Form: url.Values{
				"code": []string{
					totp.Generate(now.Add(time.Second), secret.Value("not-so-random")),
				},
			},
			WantPostCode: http.StatusSeeOther,
		},
	}

	for testName, tc := range cases {
		t.Run(testName, func(t *testing.T) {
			store := newTestSQLiteStore(t)
			var sessionID string
			atomic(t, store, func(s StoreSession) {
				sessionID = tc.Prepare(t, s)
			})
			cache := cache.NewLocalMemCache(1e6)
			safe := secret.AESSafe("t0p-secret")
			app := PublicHandler(conf, store, cache, safe, secret.Generate(16), nil)

			r := httptest.NewRequest("GET", "/t/twofactor/enable/", nil)
			r.Header.Set("cookie", "s="+sessionID)
			w := httptest.NewRecorder()
			app.ServeHTTP(w, r)
			if want, got := tc.WantGetCode, w.Code; want != got {
				t.Fatalf("want 2fa GET response %d status, got %d: %s", want, got, w.Body)
			}

			if w.Code >= 300 {
				return
			}

			csrfToken, csrfCookie := readCSRFToken(t, w)
			tc.Form.Add("csrf", csrfToken)
			body := strings.NewReader(tc.Form.Encode())
			r = httptest.NewRequest("POST", "/t/twofactor/enable/", body)
			r.Header.Set("content-type", "application/x-www-form-urlencoded")
			r.Header.Set("cookie", "s="+sessionID)
			r.Header.Add("cookie", csrfCookie)
			w = httptest.NewRecorder()
			app.ServeHTTP(w, r)
			if want, got := tc.WantPostCode, w.Code; want != got {
				t.Fatalf("want 2fa POST response %d status, got %d: %s", want, got, w.Body)
			}
		})
	}
}

func TestPublicRegisterAccount(t *testing.T) {
	conf := PublicUIConfiguration{
		PathPrefix:                        "/public/",
		SessionMaxAge:                     time.Hour,
		RequireTwoFactorAuth:              false,
		AllowRegisterAccount:              true,
		RegisteredAccountPermissionGroups: []uint64{PermissionGroupActiveAccount},
		Domain:                            "tests.com",
		DomainSSL:                         true,
		MinPasswordLength:                 16,
	}

	var tasks taskqueue.RecordingScheduler
	store := newTestSQLiteStore(t)
	cache := cache.NewLocalMemCache(1e6)
	safe := secret.AESSafe("t0p-secret")
	app := PublicHandler(conf, store, cache, safe, secret.Generate(16), &tasks)

	r := httptest.NewRequest("GET", "/public/register/", nil)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusOK, w.Code; want != got {
		t.Fatalf("want register GET response %d status, got %d: %s", want, got, w.Body)
	}

	csrfToken, csrfCookie := readCSRFToken(t, w)

	body := url.Values{
		"email": {"mona@example.com"},
		"csrf":  {csrfToken},
	}
	r = httptest.NewRequest("POST", "/public/register/", strings.NewReader(body.Encode()))
	r.Header.Set("content-type", "application/x-www-form-urlencoded")
	r.Header.Set("cookie", csrfCookie)
	w = httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusOK, w.Code; want != got {
		t.Fatalf("want register POST response %d status, got %d: %s", want, got, w.Body)
	}

	var task SendConfirmRegistration
	tasks.LoadRecorded(t, 0, &task)

	if task.AccountEmail != "mona@example.com" {
		t.Errorf("unexpected email address: %q", task.AccountEmail)
	}
	if want, got := "https://tests.com/public/register/"+task.Token+"/", task.CompleteURL; want != got {
		t.Errorf("want completion URL to be %q, got %q", want, got)
	}

	t.Run("password must be not shorter than MinPasswordLength", func(t *testing.T) {
		body = url.Values{
			"token":           []string{task.Token},
			"password":        []string{strings.Repeat("a", int(conf.MinPasswordLength-1))},
			"password_repeat": []string{strings.Repeat("a", int(conf.MinPasswordLength-1))},
			"csrf":            {csrfToken},
		}
		r := httptest.NewRequest("POST", "/public/register/"+task.Token+"/", strings.NewReader(body.Encode()))
		r.Header.Set("content-type", "application/x-www-form-urlencoded")
		r.Header.Set("cookie", csrfCookie)
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if want, got := http.StatusBadRequest, w.Code; want != got {
			t.Fatalf("want register POST response %d status, got %d: %s", want, got, w.Body)
		}
	})

	t.Run("csrf token is required", func(t *testing.T) {
		r = httptest.NewRequest("POST", "/public/register/"+task.Token+"/", strings.NewReader(url.Values{}.Encode()))
		r.Header.Set("content-type", "application/x-www-form-urlencoded")
		w = httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if want, got := http.StatusForbidden, w.Code; want != got {
			t.Fatalf("want register POST response %d status, got %d: %s", want, got, w.Body)
		}
	})

	t.Run("password and password_repeat must be the same", func(t *testing.T) {
		body = url.Values{
			"token":           []string{task.Token},
			"password":        []string{strings.Repeat("a", int(conf.MinPasswordLength))},
			"password_repeat": []string{strings.Repeat("b", int(conf.MinPasswordLength))},
			"csrf":            {csrfToken},
		}
		r := httptest.NewRequest("POST", "/public/register/"+task.Token+"/", strings.NewReader(body.Encode()))
		r.Header.Set("content-type", "application/x-www-form-urlencoded")
		r.Header.Set("cookie", csrfCookie)
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if want, got := http.StatusBadRequest, w.Code; want != got {
			t.Fatalf("want register POST response %d status, got %d: %s", want, got, w.Body)
		}
	})

	body = url.Values{
		"token":           []string{task.Token},
		"password":        []string{strings.Repeat("a", int(conf.MinPasswordLength))},
		"password_repeat": []string{strings.Repeat("a", int(conf.MinPasswordLength))},
		"csrf":            {csrfToken},
	}
	r = httptest.NewRequest("POST", "/public/register/"+task.Token+"/", strings.NewReader(body.Encode()))
	r.Header.Set("content-type", "application/x-www-form-urlencoded")
	r.Header.Set("cookie", csrfCookie)
	w = httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusOK, w.Code; want != got {
		t.Fatalf("want register POST response %d status, got %d: %s", want, got, w.Body)
	}

	atomic(t, store, func(s StoreSession) {
		a, err := s.AccountByEmail(context.Background(), "mona@example.com")
		if err != nil {
			t.Fatalf("getting mona account: %s", err)
		}
		if !reflect.DeepEqual(a.Permissions, []string{"login"}) {
			t.Fatalf("unexpected permissions: %q", a.Permissions)
		}
	})
}

func TestPublicResetPassword(t *testing.T) {
	// t.Fatal("todo")
	t.Skip("todo")
}

func TestPublicLoginNoTwoFactorAuth(t *testing.T) {
	conf := PublicUIConfiguration{
		PathPrefix:           "/t/",
		SessionMaxAge:        time.Hour,
		RequireTwoFactorAuth: false,
	}

	cases := map[string]struct {
		// PrepareStore is called before each test in order to
		// bootstrap the store state.
		PrepareStore func(testing.TB, StoreSession)
		Form         url.Values
		WantCode     int
		WantNext     string
		WantLoggedAs string
	}{
		"successful admin login with next": {
			PrepareStore: func(t testing.TB, s StoreSession) {
				insertAccount(t, s, "admin@example.com", "t0p-secret", "", []uint64{PermissionGroupActiveAccount, PermissionGroupSystemAdmin})
			},
			Form: url.Values{
				"email":    {"admin@example.com"},
				"password": {"t0p-secret"},
				"next":     {"/look-at-this/"},
			},
			WantCode:     http.StatusSeeOther,
			WantNext:     "/look-at-this/",
			WantLoggedAs: "admin@example.com",
		},
		"successful user login, no next": {
			PrepareStore: func(t testing.TB, s StoreSession) {
				insertAccount(t, s, "user@example.com", "t0p-secret", "", []uint64{PermissionGroupActiveAccount})
			},
			Form: url.Values{
				"email":    {"user@example.com"},
				"password": {"t0p-secret"},
			},
			WantCode:     http.StatusSeeOther,
			WantNext:     "/t/", // Because of conf.PathPrefix.
			WantLoggedAs: "user@example.com",
		},
		"missing login permission": {
			PrepareStore: func(t testing.TB, s StoreSession) {
				insertAccount(t, s, "nopermissions@example.com", "t0p-secret", "", nil)
			},
			Form: url.Values{
				"email":    {"nopermissions@example.com"},
				"password": {"t0p-secret"},
			},
			WantCode: http.StatusForbidden,
		},
	}

	for testName, tc := range cases {
		t.Run(testName, func(t *testing.T) {
			store := newTestSQLiteStore(t)

			atomic(t, store, func(s StoreSession) {
				tc.PrepareStore(t, s)
			})

			app := PublicHandler(conf, store, nil, nil, secret.Generate(16), nil)

			csrfToken, csrfCookie := acquireCSRFToken(t, "/t/login/", app)

			tc.Form.Add("csrf", csrfToken)
			body := strings.NewReader(tc.Form.Encode())
			r := httptest.NewRequest("POST", "/t/login/", body)
			r.Header.Set("content-type", "application/x-www-form-urlencoded")
			r.Header.Set("cookie", csrfCookie)
			w := httptest.NewRecorder()

			app.ServeHTTP(w, r)

			if want, got := tc.WantCode, w.Code; want != got {
				t.Fatalf("want %d status, got %d: %s", want, got, w.Body)
			}
			if want, got := tc.WantNext, w.Header().Get("location"); want != got {
				t.Fatalf("want next %q, got %q", want, got)
			}
			if tc.WantLoggedAs != "" {
				assertIsLoggedAs(t, w, store, tc.WantLoggedAs)
			}
		})
	}
}

func TestPublicLoginWithTwoFactorAuth(t *testing.T) {
	now := time.Now()
	withCurrentTime(t, now)
	totp.WithCurrentTime(t, now)

	ctx := context.Background()
	ctx = alert.WithEmitter(ctx, alert.NewTextEmitter(os.Stdout))

	conf := PublicUIConfiguration{
		PathPrefix:           "/t/",
		RequireTwoFactorAuth: true,
		SessionMaxAge:        time.Hour,
	}

	cases := map[string]struct {
		// Prepare is called before each test in order to
		// bootstrap the store state.
		Prepare func(testing.TB, StoreSession, cache.Store)

		FormLogin     url.Values
		WantLoginCode int
		Form2Fa       url.Values
		Want2FaCode   int
		WantNext      string
		WantLoggedAs  string
	}{
		"successful admin login with next": {
			Prepare: func(t testing.TB, s StoreSession, c cache.Store) {
				insertAccount(t, s, "admin@example.com", "pass", "totp-secret", []uint64{
					PermissionGroupActiveAccount,
					PermissionGroupSystemAdmin,
				})
			},
			FormLogin: url.Values{
				"email":    {"admin@example.com"},
				"password": {"pass"},
				"next":     {"/look-at-this/"},
			},
			WantLoginCode: http.StatusSeeOther,
			Form2Fa: url.Values{
				"code": {totp.Generate(now, []byte("totp-secret"))},
			},
			Want2FaCode:  http.StatusSeeOther,
			WantNext:     "/look-at-this/",
			WantLoggedAs: "admin@example.com",
		},
		"successful user login without next": {
			Prepare: func(t testing.TB, s StoreSession, c cache.Store) {
				insertAccount(t, s, "user@example.com", "pass", "totp-secret", []uint64{PermissionGroupActiveAccount})
			},
			FormLogin: url.Values{
				"email":    {"user@example.com"},
				"password": {"pass"},
			},
			WantLoginCode: http.StatusSeeOther,
			Form2Fa: url.Values{
				"code": {totp.Generate(now, []byte("totp-secret"))},
			},
			Want2FaCode:  http.StatusSeeOther,
			WantNext:     "/",
			WantLoggedAs: "user@example.com",
		},
		"successful user login using an older 2fa code": {
			Prepare: func(t testing.TB, s StoreSession, c cache.Store) {
				insertAccount(t, s, "user@example.com", "pass", "totp-secret", []uint64{PermissionGroupActiveAccount})
			},
			FormLogin: url.Values{
				"email":    {"user@example.com"},
				"password": {"pass"},
			},
			WantLoginCode: http.StatusSeeOther,
			Form2Fa: url.Values{
				// It is hard to figure out what when the next
				// TOTP window, so assume that using close to
				// 30s value will capture that case often
				// enough.
				"code": {totp.Generate(now.Add(-25*time.Second), []byte("totp-secret"))},
			},
			Want2FaCode:  http.StatusSeeOther,
			WantNext:     "/",
			WantLoggedAs: "user@example.com",
		},
		"invalid 2fa code": {
			Prepare: func(t testing.TB, s StoreSession, c cache.Store) {
				insertAccount(t, s, "user@example.com", "pass", "totp-secret", []uint64{PermissionGroupActiveAccount})
			},
			FormLogin: url.Values{
				"email":    {"user@example.com"},
				"password": {"pass"},
			},
			WantLoginCode: http.StatusSeeOther,
			Form2Fa: url.Values{
				"code": {"123456"},
			},
			Want2FaCode: http.StatusBadRequest,
		},
		"valid but already used 2fa code": {
			Prepare: func(t testing.TB, s StoreSession, c cache.Store) {
				const totpSecret = "qwertyuiop"

				insertAccount(t, s, "user@example.com", "pass", totpSecret, []uint64{PermissionGroupActiveAccount})

				// Validate totp secret in order to claim its use. Next validation call must return ErrUsed.
				code := totp.Generate(now, []byte(totpSecret))
				if err := totp.Validate(context.Background(), c, code, []byte(totpSecret)); err != nil {
					t.Fatalf("validate totp: %s", err)
				}
			},
			FormLogin: url.Values{
				"email":    {"user@example.com"},
				"password": {"pass"},
			},
			WantLoginCode: http.StatusSeeOther,
			Form2Fa: url.Values{
				"code": {totp.Generate(now, []byte("totp-secret"))},
			},
			Want2FaCode: http.StatusBadRequest,
		},
		"missing login permission": {
			Prepare: func(t testing.TB, s StoreSession, c cache.Store) {
				insertAccount(t, s, "nopermissions@example.com", "password", "totp-secret", nil)
			},
			FormLogin: url.Values{
				"email":    {"nopermissions@example.com"},
				"password": {"password"},
			},
			WantLoginCode: http.StatusForbidden,
		},
	}

	for testName, tc := range cases {
		t.Run(testName, func(t *testing.T) {
			store := newTestSQLiteStore(t)

			cache := cache.NewLocalMemCache(1e6)
			safe := secret.AESSafe("t0p-secret")

			atomic(t, store, func(s StoreSession) {
				tc.Prepare(t, s, cache)
			})

			app := PublicHandler(conf, store, cache, safe, secret.Generate(16), nil)

			csrfToken, csrfCookie := acquireCSRFToken(t, "/t/login/", app)

			tc.FormLogin.Set("csrf", csrfToken)
			r := httptest.NewRequest("POST", "/t/login/", strings.NewReader(tc.FormLogin.Encode()))
			r = r.WithContext(ctx)
			r.Header.Set("cookie", csrfCookie)
			r.Header.Set("content-type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			app.ServeHTTP(w, r)
			if want, got := tc.WantLoginCode, w.Code; want != got {
				t.Fatalf("want login response %d status, got %d: %s", want, got, w.Body)
			}
			if tc.WantLoginCode > 399 {
				return
			}

			// Time is passing between submitting forms.
			now = now.Add(time.Second)
			withCurrentTime(t, now)
			totp.WithCurrentTime(t, now)

			tc.Form2Fa.Set("csrf", csrfToken)
			r = httptest.NewRequest("POST", w.Header().Get("location"), strings.NewReader(tc.Form2Fa.Encode()))
			r.Header.Set("content-type", "application/x-www-form-urlencoded")
			r.Header.Set("cookie", w.HeaderMap.Get("set-cookie"))
			r.Header.Add("cookie", csrfCookie)
			w = httptest.NewRecorder()
			app.ServeHTTP(w, r)

			if want, got := tc.Want2FaCode, w.Code; want != got {
				t.Fatalf("want 2fa response %d status, got %d: %s", want, got, w.Body)
			}
			if tc.WantLoggedAs != "" {
				assertIsLoggedAs(t, w, store, tc.WantLoggedAs)
			}
			if want, got := tc.WantNext, w.Header().Get("location"); want != got {
				t.Fatalf("want next %q, got %q", want, got)
			}
		})
	}
}

func TestPublicLoginWithTwoFactorAuthRequired(t *testing.T) {
	ctx := context.Background()
	ctx = alert.WithEmitter(ctx, alert.NewTextEmitter(os.Stdout))

	store := newTestSQLiteStore(t)
	cache := cache.NewLocalMemCache(1e6)
	safe := secret.AESSafe("t0p-secret")

	secret.WithDeterministicGenerate(t, secret.Value("secret-1234"))

	var accountID string
	atomic(t, store, func(s StoreSession) {
		// An account without 2fa setup.
		accountID = insertAccount(t, s, "joe@example.com", "logpass", "", []uint64{PermissionGroupActiveAccount})
	})

	app := PublicHandler(PublicUIConfiguration{
		PathPrefix:           "/2fa-required/",
		SessionMaxAge:        time.Hour,
		RequireTwoFactorAuth: true,
	}, store, cache, safe, secret.Generate(16), nil)

	csrfToken, csrfCookie := acquireCSRFToken(t, "/2fa-required/login/", app)

	r := httptest.NewRequest("POST", "/2fa-required/login/", strings.NewReader(url.Values{
		"email":    {"joe@example.com"},
		"password": {"logpass"},
		"next":     {"/2fa-enabled-club/"},
		"csrf":     {csrfToken},
	}.Encode()))
	r = r.WithContext(ctx)
	r.Header.Set("content-type", "application/x-www-form-urlencoded")
	r.Header.Set("cookie", csrfCookie)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if want, got := http.StatusSeeOther, w.Code; want != got {
		t.Fatalf("want login response %d status, got %d: %s", want, got, w.Body)
	}

	enable2FaURL := w.Header().Get("location")
	tmpSessionCookie := w.HeaderMap.Get("set-cookie")

	// Follow the redirect URL in order to prepare account for enabling 2fa.
	r = httptest.NewRequest("GET", enable2FaURL, nil)
	// A temporary session cookie must be provided.
	r.Header.Set("cookie", tmpSessionCookie)
	w = httptest.NewRecorder()
	app.ServeHTTP(w, r)

	if want, got := http.StatusOK, w.Code; want != got {
		t.Fatalf("want login response %d status, got %d: %s", want, got, w.Body)
	}

	atomic(t, store, func(s StoreSession) {
		if _, err := s.AccountTOTPSecret(ctx, accountID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Until the user confirms 2fa enabling, TOTP secret must not be set, got %+v", err)
		}
	})
	// Change the generated secret to some other value, to ensure that once
	// generated TOTP secret is carried throughout the process and not
	// replaced with a new value.
	secret.WithDeterministicGenerate(t, secret.Value("some-other-secret"))

	r = httptest.NewRequest("POST", enable2FaURL, strings.NewReader(url.Values{
		"code": {
			// WithDeterministicGenerate ensures that the new TOTP
			// secret is not random.
			totp.Generate(time.Now().Add(-time.Second), secret.Value("secret-1234")),
		},
		"csrf": {csrfToken},
	}.Encode()))
	r.Header.Set("content-type", "application/x-www-form-urlencoded")
	// A temporary session cookie must be provided.
	r.Header.Add("cookie", tmpSessionCookie)
	r.Header.Add("cookie", csrfCookie)
	w = httptest.NewRecorder()
	app.ServeHTTP(w, r)

	if want, got := http.StatusSeeOther, w.Code; want != got {
		t.Fatalf("want login response %d status, got %d: %s", want, got, w.Body)
	}

	atomic(t, store, func(s StoreSession) {
		totpSecret, err := s.AccountTOTPSecret(ctx, accountID)
		if err != nil {
			t.Fatalf("get TOTP secret: %+v", err)
		}
		if !bytes.Equal(totpSecret, []byte("secret-1234")) {
			t.Fatalf("unexpected TOTP secret set for %q account: %q", accountID, string(totpSecret))
		}
	})

	if want, got := "/2fa-enabled-club/", w.Header().Get("location"); want != got {
		t.Errorf("want next %q, got %q", want, got)
	}

	assertIsLoggedAs(t, w, store, "joe@example.com")
}

func assertIsLoggedAs(t testing.TB, w *httptest.ResponseRecorder, store Store, email string) {
	t.Helper()

	request := &http.Request{Header: http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}}
	cookie, err := request.Cookie("s")
	if err != nil {
		t.Log(w.HeaderMap)
		t.Fatalf("read session cookie: %s", err)
	}

	session, err := store.Session(context.Background())
	if err != nil {
		t.Fatalf("create new store session: %s", err)
	}
	defer session.Rollback()

	account, err := session.AccountBySession(context.Background(), cookie.Value)
	if err != nil {
		t.Fatalf("account by session %q: %s", cookie.Value, err)
	}
	if account.Email != email {
		t.Fatalf("want %q email, session belogns to %q (account %q)", email, account.Email, account.AccountID)
	}
}
