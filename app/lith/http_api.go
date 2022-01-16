package lith

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/husio/lith/pkg/alert"
	"github.com/husio/lith/pkg/cache"
	"github.com/husio/lith/pkg/eventbus"
	"github.com/husio/lith/pkg/taskqueue"
	"github.com/husio/lith/pkg/totp"
	"github.com/husio/lith/pkg/translation"
	"github.com/husio/lith/pkg/validation"
	"github.com/husio/lith/pkg/web"
)

func APIHandler(
	conf APIConfiguration,
	store Store,
	cache cache.Store,
	events eventbus.Sink,
	queue taskqueue.Scheduler,
) http.Handler {
	rt := web.NewRouter()
	rt.MethodNotAllowed = apiDefaultHandler{code: http.StatusMethodNotAllowed}
	rt.NotFound = apiDefaultHandler{code: http.StatusNotFound}

	p := conf.PathPrefix
	rt.Add(`GET    `+p+`sessions`, apiSessionIntrospect{store: store, conf: conf})
	rt.Add(`POST   `+p+`sessions`, apiSessionCreate{store: store, conf: conf, cache: cache})
	rt.Add(`DELETE `+p+`sessions`, apiSessionDelete{store: store, conf: conf})
	rt.Add(`GET    `+p+`twofactor`, apiTwoFactorStatus{store: store, conf: conf})
	rt.Add(`POST   `+p+`twofactor`, apiTwoFactorEnable{store: store, conf: conf, cache: cache})
	if conf.AllowRegisterAccount {
		rt.Add(`POST   `+p+`accounts`, apiAccountCreateInit{store: store, conf: conf, queue: queue})
		rt.Add(`PUT    `+p+`accounts`, apiAccountCreateComplete{store: store, conf: conf, events: events})
	}
	if conf.AllowPasswordReset {
		rt.Add(`POST   `+p+`passwordreset`, apiPasswordResetInit{store: store, conf: conf, queue: queue})
		rt.Add(`PUT    `+p+`passwordreset`, apiPasswordResetComplete{store: store, conf: conf})
	}

	rt.Use(
		web.RequestIDMiddleware(),
		web.RecoverMiddleware(),
		web.TrailingSlashMiddleware(false),
		web.CORSMiddleware(conf.CORSDomain, "GET,POST,PUT,DELETE", "Authorization"),
		translation.LanguageMiddleware,
		AuthMiddleware(store, SessionFromHeader),
	)

	return rt
}

type responseAccountSession struct {
	AccountID   string    `json:"account_id"`
	SessionID   string    `json:"session_id"`
	Permissions []string  `json:"permissions"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type apiDefaultHandler struct {
	code int
	conf APIConfiguration
}

func (h apiDefaultHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	web.WriteJSONStdErr(w, h.code)
}

type apiPasswordResetInit struct {
	store Store
	conf  APIConfiguration
	queue taskqueue.Scheduler
}

func (h apiPasswordResetInit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		web.WriteJSONErr(w, http.StatusBadRequest, "Invalid input JSON.")
		return
	}

	var errs validation.Errors
	input.Email = normalizeEmail(input.Email)
	if input.Email == "" {
		errs.AddRequired("email")
	}
	if !errs.Empty() {
		web.WriteJSON(w, http.StatusBadRequest, errs)
		return
	}

	ctx := r.Context()

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	defer session.Rollback()

	account, err := session.AccountByEmail(ctx, input.Email)
	switch {
	case err == nil:
		// All good.
	case errors.Is(err, ErrNotFound):
		// Account not found, but because we don't want to give up what
		// accounts are registered, a successful message is returned.
		w.WriteHeader(http.StatusAccepted)
		return
	default:
		alert.EmitErr(ctx, err, "Cannot get account by email.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	token, err := session.CreateEphemeralToken(ctx, "api-reset-password", 6*time.Hour, struct {
		AccountID string
		Email     string
	}{
		AccountID: account.AccountID,
		Email:     input.Email,
	})
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create ephemeral token.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	completeURL, err := formatCompleteURL(h.conf.PasswordResetCompleteURL, token)
	if err != nil {
		alert.EmitErr(ctx, err, "Invalid configuration. Cannot parse PasswordResetCompleteURL")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	taskID, err := h.queue.Schedule(ctx, SendResetPassword{
		FromEmail:    h.conf.FromEmail,
		AccountID:    account.AccountID,
		Token:        token,
		AccountEmail: account.Email,
		CompleteURL:  completeURL,
	}, taskqueue.Delay(2*time.Second)) // Delay so that it can be cancelled if needed.
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot schedule SendResetPassword task")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	if err := session.Commit(); err != nil {
		_ = h.queue.Cancel(ctx, taskID)
		alert.EmitErr(ctx, err, "Cannot commit session.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

type apiPasswordResetComplete struct {
	store Store
	conf  APIConfiguration
}

func (h apiPasswordResetComplete) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		web.WriteJSONErr(w, http.StatusBadRequest, "Invalid input JSON.")
		return
	}

	var errs validation.Errors
	if input.Token == "" {
		errs.AddRequired("token")
	}
	if input.Password == "" {
		errs.AddRequired("password")
	} else if len(input.Password) < int(h.conf.MinPasswordLength) {
		errs.Add("password", "Too short. Must be at least %d characters.", h.conf.MinPasswordLength)
	}
	if !errs.Empty() {
		web.WriteJSON(w, http.StatusBadRequest, errs)
		return
	}

	ctx := r.Context()
	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	defer session.Rollback()

	var resetPasswordContext struct {
		AccountID string
		Email     string
	}
	switch err := session.EphemeralToken(ctx, "api-reset-password", input.Token, &resetPasswordContext); {
	case err == nil:
		// All good.
	case errors.Is(err, ErrNotFound):
		web.WriteJSONErr(w, http.StatusUnauthorized, "Invalid token.")
		return
	default:
		alert.EmitErr(ctx, err, "Cannot get ephemeral token.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	account, err := session.AccountByID(ctx, resetPasswordContext.AccountID)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot get account referenced by ephemeral token.",
			"token", input.Token,
			"account_id", resetPasswordContext.AccountID)
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	if account.Email != resetPasswordContext.Email {
		web.WriteJSONErr(w, http.StatusConflict, "Account email was changed.")
		return
	}

	if err := session.UpdateAccountPassword(ctx, account.AccountID, input.Password); err != nil {
		alert.EmitErr(ctx, err, "Cannot update account password.",
			"account_id", account.AccountID)
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	if err := session.DeleteEphemeralToken(ctx, input.Token); err != nil {
		alert.EmitErr(ctx, err, "Cannot delete existing ephemeral token.",
			"token", input.Token)
	}
	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	web.WriteJSON(w, http.StatusOK, struct {
		AccountID string `json:"account_id"`
	}{
		AccountID: account.AccountID,
	})
}

type apiAccountCreateInit struct {
	store Store
	conf  APIConfiguration
	queue taskqueue.Scheduler
}

func (h apiAccountCreateInit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		web.WriteJSONErr(w, http.StatusBadRequest, "Invalid input JSON.")
		return
	}

	var errs validation.Errors
	input.Email = normalizeEmail(input.Email)
	if input.Email == "" {
		errs.AddRequired("email")
	} else if ok, _ := regexp.MatchString(h.conf.AllowRegisterEmail, input.Email); !ok {
		errs.Add("email", "Email address not allowed to register.")
	}
	if !errs.Empty() {
		web.WriteJSON(w, http.StatusBadRequest, errs)
		return
	}

	ctx := r.Context()

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	defer session.Rollback()

	switch _, err := session.AccountByEmail(ctx, input.Email); {
	case err == nil:
		web.WriteJSONErr(w, http.StatusConflict, "Account already registered.")
		return
	case errors.Is(err, ErrNotFound):
		// All good.
	default:
		alert.EmitErr(ctx, err, "Cannot get an account by email.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	token, err := session.CreateEphemeralToken(ctx, "api-register-account", 6*time.Hour, struct {
		Email string
	}{
		Email: input.Email,
	})
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create ephemeral token.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	completeURL, err := formatCompleteURL(h.conf.RegisterAccountCompleteURL, token)
	if err != nil {
		alert.EmitErr(ctx, err, "Invalid configuration. Cannot parse RegisterAccountCompleteURL")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	taskID, err := h.queue.Schedule(ctx, SendConfirmRegistration{
		FromEmail:    h.conf.FromEmail,
		AccountEmail: input.Email,
		Token:        token,
		CompleteURL:  completeURL,
	}, taskqueue.Delay(2*time.Second)) // Delay so that it can be cancelled if needed.
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot schedule SendConfirmRegistration task")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	if err := session.Commit(); err != nil {
		_ = h.queue.Cancel(ctx, taskID)
		alert.EmitErr(ctx, err, "Cannot commit session.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

type apiAccountCreateComplete struct {
	store  Store
	conf   APIConfiguration
	events eventbus.Sink
}

func (h apiAccountCreateComplete) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token    string
		Password string
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		web.WriteJSONErr(w, http.StatusBadRequest, "Invalid input JSON.")
		return
	}

	var errs validation.Errors
	if input.Token == "" {
		errs.AddRequired("password")
	}
	switch n := len(input.Password); {
	case n == 0:
		errs.AddRequired("password")
	case n < int(h.conf.MinPasswordLength):
		errs.Add("password", "Too short. Must be at least %d characters.", h.conf.MinPasswordLength)
	case n > 256:
		errs.Add("password", "Too long. Must not be more than 256 characters.")
	}
	if !errs.Empty() {
		web.WriteJSON(w, http.StatusBadRequest, errs)
		return
	}

	ctx := r.Context()

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	defer session.Rollback()

	var registerAccountContext struct {
		Email string
	}
	switch err := session.EphemeralToken(ctx, "api-register-account", input.Token, &registerAccountContext); {
	case err == nil:
		// All good.
	case errors.Is(err, ErrNotFound):
		web.WriteJSONErr(w, http.StatusUnauthorized, "Invalid token.")
		return
	default:
		alert.EmitErr(ctx, err, "Cannot get ephemeral token.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	if err := session.DeleteEphemeralToken(ctx, input.Token); err != nil {
		alert.EmitErr(ctx, err, "Cannot delete existing ephemeral token.",
			"token", input.Token)
	}

	account, err := session.CreateAccount(ctx, registerAccountContext.Email, input.Password)
	switch {
	case err == nil:
		// All good.
	case errors.Is(err, ErrConflict):
		web.WriteJSONErr(w, http.StatusConflict, "Account already registered.")
		return
	default:
		alert.EmitErr(ctx, err, "Cannot register an account.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	if err := session.UpdateAccountPermissionGroups(ctx, account.AccountID, h.conf.RegisteredAccountPermissionGroups); err != nil {
		alert.EmitErr(ctx, err, "Cannot assign permission groups.",
			"account_id", account.AccountID)
	}

	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	event := AccountRegisteredEvent(account.AccountID, account.Email, account.CreatedAt)
	if err := h.events.PublishEvent(ctx, event); err != nil {
		alert.EmitErr(ctx, err,
			"Cannot emit event.",
			"account", account.AccountID,
			"event", "AccountRegisteredEvent")
	}

	web.WriteJSON(w, http.StatusCreated, struct {
		AccountID string `json:"account_id"`
	}{
		AccountID: account.AccountID,
	})
}

type apiSessionIntrospect struct {
	store Store
	conf  APIConfiguration
}

func (h apiSessionIntrospect) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a, ok := CurrentAccount(ctx)
	if !ok {
		web.WriteJSONErr(w, http.StatusUnauthorized, "Missing or invalid session key.")
		return
	}

	sessionID, _ := CurrentSessionID(ctx)
	expiresAt, err := refreshAuthSession(ctx, h.store, sessionID, h.conf.SessionRefreshAge)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot refresh auth session.")
		// Not critical for the session introspection.
	}
	web.WriteJSON(w, http.StatusOK, responseAccountSession{
		SessionID:   sessionID,
		AccountID:   a.AccountID,
		Permissions: a.Permissions,
		ExpiresAt:   expiresAt,
	})
}

func refreshAuthSession(ctx context.Context, store Store, sessionID string, refresh time.Duration) (time.Time, error) {
	session, err := store.Session(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("create database session: %w", err)
	}
	expiresAt, err := session.RefreshSession(ctx, sessionID, refresh)
	if err != nil {
		return time.Time{}, fmt.Errorf("refresh auth session: %w", err)
	}
	if err := session.Commit(); err != nil {
		return time.Time{}, fmt.Errorf("commit database session: %w", err)
	}
	return expiresAt, nil
}

type apiSessionDelete struct {
	store Store
	conf  APIConfiguration
}

func (h apiSessionDelete) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sessionID, ok := CurrentSessionID(ctx)
	if !ok {
		web.WriteJSONStdErr(w, http.StatusUnauthorized)
		return
	}
	db, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	defer db.Rollback()

	switch err := db.DeleteSession(ctx, sessionID); {
	case err == nil:
		// All good.
	case errors.Is(err, ErrNotFound):
		// This is a rare case when authentication was successful,
		// validated by the middleware, but the session no longer
		// exists in the database. Since the session is gone, operation
		// can be considered successful and there is nothing else to
		// do.
		w.WriteHeader(http.StatusGone)
		return
	default:
		alert.EmitErr(ctx, err, "Cannot delete auth sessions.",
			"session_id", sessionID)
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	if err := db.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusGone)
}

type apiSessionCreate struct {
	store Store
	conf  APIConfiguration
	cache cache.Store
}

func (h apiSessionCreate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"` // Plain text.
		Code     string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		web.WriteJSONErr(w, http.StatusBadRequest, "Invalid input JSON.")
		return
	}

	var errs validation.Errors
	input.Email = normalizeEmail(input.Email)
	if input.Email == "" {
		errs.AddRequired("email")
	}
	if input.Password == "" {
		errs.AddRequired("password")
	}

	// Before validating password, we cannot know if account requires
	// two-factor code. Validation of Code must be postponed.
	input.Code = strings.TrimSpace(input.Code)

	if !errs.Empty() {
		web.WriteJSON(w, http.StatusBadRequest, errs)
		return
	}

	ctx := r.Context()

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	defer session.Rollback()

	account, err := session.AccountByEmail(ctx, input.Email)
	switch {
	case err == nil:
		// All good.
	case errors.Is(err, ErrNotFound):
		web.WriteJSONErr(w, http.StatusBadRequest, "Invalid login and/or password.")
		return
	default:
		alert.EmitErr(ctx, err, "Cannot get account by email.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	switch err := session.IsAccountPassword(ctx, account.AccountID, input.Password); {
	case err == nil:
		// All good.
	case errors.Is(err, ErrPassword):
		web.WriteJSONErr(w, http.StatusBadRequest, "Invalid login and/or password.")
		return
	default:
		alert.EmitErr(ctx, err, "Cannot compare account password.",
			"account_id", account.AccountID)
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	if !account.HasPermission("login") {
		web.WriteJSONErr(w, http.StatusForbidden, "Account cannot login.")
		return
	}

	switch totpSecret, err := session.AccountTOTPSecret(ctx, account.AccountID); {
	case err == nil:
		if input.Code == "" {
			errs.AddRequired("code")
			web.WriteJSON(w, http.StatusUnauthorized, errs)
			return
		}
		switch err := totp.Validate(ctx, h.cache, input.Code, totpSecret); {
		case err == nil:
			// All good.
		case errors.Is(err, totp.ErrInvalid):
			web.WriteJSONErr(w, http.StatusBadRequest, "Invalid Two-Factor verification code.")
			return
		case errors.Is(err, totp.ErrUsed):
			web.WriteJSONErr(w, http.StatusBadRequest, "Two-Factor code has been used. Please wait and use the next code generated.")
			return
		default:
			alert.EmitErr(ctx, err, "Cannot verify TOTP code.")
			web.WriteJSONStdErr(w, http.StatusInternalServerError)
			return
		}
	case errors.Is(err, ErrNotFound):
		if h.conf.RequireTwoFactorAuth {
			web.WriteJSONErr(w, http.StatusUnauthorized, "Two-Factor is required but not enabled for this account.")
			return
		}
	default:
		alert.EmitErr(ctx, err, "Cannot get account TOTP secret.",
			"account_id", account.AccountID)
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	authSessionID, err := session.CreateSession(ctx, account.AccountID, h.conf.SessionMaxAge)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create authentication session.",
			"accountID", account.AccountID)
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.",
			"account_id", account.AccountID)
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	web.WriteJSON(w, http.StatusCreated, responseAccountSession{
		SessionID:   authSessionID,
		AccountID:   account.AccountID,
		Permissions: account.Permissions,

		// This is a good enough estimation.
		ExpiresAt: currentTime().Add(h.conf.SessionMaxAge),
	})
}

type apiTwoFactorStatus struct {
	store Store
	conf  APIConfiguration
}

func (h apiTwoFactorStatus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	account, ok := CurrentAccount(ctx)
	if !ok {
		web.WriteJSONErr(w, http.StatusUnauthorized, "Missing session key.")
		return
	}

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	defer session.Rollback()

	type response struct {
		Enabled bool `json:"enabled"`
	}
	switch _, err := session.AccountTOTPSecret(ctx, account.AccountID); {
	case err == nil:
		web.WriteJSON(w, http.StatusOK, response{Enabled: true})
	case errors.Is(err, ErrNotFound):
		web.WriteJSON(w, http.StatusOK, response{Enabled: false})
	default:
		alert.EmitErr(ctx, err, "Cannot get account TOTP secret.",
			"account_id", account.AccountID)
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
}

type apiTwoFactorEnable struct {
	store Store
	conf  APIConfiguration
	cache cache.Store
}

func (h apiTwoFactorEnable) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		// Base32 encoded TOTP secret.
		Secret string `json:"secret"`

		// In order to make sure that the user has "installed" the
		// secret correctly, requrie to provide a code generated with
		// that secret. Not bullet proof, only makes it harder to make
		// a terrible mistake.
		Code string `json:"code"`

		// Those are optional fields needed only when session ID is not
		// provided.
		// If two factor authentication is required and not enabled for
		// given account, user can only authenticate with
		// email/password because no session can be created.
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		web.WriteJSONErr(w, http.StatusBadRequest, "Invalid input JSON.")
		return
	}

	ctx := r.Context()
	var errs validation.Errors

	account, ok := CurrentAccount(ctx)
	if !ok {
		account = nil
		input.Email = normalizeEmail(input.Email)
		if len(input.Email) == 0 {
			errs.AddRequired("email")
		}
		if len(input.Password) == 0 {
			errs.AddRequired("password")
		}
	}

	input.Code = strings.TrimSpace(input.Code)
	if input.Code == "" {
		errs.AddRequired("code")
	} else if !regexp.MustCompile(`\d{6}`).MatchString(input.Code) {
		errs.Add("code", "Must be 6 digits.")
	}

	if input.Secret == "" {
		errs.AddRequired("secret")
		web.WriteJSON(w, http.StatusBadRequest, errs)
		return
	}
	totpSecret, err := base32.StdEncoding.DecodeString(input.Secret)
	if err != nil {
		errs.Add("secret", "Must be a base32 encoded value.")
		web.WriteJSON(w, http.StatusBadRequest, errs)
		return
	}
	const (
		minLen = 16
		maxLen = 64
	)
	if n := len(totpSecret); n < minLen || n > maxLen {
		errs.Add("secret", "Must be between %d and %d bytes long.", minLen, maxLen)
	}

	if !errs.Empty() {
		web.WriteJSON(w, http.StatusBadRequest, errs)
		return
	}

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	defer session.Rollback()

	// If account is not set, client is not authenticating with session ID
	// but by directly providing email/password combination.
	// This can be the case if the two-factor authentication but not active
	// for this account.
	if account == nil {
		account, err = session.AccountByEmail(ctx, input.Email)
		switch {
		case err == nil:
			// All good.
		case errors.Is(err, ErrNotFound):
			web.WriteJSONErr(w, http.StatusUnauthorized, "Invalid login and/or password.")
			return
		default:
			alert.EmitErr(ctx, err, "Cannot get account by email.")
			web.WriteJSONStdErr(w, http.StatusInternalServerError)
			return
		}

		switch err := session.IsAccountPassword(ctx, account.AccountID, input.Password); {
		case err == nil:
			// All good.
		case errors.Is(err, ErrPassword):
			web.WriteJSONErr(w, http.StatusUnauthorized, "Invalid login and/or password.")
			return
		default:
			alert.EmitErr(ctx, err, "Cannot compare account password.",
				"account_id", account.AccountID)
			web.WriteJSONStdErr(w, http.StatusInternalServerError)
			return
		}
	}

	switch err := totp.Validate(ctx, h.cache, input.Code, totpSecret); {
	case err == nil:
		// All good.
	case errors.Is(err, totp.ErrInvalid):
		web.WriteJSONErr(w, http.StatusBadRequest, "Invalid verification code.")
		return
	case errors.Is(err, totp.ErrUsed):
		web.WriteJSONErr(w, http.StatusBadRequest, "Code has been used. Please wait and use the next code generated.")
		return
	default:
		alert.EmitErr(ctx, err, "Cannot verify TOTP code.")
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	switch _, err := session.AccountTOTPSecret(ctx, account.AccountID); {
	case err == nil:
		web.WriteJSONErr(w, http.StatusConflict, "Two-factor enabled.")
		return
	case errors.Is(err, ErrNotFound):
		// All good.
	default:
		alert.EmitErr(ctx, err, "Cannot get account TOTP secret.",
			"account_id", account.AccountID)
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	if err := session.UpdateAccountTOTPSecret(ctx, account.AccountID, totpSecret); err != nil {
		alert.EmitErr(ctx, err, "Cannot set account TOTP secret.",
			"account_id", account.AccountID)
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}

	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.",
			"account_id", account.AccountID)
		web.WriteJSONStdErr(w, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// formatCompleteURL returns URL that includes given token. If templateURL
// contains {token}, use it to inject the token value. Otherwise, as a fallback
// include the token as a GET parameter.
func formatCompleteURL(templateURL, token string) (string, error) {
	completeURL := strings.ReplaceAll(templateURL, "{token}", token)
	if completeURL != templateURL {
		return completeURL, nil
	}

	// templateURL might contain GET parameters.
	u, err := url.Parse(templateURL)
	if err != nil {
		return "", fmt.Errorf("invalid template URL: %w", err)
	}
	params := u.Query()
	params.Set("token", token)
	u.RawQuery = params.Encode()
	return u.String(), nil
}
