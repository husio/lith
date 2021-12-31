package lith

import (
	"context"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/husio/lith/pkg/alert"
	"github.com/husio/lith/pkg/cache"
	"github.com/husio/lith/pkg/secret"
	"github.com/husio/lith/pkg/taskqueue"
	"github.com/husio/lith/pkg/totp"
	"github.com/husio/lith/pkg/translation"
	"github.com/husio/lith/pkg/validation"
	"github.com/husio/lith/pkg/web"
	qrcode "github.com/skip2/go-qrcode"
)

func PublicHandler(
	conf PublicUIConfiguration,
	store Store,
	cache cache.Store,
	safe secret.Safe,
	secret []byte,
	queue taskqueue.Scheduler,
) http.Handler {
	public := web.NewRouter()
	public.MethodNotAllowed = publicDefaultHandler{code: http.StatusMethodNotAllowed, conf: conf}
	public.NotFound = publicDefaultHandler{code: http.StatusNotFound, conf: conf}

	p := conf.PathPrefix
	public.Add(`GET,POST `+p+`login/`, publicLogin{store: store, conf: conf})
	public.Add(`GET,POST `+p+`login/verify/`, publicLoginVerify{store: store, cache: cache, conf: conf})
	public.Add(`GET      `+p+`logout/`, publicLogout{store: store, conf: conf})
	public.Add(`GET,POST `+p+`twofactor/enable/`, publicTwoFactorAuthEnable{store: store, cache: cache, conf: conf, safe: safe})

	if conf.AllowRegisterAccount {
		public.Add(`GET,POST `+p+`register/`, publicRegister{store: store, queue: queue, conf: conf})
		public.Add(`GET,POST `+p+`register/{token}/`, publicRegisterComplete{store: store, conf: conf})
	}

	if conf.AllowPasswordReset {
		public.Add(`GET,POST `+p+`password-reset/`, publicPasswordReset{store: store, conf: conf, queue: queue})
		public.Add(`GET,POST `+p+`password-reset/{token}/`, publicPasswordResetComplete{store: store, conf: conf})
	}

	public.Use(
		web.RequestIDMiddleware(),
		web.RecoverMiddleware(),
		web.TrailingSlashMiddleware(true),
		translation.LanguageMiddleware,
		AuthMiddleware(store, SessionFromCookie),
		csrf.Protect(secret,
			csrf.CookieName("csrf"),
			csrf.FieldName("csrf"),
			csrf.ErrorHandler(publicCSRFErrorHandler{conf: conf}),
		),
	)

	rt := http.NewServeMux()
	// TODO use public statics
	rt.Handle(p+`statics/`, http.StripPrefix(p+"statics", http.FileServer(http.FS(adminStaticsFS()))))
	rt.Handle(`/`, public)
	return rt
}

type publicCSRFErrorHandler struct {
	conf PublicUIConfiguration
}

func (h publicCSRFErrorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	renderPublicErr(w, h.conf, http.StatusForbidden, csrf.FailureReason(r).Error())
}

type publicDefaultHandler struct {
	code int
	conf PublicUIConfiguration
}

func (h publicDefaultHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	renderPublicErr(w, h.conf, h.code, "")
}

type publicPasswordReset struct {
	store Store
	queue taskqueue.Scheduler
	conf  PublicUIConfiguration
}

func (h publicPasswordReset) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	trans := transFor(ctx)

	templateContext := struct {
		publicTemplateCore
		Next      string
		CSRFField template.HTML
	}{
		publicTemplateCore: newPublicTemplateCore(h.conf, trans.T("Password Reset")),
		Next:               r.URL.Query().Get("next"),
		CSRFField:          csrf.TemplateField(r),
	}

	if r.Method == "GET" {
		tmpl.Render(w, http.StatusOK, "public_password_reset.html", templateContext)
		return
	}

	if err := r.ParseForm(); err != nil {
		renderPublicErr(w, h.conf, http.StatusBadRequest, trans.T("Cannot parse form."))
		return
	}

	templateContext.Next = r.Form.Get("next")

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	email := normalizeEmail(r.Form.Get("email"))
	account, err := session.AccountByEmail(ctx, email)
	switch {
	case err == nil:
		// All good.
	case errors.Is(err, ErrNotFound):
		// Account not found, but because we don't want to give up what
		// accounts are registered, a successful message is returned.
		tmpl.Render(w, http.StatusOK, "public_password_reset_wait_for_email.html", templateContext)
		return
	default:
		alert.EmitErr(ctx, err, "Cannot get account by email.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	token, err := session.CreateEphemeralToken(ctx, "public-reset-password", 6*time.Hour, struct {
		AccountID string
		Email     string
		Next      string
	}{
		AccountID: account.AccountID,
		Email:     email,
		Next:      templateContext.Next,
	})
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create ephemeral token.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	taskID, err := h.queue.Schedule(ctx, SendResetPassword{
		FromEmail:    h.conf.FromEmail,
		AccountID:    account.AccountID,
		Token:        token,
		AccountEmail: account.Email,
		CompleteURL:  resetPasswordCompleteURL(h.conf.DomainSSL, h.conf.Domain, h.conf.PathPrefix, token),
		Language:     translation.Language(ctx),
	}, taskqueue.Delay(3*time.Second)) // Delay so that it can be cancelled if needed.
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot schedule SendResetPassword task")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		_ = h.queue.Cancel(ctx, taskID)
		return
	}

	tmpl.Render(w, http.StatusOK, "public_password_reset_wait_for_email.html", templateContext)
}

// resetPasswordCompleteURL returns a full URL for registration verification. This URL
// is intended to be sent via external channels, i.e. email.
func resetPasswordCompleteURL(https bool, domain, pathPrefix, token string) string {
	protocol := "https"
	if !https {
		protocol = "http"
	}
	return protocol + "://" + domain + pathPrefix + "password-reset/" + token + "/"
}

type publicPasswordResetComplete struct {
	store Store
	conf  PublicUIConfiguration
}

func (h publicPasswordResetComplete) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// This is not an idempotent endpoint, because request comes from
	// clicking on an email URL.
	ctx := r.Context()
	trans := transFor(ctx)

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	var resetPasswordContext struct {
		AccountID string
		Email     string
		Next      string
	}
	token := web.PathArg(r, "token")
	switch err := session.EphemeralToken(ctx, "public-reset-password", token, &resetPasswordContext); {
	case err == nil:
		// All good.
	case errors.Is(err, ErrNotFound):
		renderPublicErr(w, h.conf, http.StatusBadRequest, trans.T("Invalid token."))
		return
	default:
		alert.EmitErr(ctx, err, "Cannot get ephemeral token.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	account, err := session.AccountByID(ctx, resetPasswordContext.AccountID)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot get account referenced in ephemeral token.",
			"token", token,
			"account_id", resetPasswordContext.AccountID)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if account.Email != resetPasswordContext.Email {
		renderPublicErr(w, h.conf, http.StatusBadRequest, trans.T("Account email was changed."))
		return
	}

	templateContext := struct {
		publicTemplateCore
		Errors    validation.Errors
		Next      string
		CSRFField template.HTML
	}{
		publicTemplateCore: newPublicTemplateCore(h.conf, trans.T("Register Verify")),
		Next:               resetPasswordContext.Next,
		CSRFField:          csrf.TemplateField(r),
	}

	if r.Method == "GET" {
		tmpl.Render(w, http.StatusOK, "public_password_reset_complete.html", templateContext)
		return
	}

	if err := r.ParseForm(); err != nil {
		renderPublicErr(w, h.conf, http.StatusBadRequest, trans.T("Cannot parse form."))
		return
	}

	password := r.Form.Get("password")
	passRepeat := r.Form.Get("password_repeat")

	if password != passRepeat {
		templateContext.Errors.Add("password", trans.T("Entered passwords are not the same."))
	}
	if n := len(password); n == 0 {
		templateContext.Errors.AddRequired("password")
	} else if n < int(h.conf.MinPasswordLength) {
		templateContext.Errors.Add("password",
			trans.Tn(
				"Too short. Must be at least %d character long.",
				"Too short. Must be at least %d characters long.",
				int(h.conf.MinPasswordLength)))
	}

	if !templateContext.Errors.Empty() {
		tmpl.Render(w, http.StatusOK, "public_password_reset_complete.html", templateContext)
		return
	}

	if err := session.UpdateAccountPassword(ctx, account.AccountID, password); err != nil {
		alert.EmitErr(ctx, err, "Cannot update account password.",
			"account_id", account.AccountID)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	if err := session.DeleteEphemeralToken(ctx, token); err != nil {
		alert.EmitErr(ctx, err, "Cannot delete existing ephemeral token.",
			"token", token)
	}
	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	tmpl.Render(w, http.StatusOK, "public_password_reset_success.html", templateContext)

}

type publicLogin struct {
	store Store
	conf  PublicUIConfiguration
}

func (h publicLogin) deleteAuthSession(ctx context.Context) {
	sid, ok := CurrentSessionID(ctx)
	if !ok {
		return
	}
	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		return
	}
	defer session.Rollback()
	if err := session.DeleteSession(ctx, sid); err != nil {
		alert.EmitErr(ctx, err, "Cannot delete auth session.")
		return
	}
	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.")
		return
	}
}

func (h publicLogin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	trans := transFor(ctx)

	// If the user is logged in, logout first in order to avoid confusion.
	if _, ok := CurrentSessionID(ctx); ok {
		deletePublicSessionCookie(w)
		h.deleteAuthSession(ctx)
	}

	templateContext := struct {
		publicTemplateCore
		Email     string
		Next      string
		ErrorMsg  string
		CSRFField template.HTML
	}{
		publicTemplateCore: newPublicTemplateCore(h.conf, trans.T("Login")),
		CSRFField:          csrf.TemplateField(r),
	}

	if next := r.URL.Query().Get("next"); next != "" {
		templateContext.Next = next
	} else if next := r.Header.Get("referrer"); next != "" {
		// Use referrer as the last resort, so that logging in does not
		// redirect back to login page.
		templateContext.Next = next
	} else {
		templateContext.Next = "/"
	}

	if r.Method == "GET" {
		tmpl.Render(w, http.StatusOK, "public_login.html", templateContext)
		return
	}

	if err := r.ParseForm(); err != nil {
		renderPublicErr(w, h.conf, http.StatusBadRequest, trans.T("Cannot parse form."))
		return
	}

	email := normalizeEmail(r.Form.Get("email"))
	password := r.Form.Get("password")

	templateContext.Email = email
	templateContext.Next = r.FormValue("next")

	if len(email) == 0 || len(password) == 0 {
		templateContext.ErrorMsg = trans.T("Email and password cannot be empty.")
		tmpl.Render(w, http.StatusBadRequest, "public_login.html", templateContext)
		return
	}

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	account, err := session.AccountByEmail(ctx, email)
	switch {
	case err == nil:
		// All good.
	case errors.Is(err, ErrNotFound):
		templateContext.ErrorMsg = trans.T("Invalid login and/or password.")
		tmpl.Render(w, http.StatusBadRequest, "public_login.html", templateContext)
		return
	default:
		alert.EmitErr(ctx, err, "Cannot get account by email.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	switch err := session.IsAccountPassword(ctx, account.AccountID, password); {
	case err == nil:
		// All good.
	case errors.Is(err, ErrPassword):
		templateContext.ErrorMsg = trans.T("Invalid login and/or password.")
		tmpl.Render(w, http.StatusBadRequest, "public_login.html", templateContext)
		return
	default:
		alert.EmitErr(ctx, err, "Cannot compare account password.",
			"account_id", account.AccountID)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if !account.HasPermission("login") {
		templateContext.ErrorMsg = trans.T("Account is not allowed to login.")
		tmpl.Render(w, http.StatusForbidden, "public_login.html", templateContext)
		return
	}

	switch _, err := session.AccountTOTPSecret(ctx, account.AccountID); {
	case err == nil:
		// Two factor authentication is enabled.
		timeout := 5 * time.Minute
		token, err := session.CreateEphemeralToken(ctx, "public-verify-2fa", timeout, struct {
			AccountID string
			Next      string
		}{
			AccountID: account.AccountID,
			Next:      templateContext.Next,
		})
		if err != nil {
			alert.EmitErr(ctx, err, "Cannot create ephemeral token.",
				"account_id", account.AccountID)
			renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
			return
		}
		if err := session.Commit(); err != nil {
			alert.EmitErr(ctx, err, "Cannot commit session.",
				"account_id", account.AccountID)
			renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "2fa",
			Path:     h.conf.PathPrefix + "login/verify/",
			Value:    token,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(timeout / time.Second),
			HttpOnly: true,
		})
		http.Redirect(w, r, h.conf.PathPrefix+"login/verify/", http.StatusSeeOther)
		return

	case errors.Is(err, ErrNotFound):
		// Two factor authentication is not configured for this account.
		if h.conf.RequireTwoFactorAuth {
			// Grant a limited session token and redirect to two
			// factor configuration, so that user can enable it and
			// create a normal session.

			timeout := 10 * time.Minute
			token, err := session.CreateEphemeralToken(ctx, "public-enable-2fa", timeout, struct {
				AccountID string
				Next      string
			}{
				AccountID: account.AccountID,
				Next:      templateContext.Next,
			})
			if err != nil {
				alert.EmitErr(ctx, err, "Cannot create ephemeral token.",
					"account_id", account.AccountID)
				renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
				return
			}
			if err := session.Commit(); err != nil {
				alert.EmitErr(ctx, err, "Cannot commit session.",
					"account_id", account.AccountID)
				renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     "2fa",
				Path:     h.conf.PathPrefix + "twofactor/enable/",
				Value:    token,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   int(timeout / time.Second),
				HttpOnly: true,
			})
			http.Redirect(w, r, h.conf.PathPrefix+"twofactor/enable/", http.StatusSeeOther)
			return
		}
	default:
		alert.EmitErr(ctx, err, "Cannot get account TOTP secret.",
			"account_id", account.AccountID)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	authSessionID, err := session.CreateSession(ctx, account.AccountID, h.conf.SessionMaxAge)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create authentication session.",
			"accountID", account.AccountID)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.",
			"account_id", account.AccountID)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	setPublicSessionCookie(w, h.conf, authSessionID)

	if next := r.Form.Get("next"); next != "" {
		http.Redirect(w, r, next, http.StatusSeeOther)
	} else {
		http.Redirect(w, r, h.conf.PathPrefix, http.StatusSeeOther)
	}
}

type publicLoginVerify struct {
	store Store
	cache cache.Store
	conf  PublicUIConfiguration
}

func (h publicLoginVerify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	trans := transFor(ctx)

	cookie, err := r.Cookie("2fa")
	if err != nil {
		http.Redirect(w, r, h.conf.PathPrefix+"login/", http.StatusSeeOther)
		return
	}

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	var verify2faContext struct {
		AccountID string
		Next      string
	}
	switch err := session.EphemeralToken(ctx, "public-verify-2fa", cookie.Value, &verify2faContext); {
	case err == nil:
		// All good.
	case errors.Is(err, ErrNotFound):
		http.Redirect(w, r, h.conf.PathPrefix+"login/", http.StatusSeeOther)
		return
	default:
		alert.EmitErr(ctx, err, "Cannot ephemeral token.",
			"token", cookie.Value)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	templateContext := struct {
		publicTemplateCore
		ErrorMsg  string
		CSRFField template.HTML
	}{
		publicTemplateCore: newPublicTemplateCore(h.conf, trans.T("Login Verify")),
		CSRFField:          csrf.TemplateField(r),
	}

	account, err := session.AccountByID(ctx, verify2faContext.AccountID)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot get account referenced by ephemeral token.",
			"account_id", verify2faContext.AccountID,
			"token", cookie.Value)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if r.Method == "GET" {
		tmpl.Render(w, http.StatusOK, "public_login_verify.html", templateContext)
		return
	}

	if err := r.ParseForm(); err != nil {
		renderPublicErr(w, h.conf, http.StatusBadRequest, trans.T("Cannot parse form."))
		return
	}

	totpSecret, err := session.AccountTOTPSecret(ctx, account.AccountID)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot get account TOPT secret.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	switch err := totp.Validate(ctx, h.cache, r.Form.Get("code"), totpSecret); {
	case err == nil:
		// All good.
	case errors.Is(err, totp.ErrInvalid):
		templateContext.ErrorMsg = trans.T("Invalid verification code.")
		tmpl.Render(w, http.StatusBadRequest, "public_login_verify.html", templateContext)
		return
	case errors.Is(err, totp.ErrUsed):
		templateContext.ErrorMsg = trans.T("Code has been used. Please wait and use the next code generated.")
		tmpl.Render(w, http.StatusBadRequest, "public_login_verify.html", templateContext)
		return
	default:
		alert.EmitErr(ctx, err, "Cannot verify TOTP code.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	if err := session.DeleteEphemeralToken(ctx, cookie.Value); err != nil {
		alert.EmitErr(ctx, err, "Cannot delete ephemeral token",
			"token", cookie.Value)

	}

	authSessionID, err := session.CreateSession(ctx, account.AccountID, h.conf.SessionMaxAge)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create authentication session.",
			"accountID", account.AccountID)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	setPublicSessionCookie(w, h.conf, authSessionID)
	if verify2faContext.Next == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, verify2faContext.Next, http.StatusSeeOther)
	}
	return
}

type publicLogout struct {
	store Store
	conf  PublicUIConfiguration
}

func (h publicLogout) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	next := r.URL.Query().Get("next")
	if next == "" {
		next = h.conf.PathPrefix + "login/"
	}

	// Regardless, we can always ensure the cookie is deleted.
	deletePublicSessionCookie(w)

	sid, ok := CurrentSessionID(ctx)
	if !ok {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()
	if err := session.DeleteSession(ctx, sid); err != nil {
		alert.EmitErr(ctx, err, "Cannot delete auth session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	http.Redirect(w, r, next, http.StatusSeeOther)
}

type publicTwoFactorAuthEnable struct {
	store Store
	cache cache.Store
	safe  secret.Safe
	conf  PublicUIConfiguration
}

func (h publicTwoFactorAuthEnable) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	trans := transFor(ctx)

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	var ephemeralNext string
	account, ok := CurrentAccount(ctx)
	if !ok {
		// This might be a special case when user must first enable two
		// factor authentication before allowed to create a real
		// session.
		cookie, err := r.Cookie("2fa")
		if err != nil {
			here := url.QueryEscape(r.URL.String())
			http.Redirect(w, r, h.conf.PathPrefix+"login/?next="+here, http.StatusTemporaryRedirect)
			return
		}
		var enable2faContext struct {
			AccountID string
			Next      string
		}
		switch err = session.EphemeralToken(ctx, "public-enable-2fa", cookie.Value, &enable2faContext); {
		case err == nil:
			// All good.
		case errors.Is(err, ErrNotFound):
			here := url.QueryEscape(r.URL.String())
			http.Redirect(w, r, h.conf.PathPrefix+"login/?next="+here, http.StatusTemporaryRedirect)
			return
		default:
			alert.EmitErr(ctx, err, "Cannot get ephemeral token.")
			renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
			return
		}

		ephemeralNext = enable2faContext.Next
		account, err = session.AccountByID(ctx, enable2faContext.AccountID)
		if err != nil {
			here := url.QueryEscape(r.URL.String())
			http.Redirect(w, r, h.conf.PathPrefix+"login/?next="+here, http.StatusTemporaryRedirect)
			return
		}
	}

	switch _, err := session.AccountTOTPSecret(ctx, account.AccountID); {
	case err == nil:
		// Two factor authentication is already enabled.
		next := ephemeralNext
		if next == "" {
			next = r.URL.Query().Get("next")
		}
		if next == "" {
			next = h.conf.PathPrefix + "login/"
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	case errors.Is(err, ErrNotFound):
		// All good.
	default:
		alert.EmitErr(ctx, err, "Cannot get account TOTP secret.",
			"account_id", account.AccountID)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	templateContext := struct {
		publicTemplateCore
		ErrorMsg             string
		CurrentAccount       *Account
		EphemeralSecretToken string
		QRCodeBase64         string
		CSRFField            template.HTML
	}{
		publicTemplateCore: newPublicTemplateCore(h.conf, trans.T("Two Factor")),
		CurrentAccount:     account,
		CSRFField:          csrf.TemplateField(r),
	}

	var totpEnableContext struct {
		Secret []byte
		Next   string
	}
	// Until confirmed by user by providing a correct code, TOTP is stored
	// in cache. Only after verificaion, TOTP secret is stored in the
	// database.
	totpCacheKey := "totp:" + account.AccountID + ":secret"
	switch err := h.cache.Get(ctx, totpCacheKey, &totpEnableContext); {
	case err == nil:
		// All good.
	case errors.Is(err, cache.ErrMiss):
		cyphertext, err := h.safe.Encrypt(secret.Generate(32))
		if err != nil {
			alert.EmitErr(ctx, err, "Cannot encrypt secret.",
				"account_id", account.AccountID)
			renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
			return
		}

		totpEnableContext.Secret = cyphertext
		totpEnableContext.Next = ephemeralNext
		if err := h.cache.SetNx(ctx, totpCacheKey, totpEnableContext, 10*time.Minute); err != nil {
			alert.EmitErr(ctx, err, "Cannot store TOTP enable context.",
				"account_id", account.AccountID)
			renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
			return
		}
	default:
		alert.EmitErr(ctx, err, "Cannot get from cache TOTP enable context.",
			"account_id", account.AccountID)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	totpSecret, err := h.safe.Decrypt(totpEnableContext.Secret)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot decrypt TOTP secret.",
			"account_id", account.AccountID)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			renderPublicErr(w, h.conf, http.StatusBadRequest, trans.T("Cannot parse form."))
			return
		}

		switch err := totp.Validate(ctx, h.cache, r.Form.Get("code"), totpSecret); {
		case err == nil:
			// Success.
			if err := session.UpdateAccountTOTPSecret(ctx, account.AccountID, totpSecret); err != nil {
				alert.EmitErr(ctx, err, "Cannot set account TOTP secret.",
					"account_id", account.AccountID)
				renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
				return
			}
			_ = h.cache.Del(ctx, totpCacheKey)

			// If user is forced to enable 2fa in order to login,
			// create a session now. Password was already provided
			// and user proved identity..
			if _, ok := CurrentSessionID(ctx); !ok {
				authSessionID, err := session.CreateSession(ctx, account.AccountID, h.conf.SessionMaxAge)
				if err != nil {
					alert.EmitErr(ctx, err, "Cannot create authentication session.",
						"accountID", account.AccountID)
					renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
					return
				}
				setPublicSessionCookie(w, h.conf, authSessionID)
			}

			if err := session.Commit(); err != nil {
				alert.EmitErr(ctx, err, "Cannot commit session.")
				renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
				return
			}
			if totpEnableContext.Next == "" {
				http.Redirect(w, r, h.conf.PathPrefix+"login/", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, totpEnableContext.Next, http.StatusSeeOther)
			}
			return
		case errors.Is(err, totp.ErrInvalid):
			templateContext.ErrorMsg = trans.T("Invalid code.")
		case errors.Is(err, totp.ErrUsed):
			templateContext.ErrorMsg = trans.T("Code already used. Please wait for the next one and try again.")
		default:
			alert.EmitErr(ctx, err, "Cannot validate TOTP token.",
				"account_id", account.AccountID)
			renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
			return
		}
	}

	info := totp.URI(h.conf.Domain, account.Email, totpSecret)
	qr, err := qrcode.New(info, qrcode.Highest)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create TOTP QR-Code.",
			"account_id", account.AccountID)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, trans.T("Cannot generate QR Code."))
		return

	}
	png, err := qr.PNG(400)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot generate TOTP QR-Code PNG file.",
			"account_id", account.AccountID)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, trans.T("Cannot generate QR Code."))
		return
	}
	templateContext.QRCodeBase64 = base64.StdEncoding.EncodeToString(png)

	code := http.StatusOK
	if len(templateContext.ErrorMsg) != 0 {
		code = http.StatusBadRequest
	}
	tmpl.Render(w, code, "public_twofactor_enable.html", templateContext)
}

type publicRegister struct {
	store Store
	queue taskqueue.Scheduler
	conf  PublicUIConfiguration
}

func (h publicRegister) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	trans := transFor(ctx)

	templateContext := struct {
		publicTemplateCore
		Email     string
		Next      string
		Errors    validation.Errors
		CSRFField template.HTML
	}{
		publicTemplateCore: newPublicTemplateCore(h.conf, trans.T("Register")),
		Next:               r.URL.Query().Get("next"),
		CSRFField:          csrf.TemplateField(r),
	}

	if r.Method == "GET" {
		tmpl.Render(w, http.StatusOK, "public_register.html", templateContext)
		return
	}

	if err := r.ParseForm(); err != nil {
		renderPublicErr(w, h.conf, http.StatusBadRequest, trans.T("Cannot parse form."))
		return
	}

	if next := r.FormValue("next"); next != "" {
		templateContext.Next = next
	}

	var errs validation.Errors
	email := normalizeEmail(r.Form.Get("email"))
	templateContext.Email = email
	if ok, _ := regexp.MatchString(h.conf.AllowRegisterEmail, email); !ok {
		errs.Add("email", trans.T("Email address not allowed to register."))
	}
	if !errs.Empty() {
		templateContext.Errors = errs
		tmpl.Render(w, http.StatusBadRequest, "public_register.html", templateContext)
		return
	}

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	// Instead of creating an account create a token that when used can
	// trigger account creation. This way we do not end up with stale
	// account with a fake email.
	token, err := session.CreateEphemeralToken(ctx, "public-register-account", 6*time.Hour, struct {
		Email string
		Next  string
	}{
		Email: email,
		Next:  templateContext.Next,
	})
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create ephemeral token.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	taskID, err := h.queue.Schedule(ctx, SendConfirmRegistration{
		FromEmail:    h.conf.FromEmail,
		AccountEmail: email,
		Token:        token,
		CompleteURL:  registerCompleteURL(h.conf.DomainSSL, h.conf.Domain, h.conf.PathPrefix, token),
		Language:     translation.Language(ctx),
	}, taskqueue.Delay(3*time.Second)) // Delay so that it can be cancelled if needed.
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot schedule SendConfirmRegistration task")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		_ = h.queue.Cancel(ctx, taskID)
		return
	}

	tmpl.Render(w, http.StatusOK, "public_register_wait_for_email.html", templateContext)
}

// registerCompleteURL returns a full URL for registration verification. This URL
// is intended to be sent via external channels, i.e. email.
func registerCompleteURL(https bool, domain, pathPrefix, token string) string {
	protocol := "https"
	if !https {
		protocol = "http"
	}
	return protocol + "://" + domain + pathPrefix + "register/" + token + "/"
}

type publicRegisterComplete struct {
	store Store
	conf  PublicUIConfiguration
}

func (h publicRegisterComplete) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	trans := transFor(ctx)

	templateContext := struct {
		publicTemplateCore
		Next      string
		Errors    validation.Errors
		CSRFField template.HTML
	}{
		publicTemplateCore: newPublicTemplateCore(h.conf, trans.T("Register Verify")),
		CSRFField:          csrf.TemplateField(r),
	}

	if r.Method == "GET" {
		tmpl.Render(w, http.StatusOK, "public_register_complete.html", templateContext)
		return
	}

	if err := r.ParseForm(); err != nil {
		renderPublicErr(w, h.conf, http.StatusBadRequest, trans.T("Cannot parse form."))
		return
	}

	var errs validation.Errors
	password := r.Form.Get("password")
	passwordRep := r.Form.Get("password_repeat")
	if password != passwordRep {
		errs.Add("password", trans.T("Entered passwords are not the same."))
	} else if min := h.conf.MinPasswordLength; len(password) < int(min) {
		errs.Add("password", trans.Tn(
			"Password is too short. At least %d character is required.",
			"Password is too short. At least %d characters are required.",
			int(min)))
	}
	if !errs.Empty() {
		templateContext.Errors = errs
		tmpl.Render(w, http.StatusBadRequest, "public_register_complete.html", templateContext)
		return
	}

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	var registerContext struct {
		Email string
		Next  string
	}
	token := web.PathArg(r, "token")
	switch err := session.EphemeralToken(ctx, "public-register-account", token, &registerContext); {
	case err == nil:
		// All good.
	case errors.Is(err, ErrNotFound):
		renderPublicErr(w, h.conf, http.StatusBadRequest, trans.T("Invalid token."))
		return
	default:
		alert.EmitErr(ctx, err, "Cannot get ephemeral token.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if err := session.DeleteEphemeralToken(ctx, token); err != nil {
		alert.EmitErr(ctx, err, "Cannot delete existing ephemeral token.",
			"token", token)
	}

	account, err := session.CreateAccount(ctx, registerContext.Email, password)
	switch {
	case err == nil:
		// All good.
	case errors.Is(err, ErrConflict):
		renderPublicErr(w, h.conf, http.StatusConflict, trans.T("Email already in use."))
		return
	default:
		alert.EmitErr(ctx, err, "Cannot create account.",
			"token", token)
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if err := session.UpdateAccountPermissionGroups(ctx, account.AccountID, h.conf.RegisteredAccountPermissionGroups); err != nil {
		alert.EmitErr(ctx, err, "Cannot assign permission group.",
			"account_id", account.AccountID)
	}

	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.")
		renderPublicErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	templateContext.Next = registerContext.Next
	tmpl.Render(w, http.StatusOK, "public_register_success.html", templateContext)
}

// renderPublicErr is a shortcut for rendering public error pages.
func renderPublicErr(
	w http.ResponseWriter,
	conf PublicUIConfiguration,
	code int,
	description string,
) {
	tmpl.Render(w, code, "public_error.html", struct {
		publicTemplateCore
		Title       string
		Code        int
		Description string
	}{
		publicTemplateCore: newPublicTemplateCore(conf, http.StatusText(code)),
		Title:              http.StatusText(code),
		Code:               code,
		Description:        description,
	})
}

// newPublicTemplateCore returns properly initialized core template context.
func newPublicTemplateCore(conf PublicUIConfiguration, pageTitle string) publicTemplateCore {
	return publicTemplateCore{
		PageTitle: pageTitle,
		conf:      conf,
	}
}

// publicTemplateCore contains the bare minimum of a template context that each
// public template requires. To ensure that each template provides that
// minimum, this structure was extracted. Embed it in each handler's template
// context.
type publicTemplateCore struct {
	PageTitle string
	// Keep configuration hidden, just in case, so that it is not possible
	// to leak it out via templates. Any value if needed, expose via method.
	conf PublicUIConfiguration
}

// AbsolutePath returns an absolute version of given path. Depending on
// configuration, all paths might be prefixed. This function allows to build an
// absolute path that will work regardless of path prefix configured.
//
// Alternative approach could be to use relative paths only. This is not always
// possible when rendering HTML documents. For example static files path is
// easier to provide as an absolute one.
func (c publicTemplateCore) AbsolutePath(path string) string {
	for strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	return c.conf.PathPrefix + path
}

// AllowRegisterAccount returns configuration value.
func (c publicTemplateCore) AllowRegisterAccount() bool {
	return c.conf.AllowRegisterAccount
}

// AllowPasswordReset returns configuration value.
func (c publicTemplateCore) AllowPasswordReset() bool {
	return c.conf.AllowPasswordReset
}

// CSS returns a list of absolute URLs for all static files that should be
// included.
func (c publicTemplateCore) CSS() []string {
	urls := make([]string, 0, 6)
	if !c.conf.DisableDefaultCSS {
		urls = append(urls,
			c.conf.PathPrefix+"statics/normalize.css",
			c.conf.PathPrefix+"statics/custom.css",
		)
	}
	urls = append(urls, c.conf.IncludeExtraCSS...)
	return urls
}

func setPublicSessionCookie(w http.ResponseWriter, conf PublicUIConfiguration, authSessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "s",
		Path:     "/",
		Value:    authSessionID,
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
		MaxAge:   int(conf.SessionMaxAge / time.Second),
	})
}

func deletePublicSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   "s",
		Path:   "/",
		Value:  "",
		MaxAge: 0,
	})
}
