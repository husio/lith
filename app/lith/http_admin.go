package lith

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/husio/lith/pkg/alert"
	"github.com/husio/lith/pkg/cache"
	"github.com/husio/lith/pkg/eventbus"
	"github.com/husio/lith/pkg/secret"
	"github.com/husio/lith/pkg/totp"
	"github.com/husio/lith/pkg/translation"
	"github.com/husio/lith/pkg/validation"
	"github.com/husio/lith/pkg/web"

	"github.com/gorilla/csrf"
	qrcode "github.com/skip2/go-qrcode"
)

// AdminHandler returns an HTTP handler that provides Web UI for system
// administration. Only system administrator is able to access any of nested
// endpoints.
func AdminHandler(
	conf AdminPanelConfiguration,
	store Store,
	cache cache.Store,
	safe secret.Safe,
	secret []byte,
	events eventbus.Sink,
) http.Handler {
	admin := web.NewRouter()
	admin.MethodNotAllowed = adminDefaultHandler{code: http.StatusMethodNotAllowed}
	admin.NotFound = adminDefaultHandler{code: http.StatusNotFound}

	flash := flashmsg{safe: safe, pathPrefix: conf.PathPrefix}

	p := conf.PathPrefix
	admin.Add(`GET      `+p, adminIndex{store: store, conf: conf})
	admin.Add(`GET,POST `+p+`login/ `, adminLogin{store: store, conf: conf})
	admin.Add(`GET,POST `+p+`login/verify/`, adminLoginVerify{store: store, cache: cache, conf: conf})
	admin.Add(`GET      `+p+`logout/ `, adminLogout{store: store, conf: conf})
	admin.Add(`GET,POST `+p+`twofactor/enable/`, adminTwoFactorAuthEnable{store: store, cache: cache, conf: conf, safe: safe})
	admin.Add(`GET      `+p+`accounts/`, adminAccountsList{store: store, conf: conf})
	admin.Add(`GET,POST `+p+`accounts/create/`, adminAccountCreate{store: store, conf: conf, flash: flash, events: events})
	admin.Add(`GET,POST `+p+`accounts/{account-id}/`, adminAccountDetails{store: store, conf: conf, flash: flash})
	admin.Add(`GET      `+p+`permissiongroups/`, adminPermissionGroupsList{store: store, conf: conf, flash: flash})
	admin.Add(`GET,POST `+p+`permissiongroups/create/`, adminPermissionGroupCreate{store: store, conf: conf, flash: flash})
	admin.Add(`GET,POST `+p+`permissiongroups/{permissiongroup-id:\d+}/`, adminPermissionGroupDetails{store: store, conf: conf, flash: flash})
	admin.Add(`GET      `+p+`changelogs/`, adminChangelogsList{store: store, conf: conf})
	admin.Use(
		web.RequestIDMiddleware(),
		web.RecoverMiddleware(),
		web.TrailingSlashMiddleware(true),
		translation.LanguageMiddleware,
		AuthMiddleware(store, SessionFromCookie),
		csrf.Protect(secret,
			csrf.CookieName("csrf"),
			csrf.FieldName("csrf"),
			csrf.ErrorHandler(adminCSRFErrorHandler{conf: conf}),
		),
	)

	rt := http.NewServeMux()
	rt.Handle(p+`statics/`, http.StripPrefix(p+"statics", http.FileServer(http.FS(adminStaticsFS()))))
	rt.Handle(`/`, admin)
	return rt
}

type adminCSRFErrorHandler struct {
	conf AdminPanelConfiguration
}

func (h adminCSRFErrorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	renderAdminErr(w, h.conf, http.StatusForbidden, csrf.FailureReason(r).Error())
}

type adminDefaultHandler struct {
	code int
	conf AdminPanelConfiguration
}

func (h adminDefaultHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	renderAdminErr(w, h.conf, h.code, "")
}

type adminIndex struct {
	store Store
	conf  AdminPanelConfiguration
}

func (h adminIndex) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	account, ok := adminOrRedirect(w, r, h.conf)
	if !ok {
		return
	}
	tmpl.Render(w, http.StatusOK, "admin_index.html", struct {
		adminTemplateCore
		CurrentAccount *Account
	}{
		adminTemplateCore: newAdminTemplateCore(h.conf, "Index"),
		CurrentAccount:    account,
	})
}

type adminLogin struct {
	store Store
	conf  AdminPanelConfiguration
}

func (h adminLogin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	templateContext := struct {
		adminTemplateCore
		Email          string
		Next           string
		CSRFField      template.HTML
		ErrorMsg       string
		CurrentAccount *Account
	}{
		adminTemplateCore: newAdminTemplateCore(h.conf, "Login"),
		CSRFField:         csrf.TemplateField(r),
		Next:              r.URL.Query().Get("next"),
	}

	currentAccount, _ := CurrentAccount(r.Context())
	templateContext.CurrentAccount = currentAccount

	if r.Method == "GET" {
		tmpl.Render(w, http.StatusOK, "admin_login.html", templateContext)
		return
	}

	ctx := r.Context()
	trans := transFor(ctx)

	if err := r.ParseForm(); err != nil {
		renderAdminErr(w, h.conf, http.StatusBadRequest, trans.T("Cannot parse form."))
		return
	}

	email := normalizeEmail(r.Form.Get("email"))
	password := r.Form.Get("password")

	templateContext.Email = email
	templateContext.Next = r.FormValue("next")
	if templateContext.Next == "" {
		templateContext.Next = h.conf.PathPrefix
	}

	if len(email) == 0 || len(password) == 0 {
		templateContext.ErrorMsg = "Login and password cannot be empty."
		tmpl.Render(w, http.StatusBadRequest, "admin_login.html", templateContext)
		return
	}

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	account, err := session.AccountByEmail(ctx, email)
	switch {
	case err == nil:
		// All good.
	case errors.Is(err, ErrNotFound):
		templateContext.ErrorMsg = "Invalid email and/or password."
		tmpl.Render(w, http.StatusBadRequest, "admin_login.html", templateContext)
		return
	default:
		alert.EmitErr(ctx, err, "Cannot get account by email.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	switch err := session.IsAccountPassword(ctx, account.AccountID, password); {
	case err == nil:
		// All good.
	case errors.Is(err, ErrPassword):
		templateContext.ErrorMsg = "Invalid email and/or password."
		tmpl.Render(w, http.StatusBadRequest, "admin_login.html", templateContext)
		return
	default:
		alert.EmitErr(ctx, err, "Cannot compare account password.",
			"account_id", account.AccountID)
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if !account.HasPermission("login") {
		templateContext.ErrorMsg = "Account is not allowed to login."
		tmpl.Render(w, http.StatusForbidden, "admin_login.html", templateContext)
		return
	}
	if !account.HasPermission("lith-admin") {
		templateContext.ErrorMsg = "Account is not allowed to login to admin panel."
		tmpl.Render(w, http.StatusForbidden, "admin_login.html", templateContext)
		return
	}

	switch _, err := session.AccountTOTPSecret(ctx, account.AccountID); {
	case err == nil:
		// Two factor authentication is enabled.
		timeout := 5 * time.Minute
		token, err := session.CreateEphemeralToken(ctx, "verify-admin-2fa", timeout, struct {
			AccountID string
			Next      string
		}{
			AccountID: account.AccountID,
			Next:      templateContext.Next,
		})
		if err != nil {
			alert.EmitErr(ctx, err, "Cannot create ephemeral token.",
				"account_id", account.AccountID)
			renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
			return
		}
		if err := session.Commit(); err != nil {
			alert.EmitErr(ctx, err, "Cannot commit session.",
				"account_id", account.AccountID)
			renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
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
			// factor authentication configuration, so that user
			// can enable it and create a normal session.

			timeout := 10 * time.Minute
			token, err := session.CreateEphemeralToken(ctx, "enable-admin-2fa", timeout, struct {
				AccountID string
				Next      string
			}{
				AccountID: account.AccountID,
				Next:      templateContext.Next,
			})
			if err != nil {
				alert.EmitErr(ctx, err, "Cannot create ephemeral token.",
					"account_id", account.AccountID)
				renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
				return
			}
			if err := session.Commit(); err != nil {
				alert.EmitErr(ctx, err, "Cannot commit session.",
					"account_id", account.AccountID)
				renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
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
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	authSessionID, err := session.CreateSession(ctx, account.AccountID, h.conf.SessionMaxAge)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create authentication session.",
			"accountID", account.AccountID)
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.",
			"account_id", account.AccountID)
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	setAdminSessionCookie(w, h.conf, authSessionID)

	if next := r.Form.Get("next"); next != "" {
		http.Redirect(w, r, next, http.StatusSeeOther)
	} else {
		http.Redirect(w, r, h.conf.PathPrefix, http.StatusSeeOther)
	}
}

type adminLoginVerify struct {
	store Store
	cache cache.Store
	conf  AdminPanelConfiguration
}

func (h adminLoginVerify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("2fa")
	if err != nil {
		http.Redirect(w, r, h.conf.PathPrefix+"login/", http.StatusSeeOther)
		return
	}

	ctx := r.Context()
	trans := transFor(ctx)

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	var verify2faContext struct {
		AccountID string
		Next      string
	}
	switch err := session.EphemeralToken(ctx, "verify-admin-2fa", cookie.Value, &verify2faContext); {
	case err == nil:
		// All good.
	case errors.Is(err, ErrNotFound):
		http.Redirect(w, r, h.conf.PathPrefix+"login/", http.StatusSeeOther)
		return
	default:
		alert.EmitErr(ctx, err, "Cannot get ephemeral token.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	account, err := session.AccountByID(ctx, verify2faContext.AccountID)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot get account referenced in ephemeral token.",
			"token", cookie.Value,
			"account_id", verify2faContext.AccountID)
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	templateContext := struct {
		adminTemplateCore
		PageTitle string
		ErrorMsg  string
		CSRFField template.HTML
	}{
		adminTemplateCore: newAdminTemplateCore(h.conf, "Login verify"),
		CSRFField:         csrf.TemplateField(r),
	}

	if r.Method == "GET" {
		tmpl.Render(w, http.StatusOK, "admin_login_verify.html", templateContext)
		return
	}

	if err := r.ParseForm(); err != nil {
		renderAdminErr(w, h.conf, http.StatusBadRequest, trans.T("Cannot parse form."))
		return
	}

	totpSecret, err := session.AccountTOTPSecret(ctx, account.AccountID)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot get account TOPT secret.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	switch err := totp.Validate(ctx, h.cache, r.Form.Get("code"), totpSecret); {
	case err == nil:
		// All good.
	case errors.Is(err, totp.ErrInvalid):
		templateContext.ErrorMsg = "Invalid verification code."
		tmpl.Render(w, http.StatusBadRequest, "admin_login_verify.html", templateContext)
		return
	case errors.Is(err, totp.ErrUsed):
		templateContext.ErrorMsg = "Code has been used. Please wait and use the next code generated."
		tmpl.Render(w, http.StatusBadRequest, "admin_login_verify.html", templateContext)
		return
	default:
		alert.EmitErr(ctx, err, "Cannot verify TOTP code.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	_ = session.DeleteEphemeralToken(ctx, cookie.Value)

	// To be safe, one more time verify permissions.
	if !account.HasPermission("login") {
		templateContext.ErrorMsg = "Account is not allowed to login."
		tmpl.Render(w, http.StatusForbidden, "admin_login.html", templateContext)
		return
	}
	if !account.HasPermission("lith-admin") {
		templateContext.ErrorMsg = "Account is not allowed to login to admin panel."
		tmpl.Render(w, http.StatusForbidden, "admin_login.html", templateContext)
		return
	}

	authSessionID, err := session.CreateSession(ctx, account.AccountID, h.conf.SessionMaxAge)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create authentication session.",
			"accountID", account.AccountID)
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	setAdminSessionCookie(w, h.conf, authSessionID)
	if verify2faContext.Next == "" {
		http.Redirect(w, r, h.conf.PathPrefix, http.StatusSeeOther)
	} else {
		http.Redirect(w, r, verify2faContext.Next, http.StatusSeeOther)
	}
	return
}

type adminTwoFactorAuthEnable struct {
	store Store
	cache cache.Store
	safe  secret.Safe
	conf  AdminPanelConfiguration
}

func (h adminTwoFactorAuthEnable) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	trans := transFor(ctx)

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	var ephemeralNext string
	cookie, err := r.Cookie("2fa")
	if err != nil {
		here := url.QueryEscape(r.URL.String())
		http.Redirect(w, r, h.conf.PathPrefix+"login/?next="+here, http.StatusTemporaryRedirect)
		return
	}
	var next []byte
	var enable2faContext struct {
		AccountID string
		Next      string
	}
	switch err := session.EphemeralToken(ctx, "enable-admin-2fa", cookie.Value, &enable2faContext); {
	case err == nil:
		// All good.
		ephemeralNext = string(next)
	case errors.Is(err, ErrNotFound):
		here := url.QueryEscape(r.URL.String())
		http.Redirect(w, r, h.conf.PathPrefix+"login/?next="+here, http.StatusTemporaryRedirect)
		return
	default:
		alert.EmitErr(ctx, err, "Cannot get ephemeral token.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	account, err := session.AccountByID(ctx, enable2faContext.AccountID)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot get account referenced in ephemeral token.",
			"token", cookie.Value,
			"account_id", enable2faContext.AccountID)
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	switch _, err := session.AccountTOTPSecret(ctx, account.AccountID); {
	case err == nil:
		renderAdminErr(w, h.conf, http.StatusBadRequest, trans.T("Two Factor Authentication already enabled."))
		return
	case errors.Is(err, ErrNotFound):
		// All good.
	default:
		alert.EmitErr(ctx, err, "Cannot get account TOTP secret.",
			"account_id", account.AccountID)
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	templateContext := struct {
		adminTemplateCore
		ErrorMsg             string
		CurrentAccount       *Account
		EphemeralSecretToken string
		QRCodeBase64         string
		CSRFField            template.HTML
		FlashMsg             *FlashMsg
	}{
		adminTemplateCore: newAdminTemplateCore(h.conf, "Enable Two Factor"),
		CurrentAccount:    account,
		CSRFField:         csrf.TemplateField(r),
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
			renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
			return
		}

		totpEnableContext.Secret = cyphertext
		totpEnableContext.Next = ephemeralNext
		if err := h.cache.SetNx(ctx, totpCacheKey, totpEnableContext, 10*time.Minute); err != nil {
			alert.EmitErr(ctx, err, "Cannot store TOTP enable context.",
				"account_id", account.AccountID)
			renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
			return
		}
	default:
		alert.EmitErr(ctx, err, "Cannot get from cache TOTP enable context.",
			"account_id", account.AccountID)
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	totpSecret, err := h.safe.Decrypt(totpEnableContext.Secret)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot decrypt TOTP secret.",
			"account_id", account.AccountID)
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			renderAdminErr(w, h.conf, http.StatusBadRequest, trans.T("Cannot parse form."))
			return
		}

		switch err := totp.Validate(ctx, h.cache, r.Form.Get("code"), totpSecret); {
		case err == nil:
			// Success.
			if err := session.UpdateAccountTOTPSecret(ctx, account.AccountID, totpSecret); err != nil {
				alert.EmitErr(ctx, err, "Cannot set account TOTP secret.",
					"account_id", account.AccountID)
				renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
				return
			}
			_ = h.cache.Del(ctx, totpCacheKey)

			// If user is forced to enable 2fa in order to login,
			// create a session now. Password was already provided
			// and user proved identity..
			if _, ok := CurrentSessionID(ctx); !ok && account.HasPermission("lith-admin") {
				authSessionID, err := session.CreateSession(ctx, account.AccountID, h.conf.SessionMaxAge)
				if err != nil {
					alert.EmitErr(ctx, err, "Cannot create authentication session.",
						"accountID", account.AccountID)
					renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
					return
				}
				setAdminSessionCookie(w, h.conf, authSessionID)
			}

			if err := session.Commit(); err != nil {
				alert.EmitErr(ctx, err, "Cannot commit session.")
				renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
				return
			}
			if totpEnableContext.Next == "" {
				http.Redirect(w, r, h.conf.PathPrefix, http.StatusSeeOther)
			} else {
				http.Redirect(w, r, totpEnableContext.Next, http.StatusSeeOther)
			}
			return
		case errors.Is(err, totp.ErrInvalid):
			templateContext.ErrorMsg = "Invalid code."
		case errors.Is(err, totp.ErrUsed):
			templateContext.ErrorMsg = "Code already used. Please wait for the next one and try again."
		default:
			alert.EmitErr(ctx, err, "Cannot validate TOTP token.",
				"account_id", account.AccountID)
			renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
			return
		}
	}

	info := totp.URI("Lith Admin", account.Email, totpSecret)
	qr, err := qrcode.New(info, qrcode.Highest)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create TOTP QR-Code.",
			"account_id", account.AccountID)
		renderAdminErr(w, h.conf, http.StatusInternalServerError, trans.T("Cannot generate QR Code."))
		return

	}
	png, err := qr.PNG(400)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot generate TOTP QR-Code PNG file.",
			"account_id", account.AccountID)
		renderAdminErr(w, h.conf, http.StatusInternalServerError, trans.T("Cannot generate QR Code."))
		return
	}
	templateContext.QRCodeBase64 = base64.StdEncoding.EncodeToString(png)
	tmpl.Render(w, http.StatusOK, "admin_twofactor_enable.html", templateContext)
}

type adminLogout struct {
	store Store
	conf  AdminPanelConfiguration
}

func (h adminLogout) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	next := h.conf.PathPrefix + "login/"
	if n := r.URL.Query().Get("next"); n != "" {
		next = n
	}

	sid, ok := CurrentSessionID(ctx)
	if !ok {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()
	if err := session.DeleteSession(ctx, sid); err != nil {
		alert.EmitErr(ctx, err, "Cannot delete auth session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	deleteAdminSessionCookie(w, h.conf)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

type adminAccountsList struct {
	store Store
	conf  AdminPanelConfiguration
}

func (h adminAccountsList) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	account, ok := adminOrRedirect(w, r, h.conf)
	if !ok {
		return
	}

	const accountsPerPage = 100
	query := r.URL.Query()

	templateContext := struct {
		adminTemplateCore
		CurrentAccount *Account
		Accounts       []*Account
		Query          string

		Pagination struct {
			PrevPage    uint
			HasPrev     bool
			CurrentPage uint
			NextPage    uint
			HasNext     bool
		}
	}{
		adminTemplateCore: newAdminTemplateCore(h.conf, "Accounts"),
		CurrentAccount:    account,
		Query:             query.Get("q"),
	}

	page, _ := strconv.ParseUint(query.Get("page"), 10, 64)
	if page == 0 {
		page = 1
	}
	templateContext.Pagination.CurrentPage = uint(page)
	if page > 1 {
		templateContext.Pagination.PrevPage = uint(page - 1)
		templateContext.Pagination.HasPrev = true
	}

	ctx := r.Context()
	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	offset := uint((page - 1) * accountsPerPage)
	// Fetch one more account than needed to know if there is a next page
	// or not.
	accounts, err := session.ListAccounts(ctx, query.Get("q"), accountsPerPage+1, offset)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot list accounts.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	if len(accounts) == accountsPerPage+1 {
		accounts = accounts[:accountsPerPage]
		templateContext.Pagination.NextPage = uint(page + 1)
		templateContext.Pagination.HasNext = true
	}
	templateContext.Accounts = accounts

	tmpl.Render(w, http.StatusOK, "admin_accounts_list.html", templateContext)
}

type adminAccountCreate struct {
	store  Store
	flash  flashmsg
	events eventbus.Sink
	conf   AdminPanelConfiguration
}

func (h adminAccountCreate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	currentAccount, ok := adminOrRedirect(w, r, h.conf)
	if !ok {
		return
	}

	templateContext := struct {
		adminTemplateCore
		CurrentAccount *Account
		Email          string
		Errors         validation.Errors
		CSRFField      template.HTML
	}{
		adminTemplateCore: newAdminTemplateCore(h.conf, "Create Account"),
		CurrentAccount:    currentAccount,
		CSRFField:         csrf.TemplateField(r),
	}

	if r.Method == "GET" {
		tmpl.Render(w, http.StatusOK, "admin_account_create.html", templateContext)
		return
	}

	if err := r.ParseForm(); err != nil {
		renderAdminErr(w, h.conf, http.StatusBadRequest, "Cannot parse form.")
		return
	}

	ctx := r.Context()
	trans := transFor(ctx)

	templateContext.Email = normalizeEmail(r.Form.Get("email"))
	if templateContext.Email == "" {
		templateContext.Errors.Add("email", trans.T("Email is required."))
	}

	if !templateContext.Errors.Empty() {
		tmpl.Render(w, http.StatusOK, "admin_account_create.html", templateContext)
		return
	}

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()
	// Use random password because it is the user that is supposed
	// to set it up. Because password is unknown,  password reset
	// form can be used to do it.
	randomPassword := hex.EncodeToString(secret.Generate(16))
	account, err := session.CreateAccount(ctx, templateContext.Email, randomPassword)
	switch {
	case err == nil:
		// All good.
	case errors.Is(err, ErrConflict):
		templateContext.Errors.Add("email", trans.T("Email address already in use."))
		tmpl.Render(w, http.StatusBadRequest, "admin_account_create.html", templateContext)
		return
	default:
		alert.EmitErr(ctx, err, "Cannot create account.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	addChangelog(ctx, session, "created", "Account", account.AccountID)

	if err := session.Commit(); err != nil {
		alert.EmitErr(ctx, err, "Cannot commit session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	event := AccountRegisteredEvent(account.AccountID, account.Email, account.CreatedAt)
	if err := h.events.PublishEvent(ctx, event); err != nil {
		alert.EmitErr(ctx, err,
			"Cannot emit event.",
			"account", account.AccountID,
			"event", "AccountRegisteredEvent")
	}

	h.flash.Notify(w, r, FlashMsg{
		Kind: "green",
		Text: fmt.Sprintf(trans.T("Account %q successfully created."), account.Email),
	})
	http.Redirect(w, r, h.conf.PathPrefix+"accounts/"+account.AccountID+"/", http.StatusSeeOther)
	return
}

type adminAccountDetails struct {
	store Store
	conf  AdminPanelConfiguration
	flash flashmsg
}

func (h adminAccountDetails) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	currentAccount, ok := adminOrRedirect(w, r, h.conf)
	if !ok {
		return
	}

	type ExtendedPermissionGroup struct {
		*PermissionGroup
		AssignedToAccount bool
	}

	templateContext := struct {
		adminTemplateCore
		CurrentAccount   *Account
		Account          *Account
		AccountTwoFactor bool
		PermissionGroups []*ExtendedPermissionGroup
		CSRFField        template.HTML
		FlashMsg         *FlashMsg
	}{
		adminTemplateCore: newAdminTemplateCore(h.conf, "Accounts"),
		CurrentAccount:    currentAccount,
		CSRFField:         csrf.TemplateField(r),
	}

	ctx := r.Context()
	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	account, err := session.AccountByID(ctx, web.PathArg(r, "account-id"))
	switch {
	case err == nil:
		templateContext.Account = account
	case errors.Is(err, ErrNotFound):
		renderAdminErr(w, h.conf, http.StatusNotFound, "Account does not exist.")
		return
	default:
		alert.EmitErr(ctx, err, "Cannot get account by ID.",
			"account_id", web.PathArg(r, "account-id"))
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "Cannot get account details.")
		return
	}

	switch _, err := session.AccountTOTPSecret(ctx, account.AccountID); {
	case err == nil:
		templateContext.AccountTwoFactor = true
	case errors.Is(err, ErrNotFound):
		templateContext.AccountTwoFactor = false
	default:
		alert.EmitErr(ctx, err, "Cannot get account TOTP secret.",
			"account_id", web.PathArg(r, "account-id"))
		templateContext.AccountTwoFactor = false
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			renderAdminErr(w, h.conf, http.StatusBadRequest, "Cannot parse form.")
			return
		}

		var assignedGroups []uint64
		for _, sid := range r.Form["permissiongroup"] {
			pgID, err := strconv.ParseUint(sid, 10, 64)
			if err != nil {
				renderAdminErr(w, h.conf, http.StatusInternalServerError, "Invalid Permission Group ID posted.")
				return
			}
			assignedGroups = append(assignedGroups, pgID)
		}
		if err := session.UpdateAccountPermissionGroups(ctx, account.AccountID, assignedGroups); err != nil {
			alert.EmitErr(ctx, err, "Cannot update account permission groups.",
				"account_id", account.AccountID)
			renderAdminErr(w, h.conf, http.StatusBadRequest, "Cannot update assigned permission groups.")
			return
		}

		addChangelog(ctx, session, "updated", "Account", account.AccountID)

		if err := session.Commit(); err != nil {
			alert.EmitErr(ctx, err, "Cannot commit session.",
				"account_id", account.AccountID)
			renderAdminErr(w, h.conf, http.StatusInternalServerError, "Cannot commit changes.")
			return
		}

		trans := transFor(ctx)
		h.flash.Notify(w, r, FlashMsg{
			Kind: "green",
			Text: fmt.Sprintf(trans.T("Account %q successfully updated."), account.Email),
		})

		http.Redirect(w, r, h.conf.PathPrefix+"accounts/"+account.AccountID+"/", http.StatusSeeOther)
		return
	}

	allGroups, err := session.ListPermissionGroups(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot get permission groups.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "Cannot get permission groups.")
		return
	}
	accountGroups, err := session.PermissionGroupsByAccount(ctx, account.AccountID)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot get account permission groups.",
			"account_id", account.AccountID)
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "Cannot get account permission groups.")
		return
	}
	accountGroupIDs := make(map[uint64]bool)
	for _, g := range accountGroups {
		accountGroupIDs[g.PermissionGroupID] = true
	}
	extGroups := make([]*ExtendedPermissionGroup, 0, len(allGroups))
	for _, g := range allGroups {
		extGroups = append(extGroups, &ExtendedPermissionGroup{
			PermissionGroup:   g,
			AssignedToAccount: accountGroupIDs[g.PermissionGroupID],
		})
	}
	templateContext.PermissionGroups = extGroups
	templateContext.FlashMsg = h.flash.Pop(w, r)
	tmpl.Render(w, http.StatusOK, "admin_account_details.html", templateContext)
}

type adminPermissionGroupsList struct {
	store Store
	flash flashmsg
	conf  AdminPanelConfiguration
}

func (h adminPermissionGroupsList) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	account, ok := adminOrRedirect(w, r, h.conf)
	if !ok {
		return
	}

	templateContext := struct {
		adminTemplateCore
		CurrentAccount   *Account
		PermissionGroups []*PermissionGroup
		FlashMsg         *FlashMsg
	}{
		adminTemplateCore: newAdminTemplateCore(h.conf, "Permission Groups"),
		CurrentAccount:    account,
	}

	ctx := r.Context()
	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	groups, err := session.ListPermissionGroups(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot list permission groups.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	templateContext.PermissionGroups = groups
	templateContext.FlashMsg = h.flash.Pop(w, r)
	tmpl.Render(w, http.StatusOK, "admin_permissiongroups_list.html", templateContext)
}

type adminPermissionGroupCreate struct {
	store Store
	flash flashmsg
	conf  AdminPanelConfiguration
}

func (h adminPermissionGroupCreate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	currentAccount, ok := adminOrRedirect(w, r, h.conf)
	if !ok {
		return
	}

	ctx := r.Context()
	trans := transFor(ctx)

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	templateContext := struct {
		adminTemplateCore
		CurrentAccount *Account
		Description    string
		Permissions    []string
		Errors         validation.Errors
		CSRFField      template.HTML
	}{
		adminTemplateCore: newAdminTemplateCore(h.conf, "Create Permission Group"),
		CurrentAccount:    currentAccount,
		CSRFField:         csrf.TemplateField(r),
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			renderAdminErr(w, h.conf, http.StatusBadRequest, "Cannot parse form.")
			return
		}

		templateContext.Permissions = splitPermissions(r.Form.Get("permissions"))
		validPermission := regexp.MustCompile(`[a-zA-Z0-9\-_\.:]+`)
		for _, p := range templateContext.Permissions {
			if !validPermission.MatchString(p) {
				templateContext.Errors.Add("permissions", "%q is not a valid permission name.", p)
			}
		}

		templateContext.Description = strings.TrimSpace(r.Form.Get("description"))
		if templateContext.Description == "" {
			templateContext.Errors.Add("description", trans.T("Description is required."))
		}

		if templateContext.Errors.Empty() {
			group, err := session.CreatePermissionGroup(ctx, templateContext.Description, templateContext.Permissions)
			if err != nil {
				alert.EmitErr(ctx, err, "Cannot create permission group.")
				renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
				return
			}
			addChangelog(ctx, session, "created", "PermissionGroup", group.PermissionGroupID)
			if err := session.Commit(); err != nil {
				alert.EmitErr(ctx, err, "Cannot commit session.")
				renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
				return
			}
			trans := transFor(ctx)
			h.flash.Notify(w, r, FlashMsg{
				Kind: "green",
				Text: fmt.Sprintf(trans.T("Permission Group %q successfully created."), group.Description),
			})
			http.Redirect(w, r, h.conf.PathPrefix+"permissiongroups/", http.StatusSeeOther)
			return
		}
	}

	tmpl.Render(w, http.StatusOK, "admin_permissiongroup_create.html", templateContext)
}

type adminPermissionGroupDetails struct {
	store Store
	flash flashmsg
	conf  AdminPanelConfiguration
}

func (h adminPermissionGroupDetails) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	currentAccount, ok := adminOrRedirect(w, r, h.conf)
	if !ok {
		return
	}

	ctx := r.Context()
	trans := transFor(ctx)

	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	permissiongroupID, _ := strconv.ParseUint(web.PathArg(r, "permissiongroup-id"), 10, 64)
	group, err := session.PermissionGroupByID(ctx, permissiongroupID)
	switch {
	case err == nil:
		// All good.
	case errors.Is(err, ErrNotFound):
		renderAdminErr(w, h.conf, http.StatusNotFound, trans.T("Permission Group does not exist."))
		return
	default:
		alert.EmitErr(ctx, err, "Cannot get permission group.",
			"permissiongroup_id", web.PathArg(r, "permissiongroup-id"))
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	templateContext := struct {
		adminTemplateCore
		CurrentAccount  *Account
		PermissionGroup *PermissionGroup
		Description     string
		Permissions     []string
		Errors          validation.Errors
		CSRFField       template.HTML
		FlashMsg        *FlashMsg
	}{
		adminTemplateCore: newAdminTemplateCore(h.conf, "Permission Group: "+group.Description),
		CurrentAccount:    currentAccount,
		PermissionGroup:   group,
		Description:       group.Description,
		Permissions:       group.Permissions,
		CSRFField:         csrf.TemplateField(r),
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			renderAdminErr(w, h.conf, http.StatusBadRequest, "Cannot parse form.")
			return
		}

		templateContext.Permissions = splitPermissions(r.Form.Get("permissions"))
		validPermission := regexp.MustCompile(`[a-zA-Z0-9\-_\.:]+`)
		for _, p := range templateContext.Permissions {
			if !validPermission.MatchString(p) {
				templateContext.Errors.Add("permissions", "%q is not a valid permission name.", p)
			}
		}

		templateContext.Description = strings.TrimSpace(r.Form.Get("description"))
		if templateContext.Description == "" {
			templateContext.Errors.Add("description", trans.T("Description is required."))
		}

		if templateContext.Errors.Empty() {
			if err := session.UpdatePermissionGroup(ctx, group.PermissionGroupID, templateContext.Description, templateContext.Permissions); err != nil {
				alert.EmitErr(ctx, err, "Cannot update permission group.",
					"permissiongroup_id", fmt.Sprint(group.PermissionGroupID))
				renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
				return
			}

			addChangelog(ctx, session, "updated", "PermissionGroup", group.PermissionGroupID)
			if err := session.Commit(); err != nil {
				alert.EmitErr(ctx, err, "Cannot commit session.",
					"permissiongroup_id", fmt.Sprint(group.PermissionGroupID))
				renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
				return
			}
			trans := transFor(ctx)
			h.flash.Notify(w, r, FlashMsg{
				Kind: "green",
				Text: fmt.Sprintf(trans.T("Permission Group %q successfully updated."), group.Description),
			})
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}
	}

	templateContext.FlashMsg = h.flash.Pop(w, r)
	tmpl.Render(w, http.StatusOK, "admin_permissiongroup_details.html", templateContext)
}

func splitPermissions(s string) []string {
	uniq := make(map[string]struct{})
	for _, p := range regexp.MustCompile(`\s+`).Split(s, -1) {
		if p != "" {
			uniq[p] = struct{}{}
		}
	}

	result := make([]string, 0, len(uniq))
	for p := range uniq {
		result = append(result, p)
	}
	sort.Strings(result)

	return result
}

type adminChangelogsList struct {
	store Store
	conf  AdminPanelConfiguration
}

func (h adminChangelogsList) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	account, ok := adminOrRedirect(w, r, h.conf)
	if !ok {
		return
	}

	type ExtendedChangelog struct {
		*Changelog
		EntityURL string
	}

	templateContext := struct {
		adminTemplateCore
		CurrentAccount *Account
		Changelogs     []ExtendedChangelog
	}{
		adminTemplateCore: newAdminTemplateCore(h.conf, "Changelogs"),
		CurrentAccount:    account,
	}

	ctx := r.Context()
	session, err := h.store.Session(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot create store session.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}
	defer session.Rollback()

	changelogs, err := session.ListChangelogs(ctx)
	if err != nil {
		alert.EmitErr(ctx, err, "Cannot list changelogs.")
		renderAdminErr(w, h.conf, http.StatusInternalServerError, "")
		return
	}

	for _, c := range changelogs {
		ec := ExtendedChangelog{
			Changelog: c,
		}
		switch c.EntityKind {
		case "Account":
			ec.EntityURL = h.conf.PathPrefix + "accounts/" + c.EntityPk
		case "PermissionGroup":
			ec.EntityURL = h.conf.PathPrefix + "permissiongroups/" + c.EntityPk
		}
		templateContext.Changelogs = append(templateContext.Changelogs, ec)
	}

	tmpl.Render(w, http.StatusOK, "admin_changelogs_list.html", templateContext)
}

// renderAdminErr is a shortcut for rendering admin error pages.
func renderAdminErr(
	w http.ResponseWriter,
	conf AdminPanelConfiguration,
	code int,
	description string,
) {
	tmpl.Render(w, code, "admin_error.html", struct {
		adminTemplateCore
		Title       string
		Code        int
		Description string
	}{
		adminTemplateCore: newAdminTemplateCore(conf, http.StatusText(code)),
		Title:             http.StatusText(code),
		Code:              code,
		Description:       description,
	})
}

func adminOrRedirect(w http.ResponseWriter, r *http.Request, conf AdminPanelConfiguration) (*Account, bool) {
	acc, ok := CurrentAccount(r.Context())
	if !ok {
		http.Redirect(w, r, conf.PathPrefix+"login/?next="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
		return nil, false
	}
	if !acc.HasPermission("lith-admin") {
		trans := transFor(r.Context())
		renderAdminErr(w, conf, http.StatusForbidden, trans.T("Not allowed to access admin panel."))
		return nil, false
	}
	return acc, true
}

func setAdminSessionCookie(w http.ResponseWriter, conf AdminPanelConfiguration, authSessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "s",
		Path:     conf.PathPrefix,
		Value:    authSessionID,
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
		MaxAge:   int(conf.SessionMaxAge / time.Second),
	})
}

func deleteAdminSessionCookie(w http.ResponseWriter, conf AdminPanelConfiguration) {
	http.SetCookie(w, &http.Cookie{
		Name:   "s",
		Path:   conf.PathPrefix,
		Value:  "",
		MaxAge: 0,
	})
}

// newAdminTemplateCore returns properly initialized core template context.
func newAdminTemplateCore(conf AdminPanelConfiguration, pageTitle string) adminTemplateCore {
	return adminTemplateCore{
		PageTitle: "Admin: " + pageTitle,
		conf:      conf,
	}
}

// adminTemplateCore contains the bare minimum of a template context that each
// admin template requires. To ensure that each template provides that
// minimum, this structure was extracted. Embed it in each handler's template
// context.
type adminTemplateCore struct {
	PageTitle string
	// Keep configuration hidden, just in case, so that it is not possible
	// to leak it out via templates. Any value if needed, expose via method.
	conf AdminPanelConfiguration
}

// AbsolutePath returns an absolute version of given path. Depending on
// configuration, all paths might be prefixed. This function allows to build an
// absolute path that will work regardless of path prefix configured.
//
// Alternative approach could be to use relative paths only. This is not always
// possible when rendering HTML documents. For example static files path is
// easier to provide as an absolute one.
func (c adminTemplateCore) AbsolutePath(path string) string {
	for strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	return c.conf.PathPrefix + path
}

// CSS returns a list of absolute URLs for all static files that should be
// included.
func (c adminTemplateCore) CSS() []string {
	return []string{
		c.conf.PathPrefix + "statics/normalize.css",
		c.conf.PathPrefix + "statics/custom.css",
	}
}

// addChangelog creates a changelog entry within given session. Since logging
// issues are not critical, any failure is only logged.
func addChangelog(ctx context.Context, s StoreSession, operation, entityKind string, entityPk interface{}) {
	a, ok := CurrentAccount(ctx)
	if !ok {
		alert.EmitErr(ctx, errors.New("unauthorized"), "Cannot add changelog entry - no current user.")
		return
	}
	err := s.AddChangelog(ctx, a.AccountID, operation, entityKind, fmt.Sprint(entityPk))

	if err != nil {
		alert.EmitErr(ctx, err, "Cannot add changelog entry - database failure.")
		return
	}
}

// flashmsg provides a single flash message storage that is using HTTP cookie.
//
// Implementation is limited to at most only one message at a time to simplify
// the implementation and the usage. Use this functionality for delivering
// helpful but not important messages. A flash message might not be delivered.
type flashmsg struct {
	safe       secret.Safe
	pathPrefix string
}

type FlashMsg struct {
	Kind string `json:"k"`
	Text string `json:"t"`
}

func (m FlashMsg) HTML() template.HTML {
	return template.HTML(m.Text)
}

func (fm flashmsg) Notify(w http.ResponseWriter, r *http.Request, msg FlashMsg) error {
	serialized, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("json serialize: %w", err)
	}

	noise := make([]byte, flashNoisePrefixSize, flashNoisePrefixSize+len(serialized))
	if _, err := rand.Read(noise); err != nil {
		panic(err)
	}

	raw, err := fm.safe.Encrypt(append(noise, serialized...))
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "fm",
		Path:     fm.pathPrefix,
		Value:    base64.URLEncoding.EncodeToString(raw),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(30 * time.Minute / time.Second),
		HttpOnly: true,
	})
	return nil
}

func (fm flashmsg) Pop(w http.ResponseWriter, r *http.Request) *FlashMsg {
	c, err := r.Cookie("fm")
	if err != nil {
		return nil
	}
	raw, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	serialized, err := fm.safe.Decrypt(raw)
	if err != nil {
		return nil
	}

	var msg FlashMsg
	if err := json.Unmarshal(serialized[flashNoisePrefixSize:], &msg); err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "fm",
		Path:     fm.pathPrefix,
		Value:    "",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		HttpOnly: true,
	})
	return &msg
}

// noise prefix is used to ensure encrypted data is not too short and produce
// weak encryption. Add random junk to make the cracking harder.
const flashNoisePrefixSize = 32
