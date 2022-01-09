package lith

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/husio/lith/pkg/email"
	"github.com/husio/lith/pkg/taskqueue"
)

type SendConfirmRegistration struct {
	Language     string
	FromEmail    string
	AccountEmail string
	Token        string
	CompleteURL  string
}

func (SendConfirmRegistration) TaskName() string {
	return "send-confirm-registration"
}

func NewSendConfirmRegistrationHandler(s email.Server) taskqueue.Handler {
	return sendConfirmRegistrationHandler{emailserver: s}
}

type sendConfirmRegistrationHandler struct {
	emailserver email.Server
}

func (h sendConfirmRegistrationHandler) HandleTask(ctx context.Context, sn taskqueue.Scheduler, p taskqueue.Payload) error {
	t := p.(*SendConfirmRegistration)
	var b bytes.Buffer
	if err := tmpl.RenderTo(&b, t.Language, "email_confirm_registration.html", t); err != nil {
		return fmt.Errorf("render email template: %w", err)
	}
	return h.emailserver.Send(t.FromEmail, t.AccountEmail, "Account Registration", b.Bytes())
}

type SendResetPassword struct {
	FromEmail    string
	Language     string
	AccountID    string
	AccountEmail string
	Token        string
	CompleteURL  string
}

func (SendResetPassword) TaskName() string {
	return "send-reset-password"
}

func NewSendResetPasswordHandler(s email.Server) taskqueue.Handler {
	return sendResetPasswordHandler{emailserver: s}
}

type sendResetPasswordHandler struct {
	emailserver email.Server
}

func (h sendResetPasswordHandler) HandleTask(ctx context.Context, sn taskqueue.Scheduler, p taskqueue.Payload) error {
	t := p.(*SendResetPassword)
	var b bytes.Buffer
	if err := tmpl.RenderTo(&b, t.Language, "email_reset_password.html", t); err != nil {
		return fmt.Errorf("render email template: %w", err)
	}
	return h.emailserver.Send(t.FromEmail, t.AccountEmail, "Password Reset", b.Bytes())
}

type AccountRegisteredEvent struct {
	EventID string
	Account Account
}

func (AccountRegisteredEvent) TaskName() string {
	return "account-registered-event"
}

func NewAccountRegisteredEventHandler(n Notifier) taskqueue.Handler {
	return accountRegisteredEventHandler{notifier: n}
}

type accountRegisteredEventHandler struct {
	notifier Notifier
}

func (h accountRegisteredEventHandler) HandleTask(ctx context.Context, sn taskqueue.Scheduler, p taskqueue.Payload) error {
	t := p.(*AccountRegisteredEvent)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	data := struct {
		AccountID   string    `json:"account_id"`
		Permissions []string  `json:"permissions"`
		CreatedAt   time.Time `json:"created_at"`
	}{
		AccountID:   t.Account.AccountID,
		Permissions: t.Account.Permissions,
		CreatedAt:   t.Account.CreatedAt,
	}

	if err := h.notifier.Notify(ctx, t.EventID, data); err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	return nil
}
