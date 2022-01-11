package lith

import (
	"bytes"
	"context"
	"fmt"

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
