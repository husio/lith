package email

import (
	"bytes"
	"errors"
	"fmt"
	"net/smtp"
)

// NewSMTPServer returns a mail server implementation that is using SMTP
// protocol in order to send email messages.
func NewSMTPServer(smtpAddress string, auth smtp.Auth) Server {
	return smtpclient{
		addr: smtpAddress,
		auth: auth,
	}
}

type smtpclient struct {
	addr string
	auth smtp.Auth
}

func (c smtpclient) Send(from, to, subject string, body []byte) error {
	msg := formatMessage(from, to, subject, body)
	if err := smtp.SendMail(c.addr, c.auth, from, []string{to}, msg); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}

func formatMessage(from, to, subject string, body []byte) []byte {
	b := bytes.NewBuffer(make([]byte, 0, 1024*6))

	fmt.Fprintf(b, "To: %s\r\n", to)
	fmt.Fprint(b, "MIME-version: 1.0;\r\n")
	fmt.Fprint(b, "Content-Type: text/html; charset=\"UTF-8\";\r\n")
	fmt.Fprintf(b, "Subject: %s\r\n", subject)
	fmt.Fprint(b, "\r\n")
	b.Write(body)
	fmt.Fprintf(b, "\r\n")

	return b.Bytes()
}

// unsafePlainAuth is a copy of smtp.plainAuth with a modification to allow
// sending over any unencrypted connection.
type unsafePlainAuth struct {
	identity, username, password string
	host                         string
}

// UnsafePlainAuth returns plain auth authentication, just like the
// smtp.PlainAuth function does. The difference is that UnsafePlainAuth always
// allows to use unencrypted connection.
func UnsafePlainAuth(identity, username, password, host string) smtp.Auth {
	return &unsafePlainAuth{identity, username, password, host}
}

func (a *unsafePlainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	resp := []byte(a.identity + "\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *unsafePlainAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}
