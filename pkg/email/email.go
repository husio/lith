package email

type Server interface {
	// Send is a simplified interface for sending emails. Functionality is
	// narrowed to a notification message. No attachments, Cc, etc.
	Send(from, to, subject string, body []byte) error
}
