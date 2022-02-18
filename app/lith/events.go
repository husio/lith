package lith

import (
	"time"

	"github.com/husio/lith/pkg/eventbus"
)

// AccountRegisteredEvent returns an event that represents an account
// registration.
func AccountRegisteredEvent(accountID, email string, createdAt time.Time) eventbus.Event {
	return eventbus.Event{
		Kind:      "account-registered",
		ID:        GenerateID(),
		CreatedAt: createdAt,
		Payload: struct {
			AccountID string `json:"account_id"`
			Email     string `json:"email"`
		}{
			AccountID: accountID,
			Email:     email,
		},
	}
}

// SessionCreatedEvent returns an event that represents an authentication
// session creation.
func SessionCreatedEvent(accountID string, createdAt time.Time) eventbus.Event {
	return eventbus.Event{
		Kind:      "session-created",
		ID:        GenerateID(),
		CreatedAt: createdAt,
		Payload: struct {
			AccountID string `json:"account_id"`
		}{
			AccountID: accountID,
		},
	}
}
