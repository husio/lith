package lith

import (
	"time"

	"github.com/husio/lith/pkg/eventbus"
)

// AccountRegisteredEvent returns an event that represents an account registration.
func AccountRegisteredEvent(accountID, email string, createdAt time.Time) eventbus.Event {
	return eventbus.Event{
		Kind:      "account-registered",
		ID:        generateID(),
		CreatedAt: createdAt,
		Data: struct {
			AccountID string `json:"account_id"`
			Email     string `json:"email"`
		}{
			AccountID: accountID,
			Email:     email,
		},
	}
}
