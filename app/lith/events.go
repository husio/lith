package lith

// AccountRegisteredEvent is emitted when a new account is created.
type AccountRegisteredEvent struct {
	AccountID string `json:"account_id"`
	Email     string `json:"email"`
}
