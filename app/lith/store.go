package lith

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/husio/lith/pkg/secret"
)

type Store interface {
	// Session returns a new session that process all operations within a
	// translation.
	Session(context.Context) (StoreSession, error)

	// Close store and free all resources.
	Close() error
}

type StoreSession interface {
	// Session returns a new session that process all operations within a
	// translation. Commiting returned session merges all changes to the
	// parent and it is up to the parent to do the final commit or rollback
	// all changes.
	Session(context.Context) (StoreSession, error)

	// Commit all changes applied within given sesssion.
	Commit() error

	// Rollback all changes applied within given session.
	Rollback()

	// CreateAccount creates an account using given email and password.
	// Password must be strong enough for bcrypt to be able to hash it.
	// Email must be unique.
	CreateAccount(ctx context.Context, email, password string) (*Account, error)

	// UpdateAccountPermissionGroups updates the account permission groups.
	// Previous assignement is removed.
	UpdateAccountPermissionGroups(ctx context.Context, accountID string, permissionGroupIDs []uint64) error

	// UpdateAccountPassword updates the account password to the new value.
	// Password argument must be a plain text password.
	UpdateAccountPassword(ctx context.Context, accountID string, password string) error

	// IsAccountPassword validates if given password belongs to specified
	// account. ErrNotFound is returned if account does not exist.
	// ErrPassword is returned if account does exist but password does not
	// match.
	IsAccountPassword(ctx context.Context, accountID, password string) error

	// UpdateAccountTOTPSecret updates the account TOTP secret to given
	// value.
	UpdateAccountTOTPSecret(ctx context.Context, accountID string, totp secret.Value) error

	// AccountTOTPSecret returns TOTP secret that belongs to given account.
	AccountTOTPSecret(ctx context.Context, accountID string) (secret.Value, error)

	// AccountByID returns an account with given ID.
	// Returns ErrNotFound if account with given ID cannot be found.
	AccountByID(ctx context.Context, accountID string) (*Account, error)

	// AccountBySession
	// Returns ErrNotFound if account with given ID cannot be found.
	AccountBySession(ctx context.Context, sessionID string) (*Account, error)

	// AccountByEmail
	// Returns ErrNotFound if session with given ID cannot be found.
	AccountByEmail(ctx context.Context, email string) (*Account, error)

	// ListAccounts returns all accounts matching given filter. Filter is a
	// list of whitespace separated strings that all must be part of
	// returned account email address. Match is case insensitive.
	//
	// This method is meant for internal use only and it is not safe to
	// expose it to all/any users.
	//
	// Returns ErrNotFound if account with given email cannot be found.
	ListAccounts(ctx context.Context, filter string, limit, offset uint) ([]*Account, error)

	// CreateSession creates and returns a new session that is valid for
	// given period.
	//
	// Returns ErrNotFound if an account with given ID does not exist.
	CreateSession(ctx context.Context, accountID string, expiresIn time.Duration) (string, error)

	// DeleteSession removes session from the system. Deleted session can
	// no longer be used.
	DeleteSession(ctx context.Context, sessionID string) error

	// DeleteAccountSessions deletes all authentication sessions that
	// belong to the account with the given ID.
	DeleteAccountSessions(ctx context.Context, accountID string) error

	// RefreshSession updates a session expiration time, extending it to at
	// least given duration. If the current expiration time is greater than
	// provided duration, no update is made.
	//
	// To avoid writes, this method works with expiration approximation. If
	// expiration time is close to desired state, value might not be
	// updated.
	// This method can only extend expiration time and never shorten it.
	//
	// Returns ErrNotFound if session with given ID does not exist.
	RefreshSession(ctx context.Context, sessionID string, expiresIn time.Duration) (time.Time, error)

	// CreatePermissionGroup creates a new Permission Group.
	CreatePermissionGroup(ctx context.Context, description string, permissions []string) (*PermissionGroup, error)

	// UpdatePermissionGroup is setting attributes of a single permission
	// group to provided values.
	//
	// Returns ErrNotFound if Permission Group with given ID does not
	// exist.
	UpdatePermissionGroup(ctx context.Context, permissionGroupID uint64, description string, permissions []string) error

	// PermissionGroupsByAccount returns a list of all Permission Group
	// entities that were assigned to the account with given ID.
	PermissionGroupsByAccount(ctx context.Context, accountID string) ([]*PermissionGroup, error)

	// PermissionGroupByID returns a single Permission Group with given ID.
	// Returns ErrNotFound if Permission Group with requested ID does not
	// exist.
	PermissionGroupByID(ctx context.Context, permissiongroupID uint64) (*PermissionGroup, error)

	// ListPermissionGroups returns all existing Permission Group entities.
	// No Pagination.
	ListPermissionGroups(ctx context.Context) ([]*PermissionGroup, error)

	// ListChangelogs returns all existing Changelog entries. No pagination.
	ListChangelogs(ctx context.Context) ([]*Changelog, error)

	// AddChangelog appends a changelog entry.
	//
	// AuthenticatedAs is the ID of the user that makes the change.
	// Operation should be created, updated or deleted. Entity kind and pk
	// describes the type and primary key of the modified entity. Primary
	// key must be serialized to string.
	AddChangelog(ctx context.Context, authentitcatedAs, operation, entityKind, entityPk string) error

	// CreateEphemeralToken generates a single use, expiring token.
	// Addintional payload can be provided that will be stored within the
	// token.
	CreateEphemeralToken(ctx context.Context, action string, expireIn time.Duration, payload interface{}) (string, error)

	// EphemeralToken loads payload of a token matching given action an ID
	// into provided destination.
	// ErrNotFound is returned if token does not exists.
	EphemeralToken(ctx context.Context, action, tokenID string, payloadDest interface{}) error

	// DeleteEphemeralToken removes token with given ID.
	// ErrNotFound is returned if token does not exists.
	DeleteEphemeralToken(ctx context.Context, tokenID string) error

	// Vacuum removes stale data that is no longer requred. For example
	// expired ephemeral tokens or sessions.
	Vacuum(ctx context.Context) error
}

type Account struct {
	AccountID   string
	Email       string
	CreatedAt   time.Time
	ModifiedAt  time.Time
	Permissions []string
}

// HasPermission returns true if this account requested permission. A nil
// account has no permissions.
func (a *Account) HasPermission(permission string) bool {
	if a == nil {
		return false
	}
	for _, p := range a.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

type EphemeralToken struct {
	TokenID   string
	AccountID string
	Action    string
}

type PermissionGroup struct {
	PermissionGroupID uint64
	Permissions       []string
	Description       string
	CreatedAt         time.Time
	ModifiedAt        time.Time
}

type Changelog struct {
	ChangelogID  uint64
	AccountID    string
	AccountEmail string
	Operation    string
	EntityKind   string
	EntityPk     string
	CreatedAt    time.Time
}

var (
	// ErrStore is a base error for all repository specific errors.
	ErrStore = errors.New("store")

	// ErrNotFound is returned whenever a requested entity was not found.
	ErrNotFound = fmt.Errorf("%w: not found", ErrStore)

	// ErrConflict is returned whenever an operation cannot be completed
	// because it would cause data integrity violation.
	ErrConflict = fmt.Errorf("%w: conflict", ErrStore)

	// ErrPassword is returned whenever a password comparison fails.
	ErrPassword = fmt.Errorf("%s: invalid password", ErrStore)
)

// Certain permission groups are provided by the migration and should not be
// deleted.
const (
	PermissionGroupSystemAdmin   uint64 = 1
	PermissionGroupActiveAccount uint64 = 2
)
