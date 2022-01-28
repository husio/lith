package lith

import "time"

type Configuration struct {
	Database             string
	TaskQueueDatabase    string
	Secret               string
	StoreVacuumFrequency time.Duration

	// Event recipient configuraiton.
	//
	// EventSinkBackend specifies which backend to use to broadcast events.
	// Choices are: dropall, fs, webhook
	EventSinkBackend    string
	EventSinkWebhook    EventSinkWebhookConfiguration
	EventSinkFilesystem EventSinkFilesystemConfiguration

	// Email configuraiton.
	//
	// EmailBackend specifies which backend to use. Choices are: smtp fs
	EmailBackend    string
	SMTP            SMTPConfiguration
	FilesystemEmail FilesystemEmailConfiguration

	// MaxCacheSize if set, defines how many bytes can be used by the
	// in-memory cache service before the LRU starts evicting entries.
	//
	// If set to 0, there is no memory limit and entries are never evicted.
	MaxCacheSize uint64

	AdminPanel AdminPanelConfiguration
	PublicUI   PublicUIConfiguration
	API        APIConfiguration
}

type EventSinkWebhookConfiguration struct {
	// URL is the address of the recipient. If not set, webhook
	// functionality is disabled.
	URL string

	// Secret is shared between client and server, used to sign the
	// request.
	Secret string
}

type EventSinkFilesystemConfiguration struct {
	// Dir specifies a directory where all events will be written.
	Dir string
}

type SMTPConfiguration struct {
	Port     int
	Host     string
	Username string
	Password string

	// AllowUnencrypted allows to authenticate using an unencrypted
	// connection. This configuration is for testing purposes only, when
	// running a local cluster without certificates.
	AllowUnencrypted bool
}

type FilesystemEmailConfiguration struct {
	// Dir specifies a directory where all email messages will be written
	// instead of sending over the network.
	Dir string
}

type PublicUIConfiguration struct {
	// ListenHTTP defines on which address and port the public UI HTTP
	// server should operate. Keep empty to disable.
	ListenHTTP string

	// PathPrefix allows to define a prefix path that each public UI route
	// will include.
	PathPrefix string

	// Domain is the domain of the main website. This information is used
	// when constructing absolute URL for example inside of email messages.
	Domain string

	// DomainSSL specifies if the public UI should be served over encrypted
	// connection or not.
	DomainSSL bool

	// RequireTwoFactorAuth defines if user must provide two factor
	// authentication code in order to login. If false, two factor
	// authentication is optional and can be turned on by each account
	// owner.
	RequireTwoFactorAuth bool

	// SessionMaxAge defines how long a session is present after creation.
	// This does not cover session refresh.
	SessionMaxAge time.Duration

	// MinPasswordLength specifies the minimum password length requirement
	// during a new account creation.
	MinPasswordLength uint

	// DisableDefaultCSS allows to disable (no link) provided by default
	// CSS files in all templates.
	DisableDefaultCSS bool

	// IncludeExtraCSS allows to include/link an additional set of CSS
	// files in each public template rendered.
	IncludeExtraCSS []string

	// AllowRegisterAccount controls if user can register a new account.
	// This flag turns on/off account registration functionality.
	AllowRegisterAccount bool

	// AllowRegisterEmail is a regular expression that validates any email
	// address before allowing to register an account.  This regexp is not
	// meant to validate correctness of an email but to provide a basic
	// mean of configuring which email addresses are allowed. For example,
	// it can ensure that only emails from a certain domain is allowed with
	// ".*@mydomain\.com"
	AllowRegisterEmail string

	// RegisteredAccountGroups controls which permission groups are
	// assigned to a newly created account.
	// Changing this configuration allows to grant additional permissions
	// for any newly created account.
	RegisteredAccountPermissionGroups []uint64

	// AllowPasswordReset controls if password reset functionality is
	// enabled.
	AllowPasswordReset bool

	// FromEmail defines what address outgoing emails are send from.
	FromEmail string
}

type APIConfiguration struct {
	// ListenHTTP defines on which address and port the public API HTTP
	// server should operate. Keep empty to disable.
	ListenHTTP string

	// PathPrefix allows to define a prefix path that each API route will
	// include.
	PathPrefix string

	// SessionMaxAge defines how long a session is present after creation.
	// This does not cover session refresh.
	SessionMaxAge time.Duration

	// SessionRefreshAge defines the expiration refresh duratoin for a used
	// session token. This value is also a hint on how and when to refresh
	// a session token. Setting it allows active sessions to not expire
	// after SessionMaxAge duration.
	SessionRefreshAge time.Duration

	// RequireTwoFactorAuth defines if user must provide two factor
	// authentication code in order to login. If false, two factor
	// authentication is optional and can be turned on by each account
	// owner.
	RequireTwoFactorAuth bool

	// CORSDomain is the domain of the API. This information is used when
	// constructing absolute URL for example inside of email messages or
	// when configuring CORS to enable access only from certain places.
	CORSDomain string

	// MinPasswordLength specifies the minimum password length requirement
	// during a new account creation.
	MinPasswordLength uint

	// AllowRegisterAccount controls if user can register a new account.
	// This flag turns on/off account registration functionality.
	AllowRegisterAccount bool

	// AllowRegisterEmail is a regular expression that validates any email
	// address before allowing to register an account.  This regexp is not
	// meant to validate correctness of an email but to provide a basic
	// mean of configuring which email addresses are allowed. For example,
	// it can ensure that only emails from a certain domain is allowed with
	// ".*@mydomain\.com"
	AllowRegisterEmail string

	// RegisterAccountCompleteURL is sent via email to a newly registered
	// account owner in order to complete registration process. In order to
	// activate an account, another endpoint call must be made.
	// RegisterAccountCompleteURL must be an absolute URL. Token
	// information is included in the URL in place of "{token}" or if
	// {token} is not present, as a GET parameter.
	RegisterAccountCompleteURL string

	// RegisteredAccountGroups controls which permission groups are
	// assigned to a newly created account.
	// Changing this configuration allows to grant additional permissions
	// for any newly created account.
	RegisteredAccountPermissionGroups []uint64

	// AllowPasswordReset controls if password reset functionality is
	// enabled.
	AllowPasswordReset bool

	// PasswordResetCompleteURL is sent via email and should display a
	// password setup form.
	// PasswordResetCompleteURL must be an absolute URL. Token information
	// is included in the URL in place of "{token}" or if {token} is not
	// present, as a GET parameter.
	PasswordResetCompleteURL string

	// FromEmail defines what address outgoing emails are send from.
	FromEmail string
}

type AdminPanelConfiguration struct {
	// ListenHTTP defines on which address and port the admin panel HTTP
	// server should operate. Keep empty to disable.
	ListenHTTP string

	// PathPrefix allows to define a prefix path that each admin panel
	// route will include.
	PathPrefix string

	// SessionMaxAge defines how long a session is present after creation.
	// This does not cover session refresh.
	SessionMaxAge time.Duration

	// RequireTwoFactorAuth defines if user must provide two factor
	// authentication code in order to login. If false, two factor
	// authentication is optional and can be turned on by each account
	// owner.
	RequireTwoFactorAuth bool
}
