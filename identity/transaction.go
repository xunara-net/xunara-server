package identity

import (
	"errors"
	"time"

	"tailscale.com/tailcfg"
)

// Errors returned by the transaction store. They are deliberately distinct so
// that a login handler can log (and audit) why a callback was rejected without
// leaking the reason to the browser.
var (
	// ErrTransactionNotFound is returned for an unknown transaction ID.
	ErrTransactionNotFound = errors.New("identity: auth transaction not found")
	// ErrTransactionExpired is returned once a transaction's TTL has passed.
	ErrTransactionExpired = errors.New("identity: auth transaction expired")
	// ErrTransactionConsumed is returned when an already-redeemed transaction
	// is presented again: the code-replay and state-replay guard.
	ErrTransactionConsumed = errors.New("identity: auth transaction already consumed")
)

// AuthTransaction is one login attempt.
//
// It carries the OAuth state, OIDC nonce and PKCE material for a single
// browser round trip, and is consumed exactly once. It is not a session and
// not a device authorization (AGENTS.md section 10).
type AuthTransaction struct {
	// ID is the opaque server-side identifier.
	ID string

	// ProviderID is the provider this transaction is bound to.
	ProviderID string

	// State is the OAuth state. It is stored verbatim because it must be sent
	// to the provider again on every Begin; replay is prevented by ConsumedAt.
	State string

	// Nonce is the OIDC nonce the ID token must echo.
	Nonce string

	// PKCEVerifier and PKCEChallenge are the RFC 7636 pair.
	PKCEVerifier  string
	PKCEChallenge string
	PKCEMethod    string

	// RedirectURI is the exact redirect URI registered with the provider. It
	// is never taken from a request.
	RedirectURI string

	// ReturnTo is the same-origin path to send the browser to after login.
	ReturnTo string

	// RequestedAction and MachineLoginID tie the login to the device flow
	// that started it, without merging the two objects.
	RequestedAction string
	MachineLoginID  string

	// 只引用发起绑定的人类身份，不能将认证事务当成会话或设备审批。
	AccountUserID          tailcfg.UserID
	AccountSessionID       string
	InviteTokenHash        string
	AuthenticationRevision uint64

	// BrowserSessionHash is the SHA-256 of the secret in the browser's
	// transaction cookie. The raw secret never reaches the database.
	BrowserSessionHash string

	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt time.Time
}

// NewAuthTransactionOptions are the inputs to [AuthTransactionStore.CreateAuthTransaction].
type NewAuthTransactionOptions struct {
	// ProviderID, RedirectURI, ReturnTo, RequestedAction and MachineLoginID
	// are copied into the transaction.
	ProviderID             string
	RedirectURI            string
	ReturnTo               string
	RequestedAction        string
	MachineLoginID         string
	AccountUserID          tailcfg.UserID
	AccountSessionID       string
	InviteTokenHash        string
	AuthenticationRevision uint64

	// TTL bounds the browser round trip. Zero means [DefaultAuthTransactionTTL].
	TTL time.Duration
}

// DefaultAuthTransactionTTL bounds how long a login may stay pending.
const DefaultAuthTransactionTTL = 10 * time.Minute

// AuthTransactionStore is the durable half of the login state machine.
type AuthTransactionStore interface {
	// CreateAuthTransaction creates a transaction and returns the browser
	// secret that must go into the transaction cookie (only its hash is
	// stored).
	CreateAuthTransaction(opts NewAuthTransactionOptions) (AuthTransaction, string, error)

	// GetAuthTransaction returns a transaction by ID, including expired and
	// consumed ones, so that callers can distinguish the rejection reasons.
	GetAuthTransaction(id string) (AuthTransaction, bool)

	// ConsumeAuthTransaction atomically redeems a transaction. It returns the
	// transaction, or ErrTransactionNotFound/ErrTransactionExpired/
	// ErrTransactionConsumed.
	ConsumeAuthTransaction(id string) (AuthTransaction, error)

	// DeleteExpiredAuthTransactions removes transactions past their expiry
	// (consumed or not) and reports how many were deleted.
	DeleteExpiredAuthTransactions(now time.Time) (int64, error)
}
