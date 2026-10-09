package identity

import (
	"context"
	"errors"
	"time"

	"tailscale.com/tailcfg"
)

// ErrUserNotFound is returned when a user ID or login name does not resolve.
var ErrUserNotFound = errors.New("identity: user not found")

// ErrExternalIdentityExists is returned when (provider, subject) is already
// linked to a different user.
var ErrExternalIdentityExists = errors.New("identity: external identity already linked")

// ErrLoginNameTaken is returned when a login name is already in use.
var ErrLoginNameTaken = errors.New("identity: login name already taken")

// UserStore is the human-identity half of the trust plane.
type UserStore interface {
	// CreateUser stores a user, assigning its ID and timestamps.
	CreateUser(u *User) error
	// GetUser returns a user by ID.
	GetUser(id tailcfg.UserID) (User, bool)
	// LookupUser 区分账户不存在与存储故障；认证不能把数据库不可用当成用户被删除。
	LookupUser(ctx context.Context, id tailcfg.UserID) (User, error)
	// GetUserByLoginName returns a user by login name, case-insensitively.
	GetUserByLoginName(login string) (User, bool)
	// LookupUserByLoginName 保留查询错误和取消信号；仅无记录表示未知登录名。
	LookupUserByLoginName(ctx context.Context, login string) (User, error)
	// ListUsers returns every user, oldest first.
	ListUsers() []User
	// UpdateUser replaces a stored user. It fails if the user is unknown.
	UpdateUser(u User) error
	// DeleteUser removes a user and its external identity links. It fails
	// with ErrUserNotFound if the user is unknown.
	DeleteUser(id tailcfg.UserID) error
}

// ExternalIdentityStore is the link between external accounts and users.
//
// The lookup key is (provider, subject) and nothing else: see AGENTS.md
// section 6.
type ExternalIdentityStore interface {
	// LinkExternalIdentity attaches an external account to a user. It fails
	// with ErrExternalIdentityExists when the account is already linked to a
	// different user.
	LinkExternalIdentity(ei *ExternalIdentity) error
	// GetExternalIdentity returns the link for (provider, subject).
	GetExternalIdentity(provider, subject string) (ExternalIdentity, bool)
	// ListExternalIdentities returns the links belonging to a user.
	ListExternalIdentities(userID tailcfg.UserID) []ExternalIdentity
	// UnlinkExternalIdentity removes a link.
	UnlinkExternalIdentity(provider, subject string) error
}

// AuditStore is the append-only audit log.
type AuditStore interface {
	// AppendAudit appends an event, assigning its ID and time.
	AppendAudit(e *AuditEvent) error
	// ListAudit returns events, oldest first, at most limit of them (0 means
	// no limit).
	ListAudit(limit int) []AuditEvent
}

// WebhookCursorStore tracks how far each webhook endpoint has consumed the
// audit log, so delivery is durable and survives restarts.
//
// Delivery is at-least-once: a crash between a successful POST and the cursor
// update redelivers that event. Receivers deduplicate by the delivery ID in
// the payload.
type WebhookCursorStore interface {
	// ListAuditAfter returns events with ID greater than afterID, oldest
	// first, at most limit of them (0 means no limit).
	ListAuditAfter(afterID uint64, limit int) []AuditEvent
	// GetWebhookCursor returns the last event ID delivered to an endpoint, or
	// 0 when it has never delivered.
	GetWebhookCursor(endpoint string) uint64
	// SetWebhookCursor records the last event ID delivered to an endpoint.
	SetWebhookCursor(endpoint string, eventID uint64) error

	// ClaimWebhookEndpoint claims exclusive delivery for an endpoint until
	// expiresAt. It reports false when another instance holds a live claim, so
	// several control-plane instances sharing a database deliver each event
	// once between them (receivers still deduplicate by delivery ID, because
	// delivery is at-least-once).
	ClaimWebhookEndpoint(endpoint, owner string, now, expiresAt time.Time) (bool, error)
	// RenewWebhookClaim extends a claim. It reports false when the claim was
	// taken over (the previous holder must stop delivering).
	RenewWebhookClaim(endpoint, owner string, expiresAt time.Time) (bool, error)
	// ReleaseWebhookClaim drops a claim the owner still holds, so another
	// instance can take over immediately instead of waiting for the lease to
	// expire.
	ReleaseWebhookClaim(endpoint, owner string) error
	// WebhookRetryState returns the persisted backoff of an endpoint: how many
	// consecutive attempts failed and when the next one may start.
	WebhookRetryState(endpoint string) (attempts int, retryAt time.Time)
	// SetWebhookRetryState persists the backoff state. attempts 0 with a zero
	// retryAt means "healthy".
	SetWebhookRetryState(endpoint string, attempts int, retryAt time.Time) error
}

// Store is the persistence boundary of the trust plane.
type Store interface {
	UserStore
	ExternalIdentityStore
	AuditStore
	WebhookCursorStore
	WebhookEndpointStore
	AuthTransactionStore
	SessionStore
	DeviceAuthorizationStore
	SSHCheckStore
	APIKeyStore
	AgentTokenStore
	PasskeyStore
	PasskeyCeremonyStore
	ShareUserStore
	LocalCredentialStore
	AccountStore
	RegistrationInviteStore
	RegistrationStore
}
