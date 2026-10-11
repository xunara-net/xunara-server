package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

// Errors returned by the session store.
var (
	// ErrSessionNotFound is returned for an unknown, expired or revoked
	// session token. The three cases are deliberately indistinguishable to
	// callers: a stolen token must not learn whether it was ever valid.
	ErrSessionNotFound = errors.New("identity: session not found")
	// ErrSessionRevoked is returned by rotation and revocation helpers when
	// the session exists but was already revoked.
	ErrSessionRevoked = errors.New("identity: session revoked")
)

// Session is one logged-in browser.
//
// Sessions live in the shared database, never in a server-local map: they must
// survive restarts, be revocable, and work across instances (AGENTS.md
// section 9).
type Session struct {
	// ID is the public identifier, used in audit records and revocation.
	ID string

	UserID tailcfg.UserID

	// AuthMethod names how the session was established ("oidc:dex", "local").
	AuthMethod string

	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time

	RevokedAt     time.Time
	RevokedReason string

	// RotatedFrom is the ID of the session this one replaced, if any.
	RotatedFrom string

	ClientInfo SessionClientInfo
}

// NewSessionOptions are the inputs to [SessionStore.CreateSession].
type NewSessionOptions struct {
	UserID      tailcfg.UserID
	AuthMethod  string
	TTL         time.Duration
	RotatedFrom string
	ClientInfo  SessionClientInfo
}

// DefaultSessionTTL is how long a browser session stays valid.
const DefaultSessionTTL = 24 * time.Hour

// SessionStore is the durable session table.
type SessionStore interface {
	// CreateSession creates a session and returns its token. Only the token's
	// hash is stored, so the token is returned exactly once.
	CreateSession(opts NewSessionOptions) (Session, string, error)

	// GetSessionByToken resolves a token to a live session. Expired and
	// revoked sessions return ErrSessionNotFound.
	GetSessionByToken(token string) (Session, error)

	// UseSession 验证有效人类会话并记录分钟粒度活动，不延长有效期。
	UseSession(ctx context.Context, token string) (Session, error)

	// GetSessionByID returns a session by its public ID, including revoked
	// ones, for auditing and administration.
	GetSessionByID(id string) (Session, bool)

	// ListSessions returns a user's sessions, newest first.
	ListSessions(userID tailcfg.UserID) []Session

	// TouchSession records the session's last use.
	TouchSession(id string, now time.Time) error

	// RevokeSession revokes one session. Revoking an already-revoked session
	// is a no-op.
	RevokeSession(id, reason string) error

	// RevokeUserSessions revokes every live session of a user and reports how
	// many were revoked (parallel logout).
	RevokeUserSessions(userID tailcfg.UserID, reason string) (int64, error)

	// RotateSession revokes a live session and creates a replacement with the
	// same user, returning the new session and token.
	RotateSession(token string, ttl time.Duration) (Session, string, error)

	// DeleteExpiredSessions removes sessions that expired before now.
	DeleteExpiredSessions(now time.Time) (int64, error)
}

// String implements fmt.Stringer without leaking the token.
func (s Session) String() string {
	return fmt.Sprintf("Session{ID:%s User:%d ExpiresAt:%s}", s.ID, s.UserID, s.ExpiresAt.Format(time.RFC3339))
}
