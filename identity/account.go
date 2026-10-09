package identity

import (
	"context"
	"errors"
	"time"

	"tailscale.com/tailcfg"
)

var ErrCredentialChanged = errors.New("identity: credential or initiating session changed")

type AccountStore interface {
	UpdateUserProfile(ctx context.Context, userID tailcfg.UserID, displayName, email *string) (User, error)
	CreateLocalSession(ctx context.Context, userID tailcfg.UserID, expectedHash []byte, ttl time.Duration) (Session, string, error)
	ChangeLocalPassword(ctx context.Context, userID tailcfg.UserID, sessionID string, expectedHash, replacementHash []byte) (int64, error)
	ListAccountSessions(ctx context.Context, userID tailcfg.UserID) ([]Session, error)
	RevokeAccountSessions(ctx context.Context, userID tailcfg.UserID, initiatingID string, selection SessionRevocation) (int64, error)
}
