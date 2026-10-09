package identity

import (
	"context"
	"errors"
	"time"

	"tailscale.com/tailcfg"
)

var ErrCredentialChanged = errors.New("identity: credential or initiating session changed")

// AccountStore 只处理当前人类账户的自助操作；租户边界由各租户独立的 Store 保证。
// 凭据和会话写入必须在事务中复核身份，不能只信任 HTTP 层先前读取的快照。
type AccountStore interface {
	UpdateUserProfile(ctx context.Context, userID tailcfg.UserID, displayName, email *string) (User, error)
	CreateLocalSession(ctx context.Context, userID tailcfg.UserID, expectedHash []byte, ttl time.Duration) (Session, string, error)
	ChangeLocalPassword(ctx context.Context, userID tailcfg.UserID, sessionID string, expectedHash, replacementHash []byte) (int64, error)
	ListAccountSessions(ctx context.Context, userID tailcfg.UserID) ([]Session, error)
	RevokeAccountSessions(ctx context.Context, userID tailcfg.UserID, initiatingID string, selection SessionRevocation) (int64, error)
	ListAccountPasskeys(ctx context.Context, userID tailcfg.UserID) ([]Passkey, error)
	CreateAccountPasskey(ctx context.Context, initiatingID string, passkey Passkey) (Passkey, error)
	DeleteAccountPasskey(ctx context.Context, userID tailcfg.UserID, initiatingID, passkeyID string) error
	CreatePasskeySession(ctx context.Context, userID tailcfg.UserID, passkeyID string, ttl time.Duration) (Session, string, error)
}
