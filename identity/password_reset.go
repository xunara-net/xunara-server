package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

const PasswordResetTTL = 15 * time.Minute

var ErrPasswordResetInvalid = errors.New("identity: password reset is unavailable")

type PasswordResetOptions struct {
	Reason            string
	ExpectedUpdatedAt time.Time
	OwnershipVerified bool
}

// PasswordResetStatus 只用于读取待用状态；原码不可从状态、审计或数据库恢复。
type PasswordResetStatus struct {
	ID        string
	UserID    tailcfg.UserID
	CreatedAt time.Time
	ExpiresAt time.Time
}

type PasswordResetIssuance struct {
	User   User
	Status PasswordResetStatus
	Code   string `json:"-"`
}

type PasswordResetResult struct {
	UserID          tailcfg.UserID
	RevokedSessions int64
}

type PasswordResetStore interface {
	IssuePasswordResetByPlatform(ctx context.Context, userID tailcfg.UserID, options PasswordResetOptions) (PasswordResetIssuance, error)
	GetPasswordResetStatus(ctx context.Context, userID tailcfg.UserID) (PasswordResetStatus, bool, error)
	LookupPasswordReset(ctx context.Context, code string) (User, error)
	RedeemPasswordReset(ctx context.Context, code string, replacementHash []byte) (PasswordResetResult, error)
}

func validPasswordResetCode(code string) bool {
	encoded, ok := strings.CutPrefix(code, "reset-")
	if !ok || len(encoded) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(decoded) == secretBytes && base64URL(decoded) == encoded
}
