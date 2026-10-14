package identity

import (
	"context"
	"time"

	"tailscale.com/tailcfg"
)

type PasswordResetOptions struct {
	Reason            string
	ExpectedUpdatedAt time.Time
	OwnershipVerified bool
}

type PasswordResetStore interface {
	ResetRandomPasswordByPlatform(ctx context.Context, userID tailcfg.UserID, options PasswordResetOptions, actor string) (RandomPasswordReset, error)
}
