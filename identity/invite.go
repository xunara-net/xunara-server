package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

// 邀请模式下，成员凭一次性代码加入当前租户。开放注册和独立租户自助开通使用
// 各自的准入规则。这里只保存代码哈希，不能把明文当成链接、日志或审计字段。

// InvitePrefix marks a registration invite token so it is recognisable in
// logs and support requests without being usable.
const InvitePrefix = "xunara_invite_"

// ErrInviteNotFound is returned for an unknown invite ID or token.
var ErrInviteNotFound = errors.New("identity: registration invite not found")

// ErrInviteUsed is returned when an invite has already been redeemed.
var ErrInviteUsed = errors.New("identity: registration invite already used")

// ErrInviteExpired is returned when an invite is past its expiry.
var ErrInviteExpired = errors.New("identity: registration invite expired")

var ErrInviteOwnerRequired = errors.New("identity: invitations require an owner session")

// MemberInvitation 携带发起人会话，写事务会重新检查会话有效性及 owner 角色。
type MemberInvitation struct {
	UserID    tailcfg.UserID
	SessionID string
	Role      Role
	Note      string
	TTL       time.Duration
	MaxUsers  int
}

// RegistrationInvite is one single-use invitation.
type RegistrationInvite struct {
	ID        string
	TokenHash string
	Role      Role
	Note      string
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
	// UsedAt is zero until the invite is redeemed.
	UsedAt time.Time
	UsedBy tailcfg.UserID
}

// Redeemed reports whether the invite has been used.
func (i RegistrationInvite) Redeemed() bool { return !i.UsedAt.IsZero() }

// Expired reports whether the invite is past its expiry at now.
func (i RegistrationInvite) Expired(now time.Time) bool {
	return !i.ExpiresAt.IsZero() && !now.Before(i.ExpiresAt)
}

// NewRegistrationInviteOptions describes an invite to create.
type NewRegistrationInviteOptions struct {
	Role      Role
	Note      string
	CreatedBy string
	TTL       time.Duration
}

// RegistrationInviteStore stores registration invites.
type RegistrationInviteStore interface {
	// CreateRegistrationInvite stores an invite and returns it together with
	// the plaintext token, which is shown exactly once.
	CreateRegistrationInvite(opts NewRegistrationInviteOptions) (RegistrationInvite, string, error)
	// GetRegistrationInvite returns an invite by ID.
	GetRegistrationInvite(id string) (RegistrationInvite, bool)
	// ListRegistrationInvites returns every invite, newest first.
	ListRegistrationInvites() []RegistrationInvite
	ListRegistrationInvitesContext(ctx context.Context) ([]RegistrationInvite, error)
	CreateMemberInvitation(ctx context.Context, invitation MemberInvitation) (RegistrationInvite, string, error)
	RevokeMemberInvitation(ctx context.Context, userID tailcfg.UserID, sessionID, inviteID string) error
	// RevokeRegistrationInvite deletes an unused invite. Redeemed invites
	// are kept as a record, so revoking one fails with ErrInviteUsed.
	RevokeRegistrationInvite(id string) error
	// FindRegistrationInvite returns the invite a token refers to without
	// consuming it, so a caller can read the role it grants before creating
	// the account. Invalid, used and expired invites are errors.
	FindRegistrationInvite(token string) (RegistrationInvite, error)
}

// inviteRole returns the role an invite may grant: an invite never mints
// another owner by accident, because promoting a user is an explicit act.
func inviteRole(r Role) (Role, error) {
	switch r {
	case RoleMember, RoleAdmin:
		return r, nil
	case "":
		return RoleMember, nil
	default:
		return "", fmt.Errorf("identity: registration invite cannot grant role %q", string(r))
	}
}

// normalizeInviteToken trims the token a browser submitted so a pasted link
// with padding still resolves.
func normalizeInviteToken(token string) string {
	return strings.TrimSpace(token)
}
