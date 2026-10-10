package identity

import (
	"context"
	"errors"
	"time"

	"tailscale.com/tailcfg"
)

var (
	ErrMemberConflict      = errors.New("identity: member changed")
	ErrMemberOwnerRequired = errors.New("identity: owner role required to manage members")
	ErrMemberInvalid       = errors.New("identity: invalid member update")
	ErrLastOwner           = errors.New("identity: cannot remove the last owner")
)

// MemberCaller 只携带已认证的持久身份 ID，不接受原始 Token 或机器身份。
// 会话和服务 key 必须二选一，并在写事务内复查，不信任 HTTP 层的角色快照。
type MemberCaller struct {
	UserID    tailcfg.UserID
	SessionID string
	APIKeyID  string
}

// MemberPatch 只修改明确提供的字段，避免旧资料快照覆盖并发更新后的角色。
// ExpectedUpdatedAt 保留完整纳秒精度；历史调用未提供时仍执行事务授权和 owner 保护。
type MemberPatch struct {
	LoginName         *string
	DisplayName       *string
	Email             *string
	Role              *Role
	ExpectedUpdatedAt *time.Time
}

type MemberStore interface {
	UpdateMember(ctx context.Context, caller MemberCaller, userID tailcfg.UserID, patch MemberPatch) (User, error)
	// UpdateUserByOperator 仅用于拥有状态目录访问权的本地 CLI，不能由 HTTP 选择。
	UpdateUserByOperator(ctx context.Context, userID tailcfg.UserID, patch MemberPatch) (User, error)
}
