package identity

import (
	"context"
	"errors"
	"time"

	"tailscale.com/tailcfg"
)

var ErrUserDisabled = errors.New("identity: account is disabled")

// UserStatusChange 必须携带列表中读取的完整版本；角色/资料的并发修改也会造成冲突。
type UserStatusChange struct {
	Disabled          bool
	Reason            string
	ExpectedUpdatedAt time.Time
}

type UserStatusResult struct {
	User            User
	RevokedSessions int64
}

type UserStatusStore interface {
	// SetUserStatusByPlatform 仅供已验证平台身份的管理入口，不供普通成员或服务 key 调用。
	SetUserStatusByPlatform(ctx context.Context, userID tailcfg.UserID, change UserStatusChange) (UserStatusResult, error)
}
