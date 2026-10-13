package identity

import (
	"context"
	"time"

	"tailscale.com/tailcfg"
)

const PlatformLoginName = "platform-admin"
const PlatformPasskeyNamespace = "xunara:platform:v1"

// 平台创建成员不兑换邀请、不代登录；角色与额度只由已授权的平台处理器传入。
type PlatformLocalAccount struct {
	LoginName              string
	DisplayName            string
	Email                  string
	PasswordHash           []byte
	Role                   Role
	MaxUsers               int
	AuthenticationRevision uint64
	Actor                  string
}

// 平台身份必须使用独立数据库，不能把租户 owner 的身份升级成超级管理员。
type PlatformAccountStore interface {
	CreateLocalAccountByPlatform(context.Context, PlatformLocalAccount) (User, error)
	CreatePlatformSession(context.Context, time.Duration, SessionClientInfo) (Session, string, error)
	DeletePlatformPasskey(context.Context, tailcfg.UserID, string, string, bool) error
}
